#!/usr/bin/env python3
"""
DicomLock — Parallel TCIA Downloader

Downloads DICOM slices from The Cancer Imaging Archive for calibration
and classifier training. Uses ThreadPoolExecutor for 10-20x speedup.

Usage:
    # Download 500 CT + 200 MR + 200 XR (defaults)
    python download_tcia.py

    # Download specific counts
    python download_tcia.py --ct 1000 --mr 500 --xr 300

    # Download from a specific collection only
    python download_tcia.py --collection LIDC-IDRI --modality CT --count 200
"""

import argparse
import json
import os
import random
import sys
import tempfile
import time
import urllib.request
import zipfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock

TCIA_API = "https://services.cancerimagingarchive.net/nbia-api/services/v1"
DATA_DIR = Path(__file__).parent / "data"

# Collections to download from, grouped by modality
COLLECTIONS = {
    "CT": [
        ("LIDC-IDRI", "CT"),          # 243K images, chest CT, 4 manufacturers
        ("NSCLC-Radiomics", "CT"),     # 422 patients, lung CT
        ("TCGA-LUAD", "CT"),           # Lung adenocarcinoma CT
        ("COVID-19-AR", "CT"),         # COVID chest CT
    ],
    "MR": [
        ("TCGA-GBM", "MR"),           # Brain MR (glioblastoma)
        ("QIN-BRAIN-DSC-MRI", "MR"),  # Brain perfusion MR
    ],
    "XR": [
        ("LIDC-IDRI", "CR"),          # Chest X-ray (computed radiography)
        ("LIDC-IDRI", "DX"),          # Chest X-ray (digital)
    ],
}

# Thread-safe progress counter
progress_lock = Lock()
progress = {"downloaded": 0, "errors": 0, "total": 0}


def get_series(collection: str, modality: str) -> list[dict]:
    """Get all series for a collection/modality from TCIA."""
    url = f"{TCIA_API}/getSeries?Collection={collection}&Modality={modality}"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return json.loads(resp.read())
    except Exception:
        return []


def download_one_series(series_info: dict, output_dir: Path) -> bool:
    """
    Download 1 slice from a TCIA series. Returns True on success.

    Downloads the full series ZIP, extracts the middle slice, discards the rest.
    """
    uid = series_info["SeriesInstanceUID"]
    url = f"{TCIA_API}/getImage?SeriesInstanceUID={uid}"

    # Use last 20 chars of UID as filename (unique enough)
    safe_name = uid.replace(".", "")[-20:] + ".dcm"
    dest = output_dir / safe_name

    if dest.exists():
        return True  # Already have it

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            tmp_path = tmp.name
            urllib.request.urlretrieve(url, tmp_path)

        with zipfile.ZipFile(tmp_path) as zf:
            dcm_files = [n for n in zf.namelist() if n.endswith(".dcm")]
            if not dcm_files:
                dcm_files = [n for n in zf.namelist() if not n.endswith("/")]

            if dcm_files:
                mid = len(dcm_files) // 2
                with zf.open(dcm_files[mid]) as src, open(dest, "wb") as dst:
                    dst.write(src.read())
                return True

        return False

    except Exception:
        if dest.exists():
            dest.unlink()
        return False
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)


def download_worker(args: tuple) -> bool:
    """Worker function for ThreadPoolExecutor."""
    series_info, output_dir = args
    success = download_one_series(series_info, output_dir)

    with progress_lock:
        if success:
            progress["downloaded"] += 1
        else:
            progress["errors"] += 1
        done = progress["downloaded"] + progress["errors"]
        total = progress["total"]
        mfr = series_info.get("Manufacturer", "?")[:20]
        sys.stdout.write(
            f"\r  [{progress['downloaded']}/{total}] "
            f"({progress['errors']} err) {mfr:<20}"
        )
        sys.stdout.flush()

    return success


def gather_series(modality_group: str, max_count: int) -> list[tuple[dict, str]]:
    """Gather series from all collections for a modality group."""
    all_series = []
    collections = COLLECTIONS.get(modality_group, [])

    for collection, modality in collections:
        print(f"  Querying {collection}/{modality}...", end=" ", flush=True)
        series = get_series(collection, modality)
        print(f"{len(series)} series")
        for s in series:
            s["_collection"] = collection
        all_series.extend(series)

    # Deduplicate by SeriesInstanceUID
    seen = set()
    unique = []
    for s in all_series:
        uid = s["SeriesInstanceUID"]
        if uid not in seen:
            seen.add(uid)
            unique.append(s)

    # Shuffle and select
    random.seed(42)
    random.shuffle(unique)
    selected = unique[:max_count]

    # Report manufacturer diversity
    manufacturers = defaultdict(int)
    for s in selected:
        manufacturers[s.get("Manufacturer", "Unknown")] += 1
    print(f"  Selected {len(selected)} from {len(manufacturers)} manufacturers:")
    for mfr, count in sorted(manufacturers.items(), key=lambda x: -x[1])[:5]:
        print(f"    {mfr}: {count}")

    return selected


def download_modality(modality_group: str, count: int, workers: int = 15):
    """Download `count` files for a modality group using parallel workers."""
    output_dir = DATA_DIR / f"tcia_{modality_group.lower()}"
    output_dir.mkdir(parents=True, exist_ok=True)

    existing = len(list(output_dir.glob("*.dcm")))
    print(f"\n{'='*60}")
    print(f"Downloading {modality_group} — target: {count}, existing: {existing}")
    print(f"{'='*60}")

    if existing >= count:
        print(f"  Already have {existing} files, skipping.")
        return existing

    # Gather series metadata
    series_list = gather_series(modality_group, count)
    if not series_list:
        print("  No series found!")
        return existing

    # Reset progress
    with progress_lock:
        progress["downloaded"] = 0
        progress["errors"] = 0
        progress["total"] = len(series_list)

    # Download in parallel
    print(f"\n  Downloading with {workers} parallel workers...")
    start = time.time()

    tasks = [(s, output_dir) for s in series_list]
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(download_worker, t) for t in tasks]
        for f in as_completed(futures):
            pass  # Progress printed by workers

    elapsed = time.time() - start
    final_count = len(list(output_dir.glob("*.dcm")))
    rate = progress["downloaded"] / elapsed if elapsed > 0 else 0

    print(f"\n\n  Done: {progress['downloaded']} new + {existing} existing = {final_count} total")
    print(f"  Time: {elapsed:.0f}s ({rate:.1f} files/sec)")
    print(f"  Errors: {progress['errors']}")

    return final_count


def main():
    parser = argparse.ArgumentParser(description="Download DICOM files from TCIA")
    parser.add_argument("--ct", type=int, default=500, help="Number of CT files (default: 500)")
    parser.add_argument("--mr", type=int, default=200, help="Number of MR files (default: 200)")
    parser.add_argument("--xr", type=int, default=200, help="Number of X-ray files (default: 200)")
    parser.add_argument("--workers", type=int, default=15, help="Parallel workers (default: 15)")
    parser.add_argument("--collection", type=str, help="Download from a single collection")
    parser.add_argument("--modality", type=str, help="Single modality (with --collection)")
    parser.add_argument("--count", type=int, default=200, help="Count (with --collection)")
    args = parser.parse_args()

    print("DicomLock — Parallel TCIA Downloader")
    print(f"Data directory: {DATA_DIR}")

    if args.collection:
        # Single collection mode
        output_dir = DATA_DIR / f"tcia_{args.modality or 'CT'}".lower()
        output_dir.mkdir(parents=True, exist_ok=True)
        modality = args.modality or "CT"

        print(f"\nFetching {args.collection}/{modality}...")
        series = get_series(args.collection, modality)
        print(f"  {len(series)} series available")

        random.seed(42)
        selected = random.sample(series, min(args.count, len(series)))

        with progress_lock:
            progress["downloaded"] = 0
            progress["errors"] = 0
            progress["total"] = len(selected)

        tasks = [(s, output_dir) for s in selected]
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = [executor.submit(download_worker, t) for t in tasks]
            for f in as_completed(futures):
                pass

        print(f"\n\nDone: {progress['downloaded']} downloaded, {progress['errors']} errors")
        return

    # Multi-modality mode
    totals = {}
    start_all = time.time()

    for group, count in [("CT", args.ct), ("MR", args.mr), ("XR", args.xr)]:
        if count > 0:
            totals[group] = download_modality(group, count, args.workers)

    elapsed = time.time() - start_all
    print(f"\n{'='*60}")
    print(f"ALL DOWNLOADS COMPLETE — {elapsed:.0f}s total")
    for group, count in totals.items():
        print(f"  {group}: {count} files in data/tcia_{group.lower()}/")
    print(f"{'='*60}")

    print("\nNext steps:")
    print("  1. Calibrate baselines:  python -m scanner.calibration data/tcia_ct data/baselines_ct.json")
    print("  2. Generate fakes:       python generate_fakes.py")
    print("  3. Train classifier:     python train_classifier.py")


if __name__ == "__main__":
    main()
