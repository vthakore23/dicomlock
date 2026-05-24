"""
DicomLock — Calibration Pipeline

Runs feature extraction on a corpus of known-real DICOM files to establish
per-modality baselines. These baselines define "what normal looks like"
so the scanner can flag statistical outliers.

Usage:
    from scanner.calibration import calibrate, load_baselines

    # Build baselines from a directory of real DICOM files
    calibrate("path/to/real/dicoms", "data/baselines.json")

    # Load baselines for use in scanning
    baselines = load_baselines("data/baselines.json")
"""

import json
import os
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import pydicom

from scanner.pixel_advanced import extract_all_features


def calibrate(dicom_dir: str, output_path: str, verbose: bool = True) -> dict:
    """
    Run feature extraction on all DICOM files in a directory
    and compute per-modality baseline statistics.

    Args:
        dicom_dir: Path to directory containing real DICOM files
        output_path: Where to save the baselines JSON
        verbose: Print progress

    Returns:
        The baselines dict (also saved to output_path)
    """
    # Collect all DICOM files
    dcm_files = sorted(Path(dicom_dir).rglob("*.dcm"))
    if verbose:
        print(f"Found {len(dcm_files)} DICOM files in {dicom_dir}")

    # Extract features from every file, grouped by modality
    modality_features = defaultdict(list)
    errors = 0
    skipped = 0

    for i, filepath in enumerate(dcm_files):
        try:
            ds = pydicom.dcmread(str(filepath), force=True)
            features = extract_all_features(ds)

            if features is None:
                skipped += 1
                continue

            modality = features.pop("modality", "UNKNOWN")
            # Remove non-numeric fields
            features.pop("rows", None)
            features.pop("cols", None)

            modality_features[modality].append(features)

            if verbose and (i + 1) % 50 == 0:
                print(f"  Processed {i + 1}/{len(dcm_files)} files...")
        except Exception as e:
            errors += 1
            if verbose:
                print(f"  Error on {filepath.name}: {e}")

    if verbose:
        print(f"\nExtraction complete:")
        for mod, feats in sorted(modality_features.items()):
            print(f"  {mod}: {len(feats)} files")
        if skipped:
            print(f"  Skipped (no pixel data): {skipped}")
        if errors:
            print(f"  Errors: {errors}")

    # Compute statistics for each feature within each modality
    baselines = {}
    for modality, feature_list in modality_features.items():
        if len(feature_list) < 3:
            if verbose:
                print(f"\n  Skipping {modality} — too few samples ({len(feature_list)})")
            continue

        baselines[modality] = {
            "_sample_count": len(feature_list),
        }

        # Get all feature keys
        all_keys = set()
        for f in feature_list:
            all_keys.update(f.keys())

        for key in sorted(all_keys):
            values = [f[key] for f in feature_list if key in f and np.isfinite(f[key])]
            if len(values) < 3:
                continue

            arr = np.array(values)
            baselines[modality][key] = {
                "mean": float(np.mean(arr)),
                "std": float(np.std(arr)),
                "median": float(np.median(arr)),
                "min": float(np.min(arr)),
                "max": float(np.max(arr)),
                "p5": float(np.percentile(arr, 5)),
                "p95": float(np.percentile(arr, 95)),
                "n": len(values),
            }

    # Save
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(baselines, f, indent=2)

    if verbose:
        total_features = sum(
            len([k for k in v if not k.startswith("_")])
            for v in baselines.values()
        )
        print(f"\nBaselines saved to {output_path}")
        print(f"  {len(baselines)} modalities, {total_features} total feature baselines")

    return baselines


def load_baselines(path: str) -> dict:
    """Load baselines from a JSON file."""
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m scanner.calibration <dicom_dir> [output.json]")
        print("  Scans all .dcm files in <dicom_dir> and computes baselines.")
        print("  Default output: data/baselines.json")
        sys.exit(1)

    dicom_dir = sys.argv[1]
    output = sys.argv[2] if len(sys.argv) > 2 else "data/baselines.json"

    calibrate(dicom_dir, output)
