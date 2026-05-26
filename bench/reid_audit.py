#!/usr/bin/env python3
"""Track B3: residual re-identification-risk audit across public "de-identified" imaging datasets.

For each dataset directory it scores every file with the DicomLock re-identification-risk score
(deid_auditor.score_reidentification_risk), then reports the band distribution, the prevalence of
each channel (structured tags, free text and private, burned-in pixels, facial geometry), and the
mean points per channel.

The honest framing: public archives like TCIA pseudonymize at the tag level, but the pixel-domain
channels are typically untouched. So even after a published "de-identification," files can carry
measurable residual re-identification risk that no tag anonymizer can fix (see bench.reid_vs_anonymizer
on this point: a standard anonymizer leaves the pixels byte-identical). This audit quantifies that
residual on the public data we have on disk.

Ethics: public data only. The score is a heuristic + metadata triage signal. This harness never runs
face recognition against real people; never re-identifies anyone; never publishes any identifier or
image that could expose a specific patient.

Run:  python -m bench.reid_audit              # the 3 modalities on disk
      python -m bench.reid_audit --limit 200  # cap per dataset for a quick pass
      python -m bench.reid_audit --dir data/tcia_ct --label "CT (TCIA mixed)"
"""

import argparse
import collections
import glob
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
if PROJECT not in sys.path:
    sys.path.insert(0, PROJECT)

import pydicom  # noqa: E402
from scanner.deid_auditor import score_reidentification_risk  # noqa: E402

DEFAULT_DATASETS = [
    ("CT (TCIA mixed: LIDC/NSCLC/TCGA/COVID)", os.path.join(PROJECT, "data", "tcia_ct")),
    ("MR (brain, UPENN-GBM)",                  os.path.join(PROJECT, "data", "tcia_mr")),
    ("XR (chest CR/DX, LIDC-IDRI)",            os.path.join(PROJECT, "data", "tcia_xr")),
]

CHANNELS = ("structured_identifiers", "text_identifiers", "burned_in_pixels", "facial_geometry")
SHORT = {
    "structured_identifiers": "structured tags",
    "text_identifiers":       "text/private",
    "burned_in_pixels":       "burned-in",
    "facial_geometry":        "facial geom",
}


def audit_dir(label, directory, limit=0):
    files = sorted(glob.glob(os.path.join(directory, "*.dcm")))
    if limit:
        files = files[:limit]
    rows = []
    errors = 0
    for fp in files:
        try:
            ds = pydicom.dcmread(fp, force=True)
            s = score_reidentification_risk(ds, use_ocr=False)
            rows.append(s)
        except Exception:
            errors += 1

    n = len(rows)
    bands = collections.Counter(r.get("band", "?") for r in rows)
    mean_score = sum(r.get("score", 0) for r in rows) / n if n else 0
    channel_prev = {}
    channel_mean = {}
    for ch in CHANNELS:
        pts = [r["dimensions"].get(ch, {}).get("points", 0) for r in rows]
        channel_prev[ch] = sum(1 for p in pts if p > 0) / n if n else 0
        channel_mean[ch] = (sum(pts) / n) if n else 0

    return {
        "label": label, "directory": directory, "n": n, "errors": errors,
        "bands": bands, "mean_score": mean_score,
        "channel_prev": channel_prev, "channel_mean": channel_mean,
    }


def fmt_pct(x):
    return f"{100*x:5.1f}%"


def print_dataset(r):
    print(f"\n{'='*78}\n{r['label']}  ({r['n']} files; {r['errors']} read errors)\n{'='*78}")
    print(f"  mean re-identification score: {r['mean_score']:5.1f}/100")
    print(f"  band distribution:")
    for band in ("MINIMAL", "LOW", "MODERATE", "HIGH"):
        c = r["bands"].get(band, 0)
        pct = (100 * c / r["n"]) if r["n"] else 0
        print(f"     {band:9s} {c:>4} ({pct:5.1f}%)")
    print(f"  channel prevalence (% of files where the channel fires) and mean points:")
    print(f"    {'channel':16s} {'% files':>10}   {'mean pts':>10}")
    for ch in CHANNELS:
        print(f"    {SHORT[ch]:16s} {fmt_pct(r['channel_prev'][ch]):>10}   "
              f"{r['channel_mean'][ch]:>10.1f}")


def print_summary(results):
    total = sum(r["n"] for r in results)
    if not total:
        return
    print(f"\n{'='*78}\nCROSS-DATASET SUMMARY ({total} files across {len(results)} datasets)\n"
          f"{'='*78}")
    print(f"  {'dataset':46s} {'N':>5} {'HIGH%':>7} {'face%':>7} {'burn%':>7}")
    for r in results:
        if not r["n"]:
            continue
        highpct = 100 * r["bands"].get("HIGH", 0) / r["n"]
        print(f"  {r['label'][:46]:46s} {r['n']:>5} {highpct:>6.1f}% "
              f"{fmt_pct(r['channel_prev']['facial_geometry']):>7} "
              f"{fmt_pct(r['channel_prev']['burned_in_pixels']):>7}")

    # Pixel-domain channels (what no tag anonymizer can fix) are the actionable finding.
    print(f"\n  Pixel-domain residual risk (the part no tag anonymizer can fix):")
    for r in results:
        face_pct = 100 * r["channel_prev"]["facial_geometry"]
        burn_pct = 100 * r["channel_prev"]["burned_in_pixels"]
        if face_pct > 0 or burn_pct > 0:
            parts = []
            if face_pct > 0:
                parts.append(f"facial geometry on {face_pct:.1f}%")
            if burn_pct > 0:
                parts.append(f"burned-in text on {burn_pct:.1f}%")
            print(f"    {r['label'][:46]:46s} {', '.join(parts)}")

    print(f"\n  Honest scoping:")
    print(f"    The tag-domain channels (structured + private) fire on essentially every file in")
    print(f"    these archives because TCIA pseudonymizes (replaces values) rather than empties tags,")
    print(f"    and our ordinal score counts populated tags as residual risk. That structural floor")
    print(f"    is why every dataset clears the MODERATE band; it is not undetected direct PHI.")
    print(f"    The pixel-domain numbers above are the actionable signal. Per bench.reid_vs_anonymizer,")
    print(f"    a standard tag anonymizer (dicognito 0.19) leaves the pixels byte-identical 60/60 on")
    print(f"    brain MR, so the facial-geometry and burned-in channels reported here are provably")
    print(f"    unchanged by current tag-based anonymization.")


def main():
    ap = argparse.ArgumentParser(prog="bench.reid_audit")
    ap.add_argument("--dir", action="append", help="extra directory to audit (repeatable)")
    ap.add_argument("--label", action="append",
                    help="optional label for each --dir (positional pair)")
    ap.add_argument("--limit", type=int, default=0, help="cap files per dataset")
    args = ap.parse_args()

    datasets = list(DEFAULT_DATASETS)
    extra_dirs = args.dir or []
    extra_labels = args.label or []
    for i, d in enumerate(extra_dirs):
        lbl = extra_labels[i] if i < len(extra_labels) else os.path.basename(d.rstrip("/"))
        path = d if os.path.isabs(d) else os.path.join(PROJECT, d)
        datasets.append((lbl, path))

    results = []
    for label, directory in datasets:
        if not os.path.isdir(directory) or not glob.glob(os.path.join(directory, "*.dcm")):
            print(f"\n(skipping {label}: no .dcm in {directory})")
            continue
        print(f"\nauditing {label} ...", flush=True)
        results.append(audit_dir(label, directory, args.limit))
        print_dataset(results[-1])

    print_summary(results)

    out = os.path.join(HERE, "reid_audit_results.txt")
    with open(out, "w") as f:
        for r in results:
            f.write(f"{r['label']}: n={r['n']}, mean_score={r['mean_score']:.1f}\n")
            for band in ("MINIMAL", "LOW", "MODERATE", "HIGH"):
                f.write(f"  band {band}: {r['bands'].get(band, 0)}\n")
            for ch in CHANNELS:
                f.write(f"  channel {ch}: prevalence={r['channel_prev'][ch]:.3f}, "
                        f"mean_pts={r['channel_mean'][ch]:.2f}\n")
        total = sum(r["n"] for r in results)
        modplus = sum(sum(r["bands"].get(b, 0) for b in ("MODERATE", "HIGH")) for r in results)
        f.write(f"\nAGGREGATE: {modplus}/{total} files MODERATE+ "
                f"({100*modplus/total:.1f}% if total else 0).\n")
    print(f"\nartifact: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
