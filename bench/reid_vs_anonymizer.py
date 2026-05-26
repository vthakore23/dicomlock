#!/usr/bin/env python3
"""Track B1: re-identification risk after a standard tag anonymizer.

A standard DICOM anonymizer (here dicognito, a widely used open-source tool; the same argument holds
for RSNA CTP and pydicom-based scrubbers) replaces or shifts identifying TAGS. By construction it does
not touch pixel data. But two of the strongest re-identification channels live in the pixels, not the
tags: facial geometry reconstructable from a head CT or MR (Schwarz et al., NEJM 2019, 83 percent; a
2025 Mayo and Carnegie Mellon study, up to 98 percent) and any patient text burned into the image.

This harness quantifies the gap on real public brain MR (TCIA UPENN-GBM):

  1. Hash the pixel data, then run dicognito, then hash again. If the pixels are byte-identical, every
     pixel-domain re-identification channel is provably unchanged by the anonymizer.
  2. Record the direct identifiers (PatientName, PatientID, AccessionNumber) before and after, to
     confirm the anonymizer did its job on the tag channel (linkage broken).
  3. Score the file with DicomLock's re-identification score before and after, per channel.

Ethics: uses public, already-de-identified TCIA imaging. It measures residual RISK and never
re-identifies a real person. It adds no PHI; it only reads what is present and runs a standard tool.

Run:  python -m bench.reid_vs_anonymizer            # ~20 brain MR
      python -m bench.reid_vs_anonymizer --limit 60
"""

import argparse
import collections
import copy
import glob
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
if PROJECT not in sys.path:
    sys.path.insert(0, PROJECT)

import pydicom  # noqa: E402
from scanner.deid_auditor import score_reidentification_risk  # noqa: E402

_DIRECT = ["PatientName", "PatientID", "AccessionNumber", "PatientBirthDate"]


def _pixel_hash(ds):
    pd = ds.get("PixelData", None)
    return hashlib.sha256(bytes(pd)).hexdigest() if pd is not None else None


def _channels(score):
    d = score["dimensions"]
    return {
        "structured": d["structured_identifiers"]["points"],
        "text": d["text_identifiers"]["points"],
        "burned_in": d["burned_in_pixels"]["points"],
        "facial": d["facial_geometry"]["points"],
        "total": score["score"],
    }


def run_one(fp):
    ds = pydicom.dcmread(fp, force=True)
    direct_before = {t: str(getattr(ds, t, "")) for t in _DIRECT}
    px_before = _pixel_hash(ds)
    before = _channels(score_reidentification_risk(ds, use_ocr=False))

    anon = copy.deepcopy(ds)
    from dicognito.anonymizer import Anonymizer
    Anonymizer().anonymize(anon)

    direct_after = {t: str(getattr(anon, t, "")) for t in _DIRECT}
    px_after = _pixel_hash(anon)
    after = _channels(score_reidentification_risk(anon, use_ocr=False))

    changed = sum(1 for t in _DIRECT
                  if direct_before[t] and direct_before[t] != direct_after[t])
    populated = sum(1 for t in _DIRECT if direct_before[t])
    return {
        "before": before, "after": after,
        "pixels_identical": (px_before is not None and px_before == px_after),
        "direct_changed": changed, "direct_populated": populated,
    }


def main():
    ap = argparse.ArgumentParser(prog="bench.reid_vs_anonymizer")
    ap.add_argument("--dir", default=os.path.join(PROJECT, "data", "tcia_mr"))
    ap.add_argument("--limit", type=int, default=20)
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.dir, "*.dcm")))[:args.limit]
    if not files:
        print(f"no .dcm in {args.dir} (pull brain MR first: "
              f"python download_tcia.py --collection UPENN-GBM --modality MR --count 120)")
        return 0

    rows = []
    for fp in files:
        try:
            rows.append(run_one(fp))
        except Exception as e:
            print(f"  skip {os.path.basename(fp)}: {str(e)[:80]}")

    n = len(rows)
    px_identical = sum(1 for r in rows if r["pixels_identical"])
    facial_persist = sum(1 for r in rows if r["after"]["facial"] > 0)
    facial_before = sum(1 for r in rows if r["before"]["facial"] > 0)
    direct_changed = sum(r["direct_changed"] for r in rows)
    direct_populated = sum(r["direct_populated"] for r in rows)

    def mean(side, ch):
        return sum(r[side][ch] for r in rows) / n if n else 0

    print(f"\n{'='*70}\nRe-identification risk vs a standard anonymizer (dicognito 0.19)\n{'='*70}")
    print(f"corpus: {n} real public brain MR ({os.path.relpath(args.dir, PROJECT)})\n")

    print("Tag channel (what the anonymizer is built for):")
    print(f"  direct identifiers re-pseudonymized: {direct_changed}/{direct_populated} "
          f"populated direct-identifier values were changed (linkage to the real record broken)")

    print("\nPixel channel (what a tag anonymizer cannot touch):")
    print(f"  pixel data byte-identical after anonymization: {px_identical}/{n}")
    print(f"  -> every pixel-domain re-identification channel is unchanged. Facial geometry is "
          f"reconstructable\n     from a head MR regardless of any tag edit.")

    print("\nDicomLock re-identification score, mean points per channel (before -> after dicognito):")
    for ch in ("structured", "text", "burned_in", "facial", "total"):
        print(f"  {ch:11s} {mean('before', ch):5.1f} -> {mean('after', ch):5.1f}")
    print("  (structured stays populated because dicognito re-pseudonymizes the identifier tags rather")
    print("   than emptying them; the linkage to the real record is broken, per the tag-channel line")
    print("   above. The decisive residual the score captures is the pixel channel, which no tag edit")
    print("   can change.)")
    print(f"\n  files our score still flags facial-geometry risk on, after anonymization: "
          f"{facial_persist}/{n} (was {facial_before}/{n} before)")

    print(f"\n{'='*70}\nTAKEAWAY\n{'='*70}")
    print("A standard tag anonymizer re-pseudonymizes the identifier tags but leaves the pixels"
          "\nbyte-identical, so a head scan stays re-identifiable by face. Tag anonymization is not"
          "\nthe same as re-identification safety. DicomLock's score surfaces the residual pixel-domain"
          "\nrisk that the anonymizer does not address; defacing or skull-stripping is the actual fix.")

    out = os.path.join(HERE, "reid_vs_anonymizer_results.txt")
    with open(out, "w") as f:
        f.write(f"corpus: {n} real public brain MR\n")
        f.write(f"direct identifiers changed by dicognito: {direct_changed}/{direct_populated}\n")
        f.write(f"pixels byte-identical after anonymization: {px_identical}/{n}\n")
        f.write(f"facial-geometry flagged after anonymization: {facial_persist}/{n}\n")
        for ch in ("structured", "text", "burned_in", "facial", "total"):
            f.write(f"mean {ch}: {mean('before', ch):.1f} -> {mean('after', ch):.1f}\n")
    print(f"\nartifact: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
