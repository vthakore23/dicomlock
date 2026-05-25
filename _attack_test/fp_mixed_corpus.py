#!/usr/bin/env python3
"""
Mixed-compression false-positive corpus (addresses AUDIT.md weakness #7).

The headline "0 false positives across 575 real CTs" is on a HOMOGENEOUS, uncompressed
corpus (every CT is native Explicit VR LE), so the codec-CVE and private-tag paths are
never exercised at scale. This harness scans a deliberately HETEROGENEOUS corpus drawn
ONLY from DICOM files already on disk (pydicom + pylibjpeg bundled test data + the repo
samples) — no network download — covering JPEG Baseline/Extended/Lossless, JPEG-LS
lossy+lossless, JPEG 2000, RLE, deflate, big-endian, and implicit VR, including files
that carry private tags.

It reports the metric that actually matters for adoption:
  * FALSE POSITIVE  = a benign file given a blocking verdict (FAIL/CRITICAL, i.e. is_dangerous).
                      Target ~0. Any hit is printed in full so it can be judged a true FP
                      vs a genuinely-malformed test file.
  * WARN rate       = files drawing >=1 warn (mostly by-design codec-CVE *exposure*). This is
                      NOT an error, but it is the "warn fatigue" surface the audit flagged, so
                      we quantify it honestly, including the compressed-only subset.

Run:  python _attack_test/fp_mixed_corpus.py
"""

import os
import sys
import glob
import hashlib
import collections

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)

import pydicom
from pydicom.uid import UID

from scanner.pipeline import run_security_scan, is_dangerous


def gather():
    """Union of on-disk DICOMs, deduplicated by content hash. No network."""
    sp = os.path.dirname(os.path.dirname(pydicom.__file__))  # site-packages
    candidates = []
    candidates += glob.glob(os.path.join(sp, "**", "*.dcm"), recursive=True)
    candidates += glob.glob(os.path.join(REPO, "samples", "*.dcm"))  # NOT samples/tampered/
    seen, files = set(), []
    for fp in sorted(candidates):
        try:
            h = hashlib.sha256(open(fp, "rb").read()).hexdigest()
        except OSError:
            continue
        if h in seen:
            continue
        seen.add(h)
        files.append(fp)
    return files


def describe(fp):
    try:
        ds = pydicom.dcmread(fp, stop_before_pixels=True, force=True)
        ts = str(getattr(ds.file_meta, "TransferSyntaxUID", "")) or "(none)"
        try:
            tsname = UID(ts).name if ts != "(none)" else "(no file meta)"
            comp = ts != "(none)" and UID(ts).is_compressed
        except Exception:
            tsname, comp = ts, False
        priv = any(e.tag.is_private for e in ds)
        return ts, tsname, bool(comp), bool(priv)
    except Exception:
        return "(unreadable header)", "(unreadable header)", False, False


def main():
    files = gather()
    print(f"corpus: {len(files)} unique on-disk DICOM files "
          f"(pydicom + pylibjpeg bundled test data + repo samples; no download)\n")

    by_ts = collections.defaultdict(lambda: collections.Counter())
    rows = []
    fp_hits, warn_hits, comp_total, comp_warn, priv_total, priv_danger = [], 0, 0, 0, 0, 0

    for fp in files:
        ts, tsname, comp, priv = describe(fp)
        try:
            rep = run_security_scan(fp)
        except Exception as e:
            rows.append((fp, tsname, comp, priv, "SCAN_ERROR", True,
                         [{"check": "scan_error", "severity": "critical", "message": str(e)[:160]}], []))
            by_ts[tsname]["SCAN_ERROR"] += 1
            fp_hits.append(rows[-1])
            continue
        overall = rep["summary"]["overall"]
        danger = is_dangerous(rep)
        dangers = [f for f in rep["findings"] if f["severity"] in ("fail", "critical")]
        warns = [f for f in rep["findings"] if f["severity"] == "warn"]
        rows.append((fp, tsname, comp, priv, overall, danger, dangers, warns))
        by_ts[tsname][overall] += 1
        if comp:
            comp_total += 1
            if warns:
                comp_warn += 1
        if priv:
            priv_total += 1
            if danger:
                priv_danger += 1
        if warns:
            warn_hits += 1
        if danger:
            fp_hits.append(rows[-1])

    # Per-transfer-syntax verdict table
    cols = ["CLEAN", "CAUTION", "SUSPICIOUS", "FAIL", "CRITICAL", "SCAN_ERROR"]
    print(f"{'transfer syntax':42s} {'n':>3} " + " ".join(f"{c[:5]:>6}" for c in cols)
          + "  compressed")
    print("-" * 110)
    for tsname in sorted(by_ts, key=lambda k: -sum(by_ts[k].values())):
        c = by_ts[tsname]
        n = sum(c.values())
        any_comp = any(comp for (_, t, comp, _, _, _, _, _) in rows if t == tsname)
        print(f"{tsname[:42]:42s} {n:>3} "
              + " ".join(f"{c.get(col, 0):>6}" for col in cols)
              + f"   {'yes' if any_comp else 'no'}")

    n = len(files)
    print("\n" + "=" * 70)
    print("HEADLINE")
    print("=" * 70)
    print(f"  false positives (benign file given a BLOCKING FAIL/CRITICAL verdict): "
          f"{len(fp_hits)} / {n}")
    print(f"  warn rate (>=1 warn, mostly by-design codec-CVE exposure):            "
          f"{warn_hits} / {n}  ({100*warn_hits/n:.0f}%)")
    print(f"  warn rate on the COMPRESSED subset:                                   "
          f"{comp_warn} / {comp_total}"
          + (f"  ({100*comp_warn/comp_total:.0f}%)" if comp_total else ""))
    print(f"  private-tag files flagged dangerous (FAIL/CRITICAL):                  "
          f"{priv_danger} / {priv_total}")

    print("\n" + "=" * 70)
    print("FILES GIVEN A BLOCKING VERDICT (inspect: true FP vs genuinely-malformed)")
    print("=" * 70)
    if not fp_hits:
        print("  (none)")
    else:
        for fp, tsname, comp, priv, overall, danger, dangers, warns in fp_hits:
            print(f"  {os.path.basename(fp)}  [{tsname}]  -> {overall}")
            for d in dangers:
                print(f"      [{d['severity']}] {d['check']}: {d['message'][:150]}")

    # Persist a short artifact for the preprint.
    out = os.path.join(HERE, "fp_mixed_results.txt")
    with open(out, "w") as f:
        f.write(f"mixed-compression FP corpus: {n} unique on-disk DICOMs\n")
        f.write(f"false positives (FAIL/CRITICAL on benign): {len(fp_hits)}/{n}\n")
        f.write(f"warn rate: {warn_hits}/{n}; compressed-subset warn rate: "
                f"{comp_warn}/{comp_total}\n")
        f.write(f"private-tag files flagged dangerous: {priv_danger}/{priv_total}\n\n")
        for tsname in sorted(by_ts, key=lambda k: -sum(by_ts[k].values())):
            f.write(f"{tsname}: {dict(by_ts[tsname])}\n")
        if fp_hits:
            f.write("\nblocking-verdict files:\n")
            for fp, tsname, comp, priv, overall, danger, dangers, warns in fp_hits:
                f.write(f"  {os.path.basename(fp)} [{tsname}] {overall}\n")
                for d in dangers:
                    f.write(f"    [{d['severity']}] {d['check']}: {d['message'][:200]}\n")
    print(f"\nartifact written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
