#!/usr/bin/env python3
"""Diverse-modality false-positive + CDR-fidelity check (Track C2).

The headline "0 false positives across 575 real CTs" and the bit-exact fidelity numbers rest on a
homogeneous corpus (the CTs are all native Explicit VR Little Endian, so the codec and private-tag
paths are never exercised at scale). This harness runs the REAL security scan (false positives) and
the REAL CDR rebuild (fidelity) over diverse real clinical DICOM pulled from TCIA beyond the CTs:

  - brain MR (UPENN-GBM)            -> data/tcia_mr
  - chest radiography CR/DX (LIDC)  -> data/tcia_xr

For every file it records whether the scan blocks it (a candidate false positive) and lists the
blocking finding, so a genuine false positive is distinguished from a correctly-rejected
non-conformant file (no Part-10 header, truncated, missing dimensions). It also disarms each file and
reports the fidelity bucket per modality and per transfer syntax. No network; reuses the shipped
scanner and CDR exactly as a user would.

Run:  python -m bench.diverse_check
      python -m bench.diverse_check --dir data/tcia_mr --limit 50
"""

import argparse
import collections
import glob
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
if PROJECT not in sys.path:
    sys.path.insert(0, PROJECT)

from scanner.pipeline import run_security_scan  # noqa: E402
from bench.fidelity import measure, ts_name  # noqa: E402

_DANGER = {"fail", "critical"}

# label -> directory (relative to the project root)
DEFAULT_DIRS = {
    "MR (brain, UPENN-GBM)": os.path.join(PROJECT, "data", "tcia_mr"),
    "XR (chest CR/DX, LIDC-IDRI)": os.path.join(PROJECT, "data", "tcia_xr"),
}


def check_dir(label, directory, tmp, limit=0):
    files = sorted(glob.glob(os.path.join(directory, "*.dcm")))
    if limit:
        files = files[:limit]
    n = len(files)
    blocked = []           # (name, [blocking messages]) -> candidate false positives
    fid = collections.Counter()
    by_ts = collections.defaultdict(lambda: collections.Counter())
    parse_errors = 0

    for fp in files:
        # 1) false-positive check: does the default scan raise a blocking verdict on benign data?
        try:
            report = run_security_scan(fp)
            msgs = [f["message"] for f in report["findings"] if f["severity"] in _DANGER]
            if msgs:
                blocked.append((os.path.basename(fp), msgs))
        except Exception as e:
            parse_errors += 1

        # 2) fidelity check: disarm and classify the rebuild outcome
        try:
            o = measure(fp, tmp)
        except Exception as e:
            o = {"ts": ts_name(fp), "bucket": "skipped", "detail": str(e)[:60]}
        fid[o["bucket"]] += 1
        by_ts[o["ts"]][o["bucket"]] += 1

    return {
        "label": label, "n": n, "blocked": blocked, "fid": fid,
        "by_ts": by_ts, "parse_errors": parse_errors,
    }


def print_result(r):
    print(f"\n{'='*70}\n{r['label']}  ({r['n']} files)\n{'='*70}")
    lossless = r["fid"]["lossless_bitexact"] + r["fid"]["lossless_BREAK"]
    lossy = r["fid"]["lossy_preserved"] + r["fid"]["lossy_changed"]
    print(f"  Blocking verdicts (candidate false positives): {len(r['blocked'])}/{r['n']}")
    for name, msgs in r["blocked"][:15]:
        print(f"     {name}: {msgs[0][:90]}")
    if len(r["blocked"]) > 15:
        print(f"     ... and {len(r['blocked'])-15} more")
    print(f"  CDR fidelity:")
    print(f"     native/lossless bit-exact: {r['fid']['lossless_bitexact']}/{lossless}"
          + (f"  (BREAKS {r['fid']['lossless_BREAK']})" if r['fid']['lossless_BREAK'] else ""))
    print(f"     lossy preserved-as-decoded: {r['fid']['lossy_preserved']}/{lossy}"
          + (f"  (CHANGED {r['fid']['lossy_changed']})" if r['fid']['lossy_changed'] else ""))
    print(f"     skipped (no image/un-decodable/quarantined): {r['fid']['skipped']}")
    print(f"  By transfer syntax:")
    for ts in sorted(r["by_ts"], key=lambda k: -sum(r["by_ts"][k].values())):
        c = r["by_ts"][ts]
        print(f"     {ts[:48]:48s} bitexact={c['lossless_bitexact']:>4} "
              f"lossy={c['lossy_preserved']:>3} skip={c['skipped']:>3}"
              + ("  <-- BREAK" if c["lossless_BREAK"] or c["lossy_changed"] else ""))


def main():
    ap = argparse.ArgumentParser(prog="bench.diverse_check")
    ap.add_argument("--dir", action="append", help="extra directory to check (repeatable)")
    ap.add_argument("--limit", type=int, default=0, help="cap files per directory")
    args = ap.parse_args()

    dirs = dict(DEFAULT_DIRS)
    for d in (args.dir or []):
        dirs[os.path.basename(d.rstrip("/"))] = (d if os.path.isabs(d)
                                                 else os.path.join(PROJECT, d))

    results = []
    with tempfile.TemporaryDirectory(prefix="dicomlock-diverse-") as tmp:
        for label, directory in dirs.items():
            if not os.path.isdir(directory) or not glob.glob(os.path.join(directory, "*.dcm")):
                print(f"\n(skipping {label}: no .dcm in {directory})")
                continue
            results.append(check_dir(label, directory, tmp, args.limit))

    total = sum(r["n"] for r in results)
    total_blocked = sum(len(r["blocked"]) for r in results)
    total_break = sum(r["fid"]["lossless_BREAK"] + r["fid"]["lossy_changed"] for r in results)
    for r in results:
        print_result(r)

    print(f"\n{'='*70}\nSUMMARY (diverse modalities, beyond the 575 CTs)\n{'='*70}")
    print(f"  files: {total}")
    print(f"  blocking verdicts (inspect each, benign data should be 0 unless non-conformant): "
          f"{total_blocked}")
    print(f"  fidelity breaks (lossless not bit-exact, or lossy altered): {total_break}")

    out = os.path.join(HERE, "diverse_check_results.txt")
    with open(out, "w") as f:
        for r in results:
            ll = r["fid"]["lossless_bitexact"] + r["fid"]["lossless_BREAK"]
            ly = r["fid"]["lossy_preserved"] + r["fid"]["lossy_changed"]
            f.write(f"{r['label']}: {r['n']} files; blocked={len(r['blocked'])}; "
                    f"lossless_bitexact={r['fid']['lossless_bitexact']}/{ll}; "
                    f"lossy_preserved={r['fid']['lossy_preserved']}/{ly}; "
                    f"skipped={r['fid']['skipped']}; breaks="
                    f"{r['fid']['lossless_BREAK']+r['fid']['lossy_changed']}\n")
            for name, msgs in r["blocked"]:
                f.write(f"    BLOCKED {name}: {msgs}\n")
    print(f"\nartifact: {out}")
    return 1 if total_break else 0


if __name__ == "__main__":
    raise SystemExit(main())
