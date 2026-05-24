#!/usr/bin/env python3
"""
Scale validation — run the Phase 1 security checks against ALL real clinical CT files
to measure the true false-positive rate. These are genuine TCIA files: ANY fail/critical
is a false positive; warns are noise to quantify.
"""

import glob
import os
import sys
import time
from collections import defaultdict

import pydicom

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
sys.path.insert(0, PROJECT)

from scanner.file_security import (  # noqa: E402
    check_preamble, check_length_amplification,
    check_sequence_depth, check_pixel_dimension_bomb, check_private_tag_payloads,
)
from scanner.codec_cve import check_codec_cve_exposure  # noqa: E402

ORDER = {"pass": 0, "info": 1, "warn": 2, "fail": 3, "critical": 4}
ALARM = {"fail", "critical"}
CHECKS = ["preamble", "length_amp", "seq_depth", "pixel_bomb", "private", "codec"]


def worst(findings):
    return max((f.severity for f in findings), default="pass",
               key=lambda s: ORDER.get(s, 0)) if findings else "pass"


def main():
    root = os.path.join(PROJECT, "data", "tcia_ct")

    def _is_dicom(f):
        try:
            with open(f, "rb") as h:
                h.seek(128)
                return h.read(4) == b"DICM"
        except Exception:
            return False

    all_files = [f for f in glob.glob(os.path.join(root, "**", "*"), recursive=True)
                 if os.path.isfile(f)]
    files = [f for f in all_files if _is_dicom(f)]
    print(f"Found {len(all_files)} files; {len(files)} are valid Part-10 DICOM "
          f"({len(all_files) - len(files)} non-DICOM skipped)\n")

    sev_counts = {c: defaultdict(int) for c in CHECKS}
    parse_errors = 0
    examples = defaultdict(list)
    t0 = time.time()

    for i, fp in enumerate(files):
        # byte-level checks (no parse needed)
        for name, fn in (("preamble", check_preamble), ("length_amp", check_length_amplification)):
            try:
                s = worst(fn(fp))
            except Exception:
                s = "error"
            sev_counts[name][s] += 1
            if s in ALARM and len(examples[name]) < 5:
                examples[name].append(os.path.basename(fp))
        # parse-based checks
        try:
            ds = pydicom.dcmread(fp, force=True)
            for name, fn in (("seq_depth", check_sequence_depth),
                             ("pixel_bomb", check_pixel_dimension_bomb),
                             ("private", check_private_tag_payloads),
                             ("codec", check_codec_cve_exposure)):
                s = worst(fn(ds))
                sev_counts[name][s] += 1
                if s in ALARM and len(examples[name]) < 5:
                    examples[name].append(os.path.basename(fp))
        except Exception:
            parse_errors += 1

    dt = time.time() - t0
    n = len(files)
    print(f"Done in {dt:.1f}s ({1000*dt/max(n,1):.1f} ms/file). Parse errors: {parse_errors}\n")
    print(f"{'check':<13}{'pass':>7}{'info':>7}{'warn':>7}{'fail':>7}{'critical':>10}   FALSE POSITIVES")
    print("-" * 72)
    total_fp = 0
    for c in CHECKS:
        sc = sev_counts[c]
        fp = sc.get("fail", 0) + sc.get("critical", 0)
        total_fp += fp
        print(f"{c:<13}{sc.get('pass',0):>7}{sc.get('info',0):>7}{sc.get('warn',0):>7}"
              f"{sc.get('fail',0):>7}{sc.get('critical',0):>10}   {fp}")
    print("-" * 72)
    print(f"\nTOTAL FALSE POSITIVES (fail/critical on real files): {total_fp}")
    for c in CHECKS:
        if examples[c]:
            print(f"  {c} flagged: {examples[c]}")
    # codec warns are EXPECTED exposure reporting, not FPs — note count
    cw = sev_counts["codec"].get("warn", 0)
    pw = sev_counts["private"].get("warn", 0)
    print(f"\nNote: codec 'warn' = correct exposure reporting (not FP): {cw}")
    print(f"Note: private-tag 'warn' (entropy heuristic, potential noise): {pw}")


if __name__ == "__main__":
    main()
