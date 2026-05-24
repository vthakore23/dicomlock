#!/usr/bin/env python3
"""
Aim 3 harness (the STUDY START) — paired raw-vs-CDR evaluation.

For each input file this runs the core experiment from ../STUDY_DESIGN.md:
  1. RAW   -> feed the file to a target parser/decoder in a sandboxed subprocess; record outcome
  2. CDR   -> disarm_or_quarantine(); record verdict (disarmed | quarantined)
  3. POST  -> if disarmed, feed the disarmed file to the same target; record outcome
  4. FIDELITY -> if raw and disarmed both decode, compare pixel arrays bit-exact

NEUTRALIZED = after CDR the target no longer hits a dangerous outcome — either the file was
disarmed to something that parses cleanly, or it was quarantined and never reaches the parser.

Outcomes (subprocess return signal makes C-level faults observable, unlike in-process try/except):
  ok        exit 0                      parsed + decoded cleanly
  rejected  exit 1 (Python exception)   parser refused it (a SAFE outcome)
  CRASH     killed by signal (segv/OOM) the bug class the CVEs represent
  HANG      wall-clock timeout          denial of service

SAFETY: files that DicomLock pre-identifies as allocation/decompression/length bombs are NOT
executed raw (decoding them is the very DoS we defend against). That pre-parse rejection IS the
defense, so the harness records "would-DoS (pre-identified)" instead of thrashing the host.

This is in the repo as a runnable START. On today's inert corpus modern parsers mostly ACCEPT or
REJECT (they don't segfault — that needs pinned-vulnerable builds per the study). Point --dir at a
fuzzer corpus and add pinned targets to TARGETS to scale to the full Aim 1/3 evaluation.

Run:  python3 _attack_test/cdr_vs_parsers.py [--dir samples/tampered]
"""

import argparse
import glob
import os
import subprocess
import sys

import pydicom

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
sys.path.insert(0, PROJECT)

from scanner.file_security import check_length_amplification, check_pixel_dimension_bomb  # noqa: E402
from scanner.pipeline import disarm_or_quarantine  # noqa: E402

TIMEOUT_S = 15
MEM_LIMIT_BYTES = 2 * 1024 ** 3  # 2 GiB rlimit on each worker so a bomb can't take down the host

# A target = (name, [argv...]) where {f} is replaced by the file path. The worker parses AND
# decodes pixels, so the codec path (the deep attack surface) is actually exercised.
_PYDICOM_WORKER = (
    "import sys,pydicom; ds=pydicom.dcmread(sys.argv[1],force=True); "
    "ds.pixel_array if 'PixelData' in ds else 0"
)
TARGETS = [
    ("pydicom", [sys.executable, "-c", _PYDICOM_WORKER, "{f}"]),
    # ("dcmdump", ["dcmdump", "{f}"]),   # uncomment if dcmtk is installed (C++ crash-observable)
]


def _limit_memory():
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (MEM_LIMIT_BYTES, MEM_LIMIT_BYTES))
        resource.setrlimit(resource.RLIMIT_CPU, (TIMEOUT_S, TIMEOUT_S))
    except Exception:
        pass


def is_dos_bomb(fp: str) -> bool:
    """True if DicomLock flags this as an allocation/decompression/length bomb — do NOT execute it
    raw (that decode is the DoS). Pre-parse rejection is the defense."""
    findings = list(check_length_amplification(fp))
    try:
        ds = pydicom.dcmread(fp, force=True)
        findings += check_pixel_dimension_bomb(ds)
    except Exception:
        pass
    return any(f.severity in ("fail", "critical") for f in findings)


def run_target(argv_tmpl, fp) -> str:
    argv = [a.replace("{f}", fp) for a in argv_tmpl]
    try:
        p = subprocess.run(argv, capture_output=True, timeout=TIMEOUT_S,
                           preexec_fn=_limit_memory)
    except subprocess.TimeoutExpired:
        return "HANG"
    except FileNotFoundError:
        return "n/a"
    if p.returncode == 0:
        return "ok"
    if p.returncode < 0:
        return f"CRASH(sig{-p.returncode})"
    return "rejected"


def fidelity(raw_fp, disarmed_fp):
    try:
        import numpy as np
        a = pydicom.dcmread(raw_fp, force=True)
        b = pydicom.dcmread(disarmed_fp, force=True)
        if "PixelData" not in a or "PixelData" not in b:
            return "n/a"
        return "bit-exact" if np.array_equal(a.pixel_array, b.pixel_array) else "CHANGED"
    except Exception:
        return "n/a"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=os.path.join(PROJECT, "samples", "tampered"))
    args = ap.parse_args()

    files = sorted(glob.glob(os.path.join(args.dir, "*.dcm")))
    if not files:
        print(f"No .dcm files in {args.dir}")
        return

    name = TARGETS[0][0]
    print(f"\nPaired raw-vs-CDR evaluation (target: {name}) on {len(files)} files from {args.dir}\n")
    hdr = f"{'file':<26}{'raw':<16}{'CDR verdict':<14}{'post-CDR':<16}{'fidelity':<12}{'neutralized'}"
    print(hdr)
    print("-" * len(hdr))

    neutralized = total_dangerous = 0
    for fp in files:
        base = os.path.basename(fp)
        out = os.path.join(HERE, base.replace(".dcm", ".cdrtest.dcm"))

        # 1) RAW (skip execution for pre-identified DoS bombs — see SAFETY)
        bomb = is_dos_bomb(fp)
        raw = "would-DoS*" if bomb else run_target(TARGETS[0][1], fp)

        # 2) CDR
        verdict = disarm_or_quarantine(fp, out_path=out)
        action = verdict["action"]

        # 3) POST-CDR + 4) fidelity
        post = fid = "—"
        if action == "disarmed":
            post = run_target(TARGETS[0][1], out)
            fid = fidelity(fp, out) if not bomb else "n/a"
        elif action == "quarantined":
            post = "(blocked)"

        # neutralization bookkeeping: a file is "dangerous raw" if it would DoS or actually
        # crashed/hung the target; neutralized if post-CDR it's clean/rejected or was quarantined.
        dangerous_raw = bomb or raw.startswith("CRASH") or raw == "HANG"
        if dangerous_raw:
            total_dangerous += 1
            ok_post = action == "quarantined" or post in ("ok", "rejected")
            if ok_post:
                neutralized += 1
        mark = "yes" if (dangerous_raw and (action == "quarantined" or post in ("ok", "rejected"))) else \
               ("" if not dangerous_raw else "NO")

        print(f"{base:<26}{raw:<16}{action:<14}{post:<16}{fid:<12}{mark}")
        if os.path.exists(out):
            os.unlink(out)

    print("-" * len(hdr))
    print(f"\nDangerous-raw inputs: {total_dangerous}   neutralized by CDR: {neutralized}/{total_dangerous}")
    print("* would-DoS = DicomLock pre-identified an allocation/decompression/length bomb and the")
    print("  harness did NOT execute it raw (pre-parse rejection is the defense).")
    print("\nNote: modern unpinned parsers mostly ACCEPT/REJECT the inert corpus rather than CRASH.")
    print("Reproduce real segfaults by pointing --dir at a fuzzer corpus + adding pinned-vulnerable")
    print("targets to TARGETS (see ../STUDY_DESIGN.md, Aims 1–3).")


if __name__ == "__main__":
    main()
