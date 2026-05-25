#!/usr/bin/env python3
"""Pinned-vulnerable-codec efficacy harness (study Aim 3, target-grounded).

Runs the J2K pixel stream from a DICOM through a pinned OpenJPEG 2.3.0 + AddressSanitizer build
(the aim3 Docker image) and measures whether CDR neutralizes what the real, vulnerable decoder
chokes on. This is the "a real decoder breaking, and the fix" half of the study, as opposed to the
host-safe modern-parser matrix in targets.py.

Outcomes from the pinned decoder:
  clean     decoded (exit 0)
  rejected  graceful decode error
  crash     AddressSanitizer fault / killed by signal  (the memory-safety CVE class)
  oom       killed at the 2 GiB container limit         (allocation / decompression DoS)
  hang      wall-clock timeout

SAFETY: files DicomLock pre-identifies as allocation/decompression/length bombs are NOT decoded raw
(that decode is the DoS we defend against). Pre-parse rejection is the defense, recorded as
"dos(pre-identified)". The known crash + neutralization case is in _attack_test/aim3/results/.

Run:  python -m bench.pinned                 # benign J2K baseline + any J2K corpus files
      python -m bench.pinned --demo FILE.dcm # raw -> CDR -> re-decode neutralization on one file
"""

import argparse
import glob
import os
import subprocess
import sys
import tempfile

import pydicom

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
if PROJECT not in sys.path:
    sys.path.insert(0, PROJECT)

from scanner.file_security import check_length_amplification, check_pixel_dimension_bomb  # noqa: E402
from scanner.pipeline import disarm_or_quarantine  # noqa: E402

IMAGE = "dicomlock-aim3"
OPJ = "/src/openjpeg/build/bin/opj_decompress"
J2K_TS = {
    "1.2.840.10008.1.2.4.90", "1.2.840.10008.1.2.4.91",
    "1.2.840.10008.1.2.4.92", "1.2.840.10008.1.2.4.93",
}


def image_available():
    try:
        subprocess.run(["docker", "image", "inspect", IMAGE],
                       capture_output=True, check=True)
        return True
    except Exception:
        return False


def is_dos_bomb(fp):
    findings = list(check_length_amplification(fp))
    try:
        findings += list(check_pixel_dimension_bomb(pydicom.dcmread(fp, force=True)))
    except Exception:
        pass
    return any(f.severity in ("fail", "critical") for f in findings)


def extract_j2k(fp):
    """First J2K frame from an encapsulated J2K DICOM, or None if not J2K / not extractable."""
    ds = pydicom.dcmread(fp, force=True)
    ts = str(getattr(ds.file_meta, "TransferSyntaxUID", ""))
    if ts not in J2K_TS or "PixelData" not in ds:
        return None
    raw = ds.PixelData
    import pydicom.encaps as E
    n = int(getattr(ds, "NumberOfFrames", 1) or 1)
    for name, kwargs in (("generate_frames", {"number_of_frames": n}),
                         ("generate_pixel_data_frame", {}),
                         ("decode_data_sequence", {})):
        fn = getattr(E, name, None)
        if not fn:
            continue
        try:
            frames = list(fn(raw, **kwargs))
            if frames:
                return bytes(frames[0])
        except Exception:
            continue
    return None


def decode_pinned(j2k_bytes, timeout=60):
    """Run the pinned decoder on raw J2K bytes inside Docker (2 GiB cap). Returns (label, detail)."""
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "in.j2k"), "wb") as f:
            f.write(j2k_bytes)
        argv = ["docker", "run", "--rm", "-m", "2g", "-v", f"{d}:/in", IMAGE,
                "sh", "-c", f"{OPJ} -i /in/in.j2k -o /in/out.pgm"]
        try:
            p = subprocess.run(argv, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return "hang", "timeout"
        out = (p.stdout + p.stderr).decode("latin1", "ignore")
        if "AddressSanitizer" in out or "runtime error" in out:
            return "crash", "ASan fault"
        if p.returncode < 0:
            return f"crash(sig{-p.returncode})", ""
        if p.returncode == 137:
            return "oom", "container OOM-killed at 2 GiB"
        if p.returncode != 0:
            return "rejected", f"rc={p.returncode}"
        return "clean", ""


def raw_outcome(fp):
    if is_dos_bomb(fp):
        return "dos(pre-identified)", "not decoded raw (the decode IS the DoS)"
    j2k = extract_j2k(fp)
    if j2k is None:
        return "n/a", "no extractable J2K"
    return decode_pinned(j2k)


def main():
    ap = argparse.ArgumentParser(prog="bench.pinned")
    ap.add_argument("--demo", metavar="FILE", help="raw -> CDR -> re-decode neutralization on one DICOM")
    ap.add_argument("--dir", default=os.path.join(PROJECT, "samples"))
    args = ap.parse_args()

    if not image_available():
        print(f"Pinned image '{IMAGE}' not found. Build it: see _attack_test/aim3/ "
              "(docker build -t dicomlock-aim3 _attack_test/aim3). Skipping.")
        return 0

    if args.demo:
        raw, detail = raw_outcome(args.demo)
        print(f"RAW   {os.path.basename(args.demo)} -> {raw}  {detail}")
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "clean.dcm")
            action = disarm_or_quarantine(args.demo, out_path=out)["action"]
            print(f"CDR   -> {action}")
            if action == "disarmed" and os.path.exists(out):
                post, pd = raw_outcome(out)
                print(f"POST  -> {post}  {pd}")
                print("NEUTRALIZED" if post in ("clean", "rejected", "n/a") else "NOT NEUTRALIZED")
            else:
                print("NEUTRALIZED (quarantined; never reaches the decoder)")
        return 0

    files = [fp for fp in sorted(glob.glob(os.path.join(args.dir, "*.dcm")))
             if str(getattr(pydicom.dcmread(fp, force=True).file_meta, "TransferSyntaxUID", "")) in J2K_TS]
    print(f"Pinned OpenJPEG 2.3.0+ASan over {len(files)} J2K file(s) from {args.dir}:\n")
    for fp in files:
        label, detail = raw_outcome(fp)
        print(f"  {os.path.basename(fp):<34} {label:<22} {detail}")
    print("\nBenign J2K should decode 'clean'. The crash + CDR-neutralization case is documented in "
          "_attack_test/aim3/results/ (reproduce with --demo on that malicious DICOM).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
