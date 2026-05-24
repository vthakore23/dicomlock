#!/usr/bin/env python3
"""
Phase 2 spike — does the CDR fix work on the HARD case?

Easy case (already proven): zero a polyglot preamble on a native file -> bit-exact.
Hard case (this): files whose pixels route through a third-party codec (JPEG2000/JPEG-LS/
JPEG). Disarm must transcode them OFF the vulnerable codec while keeping the image exact,
including a worst-case file that is BOTH compressed AND a polyglot.
"""

import os
import sys

import pydicom

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
sys.path.insert(0, PROJECT)

from scanner.disarm import disarm  # noqa: E402
from scanner.codec_cve import check_codec_cve_exposure  # noqa: E402
from scanner.file_security import check_preamble  # noqa: E402

OUT = HERE


def codec_state(fp):
    f = check_codec_cve_exposure(pydicom.dcmread(fp, force=True))[0]
    return f"{f.severity.upper()} ({f.message})"


def preamble_state(fp):
    f = check_preamble(fp)[0]
    return f"{f.severity.upper()} ({f.message[:46]})"


SAMPLES = [
    ("JPEG2000 lossless (OpenJPEG)", "MR_small_jp2klossless.dcm"),
    ("JPEG-LS lossless (CharLS)", "MR_small_jpeg_ls_lossless.dcm"),
    ("JPEG lossy (libjpeg)", "JPEG_lossy.dcm"),
]


def run_one(label, fp, out_name):
    out = os.path.join(OUT, out_name)
    print(label)
    print(f"   BEFORE  codec: {codec_state(fp)}")
    res = disarm(fp, out_path=out)
    if res.error:
        print(f"   DISARM ERROR: {res.error}\n")
        return
    print(f"   changes: {res.changes}")
    print(f"   AFTER   codec: {codec_state(res.out_path)}")
    print(f"   IMAGE PRESERVED BIT-EXACT: {res.image_preserved}")
    print()


def main():
    print("===== CDR on compressed files (transcode off the codec, keep image exact) =====\n")
    for label, name in SAMPLES:
        run_one(label, os.path.join(PROJECT, "samples", name), name.replace(".dcm", ".disarmed.dcm"))

    # Worst case: JPEG2000 lossless that is ALSO an ELF polyglot.
    print("===== WORST CASE: JPEG2000 + ELF polyglot (both threats in one file) =====")
    base = os.path.join(PROJECT, "samples", "MR_small_jp2klossless.dcm")
    poly = os.path.join(OUT, "compressed_polyglot.dcm")
    raw = bytearray(open(base, "rb").read())
    raw[0:4] = b"\x7fELF"
    with open(poly, "wb") as f:
        f.write(raw)
    print(f"   BEFORE  preamble: {preamble_state(poly)}")
    print(f"   BEFORE  codec   : {codec_state(poly)}")
    res = disarm(poly, out_path=os.path.join(OUT, "compressed_polyglot.disarmed.dcm"))
    if res.error:
        print(f"   DISARM ERROR: {res.error}")
        return
    print(f"   changes: {res.changes}")
    print(f"   AFTER   preamble: {preamble_state(res.out_path)}")
    print(f"   AFTER   codec   : {codec_state(res.out_path)}")
    print(f"   IMAGE PRESERVED BIT-EXACT: {res.image_preserved}")


if __name__ == "__main__":
    main()
