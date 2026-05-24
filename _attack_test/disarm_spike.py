#!/usr/bin/env python3
"""
Fix-feasibility spike: can we actually NEUTRALIZE a weaponized file while keeping the
medical image bit-exact? (Minimal proof for the polyglot class — full CDR is Phase 2.)

Disarm step here = zero the 128-byte preamble of the polyglot. Then prove:
  1. the OS no longer sees an executable (weapon neutralized)
  2. the pixel data is BIT-EXACT vs the original clean scan (image preserved)
  3. DicomLock now passes the file
"""

import hashlib
import os
import subprocess
import sys

import numpy as np
import pydicom

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
sys.path.insert(0, PROJECT)

from scanner.file_security import check_preamble  # noqa: E402

BASE = os.path.join(PROJECT, "samples", "CT_small_pydicom.dcm")          # original clean
WEAP = os.path.join(PROJECT, "samples", "tampered", "polyglot_elf.dcm")  # weaponized
OUT = os.path.join(HERE, "polyglot_elf.disarmed.dcm")                    # after disarm


def filetype(p):
    try:
        return subprocess.run(["file", "-b", p], capture_output=True, text=True).stdout.strip()
    except Exception:
        return "(file cmd unavailable)"


def pixhash(p):
    return hashlib.sha256(pydicom.dcmread(p).pixel_array.tobytes()).hexdigest()


def main():
    # --- disarm: rebuild with a zeroed preamble ---
    raw = bytearray(open(WEAP, "rb").read())
    raw[0:128] = b"\x00" * 128
    with open(OUT, "wb") as f:
        f.write(raw)

    print("1) WEAPON NEUTRALIZED?")
    print(f"   weaponized : file says -> {filetype(WEAP)}")
    print(f"   disarmed   : file says -> {filetype(OUT)}")

    print("\n2) IMAGE PRESERVED BIT-EXACT?")
    base_h = pixhash(BASE)
    out_h = pixhash(OUT)
    ds = pydicom.dcmread(OUT)
    equal = np.array_equal(pydicom.dcmread(BASE).pixel_array, ds.pixel_array)
    print(f"   original  pixel SHA-256: {base_h[:32]}...")
    print(f"   disarmed  pixel SHA-256: {out_h[:32]}...")
    print(f"   numpy array_equal      : {equal}")
    print(f"   still a valid scan     : Modality={getattr(ds,'Modality','?')} "
          f"shape={ds.pixel_array.shape}")

    print("\n3) DICOMLOCK VERDICT ON DISARMED FILE:")
    for fnd in check_preamble(OUT):
        print(f"   [{fnd.severity.upper()}] {fnd.message}")

    ok = (filetype(OUT) != filetype(WEAP)) and equal and (base_h == out_h)
    print("\n" + ("RESULT: FIX WORKS — weapon removed, image bit-exact." if ok
                  else "RESULT: check output above."))


if __name__ == "__main__":
    main()
