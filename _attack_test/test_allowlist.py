#!/usr/bin/env python3
"""
Validate the private-tag allowlist (default-deny):
  1. clean GE file        -> keep all legit GEMS_* tags
  2. payload, unknown creator -> strip that block, keep GE tags
  3. payload hidden UNDER an allowlisted creator -> exe-signature override must still strip it
All three must keep the image bit-exact and leave no residual danger.
"""

import os
import sys

import pydicom

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
sys.path.insert(0, PROJECT)

from scanner.disarm import disarm, _load_private_allowlist  # noqa: E402
from scanner.pipeline import run_security_scan  # noqa: E402


def residual_danger(fp):
    rep = run_security_scan(fp)
    return [f["message"] for f in rep["findings"] if f["severity"] in ("fail", "critical")] or ["none"]


def report(label, src, out):
    res = disarm(src, out_path=out)
    print(label)
    if res.error:
        print(f"   ERROR: {res.error}\n")
        return
    print(f"   changes: {res.changes}")
    print(f"   image bit-exact: {res.image_preserved}")
    print(f"   residual danger after disarm: {residual_danger(res.out_path)}")
    print()


def main():
    print(f"allowlist creators: {len(_load_private_allowlist())}\n")

    report("1) Clean GE CT (179 legit GEMS_* tags) — expect KEEP ALL",
           os.path.join(PROJECT, "samples", "CT_small_pydicom.dcm"),
           os.path.join(HERE, "allow_ge.disarmed.dcm"))

    report("2) Payload under UNKNOWN creator (DICOMLOCK_TEST) — expect STRIP block, KEEP GE",
           os.path.join(PROJECT, "samples", "tampered", "private_payload.dcm"),
           os.path.join(HERE, "allow_payload.disarmed.dcm"))

    # 3) hide an ELF payload UNDER an existing allowlisted creator block
    src = os.path.join(PROJECT, "samples", "CT_small_pydicom.dcm")
    ds = pydicom.dcmread(src, force=True)
    allow = _load_private_allowlist()
    target = next(((e.tag.group, e.tag.element, str(e.value)) for e in ds
                   if e.tag.is_private and 0x0010 <= e.tag.element <= 0x00FF
                   and str(e.value) in allow), None)
    grp, creator_elem, cname = target
    data_tag = pydicom.tag.Tag(grp, (creator_elem << 8) | 0x55)
    ds.add_new(data_tag, "OB", b"\x7fELF" + b"\x00" * 2048)
    hidden = os.path.join(HERE, "hidden_in_vendor.dcm")
    try:
        ds.save_as(hidden)
    except TypeError:
        ds.save_as(hidden, enforce_file_format=False)
    print(f"   (hid ELF payload at {data_tag} under allowlisted creator '{cname}')")
    print(f"   scanner sees the planted file as: {residual_danger(hidden)}")
    report("3) Payload hidden UNDER an allowlisted vendor creator — exe-override must STRIP it",
           hidden, os.path.join(HERE, "allow_hidden.disarmed.dcm"))


if __name__ == "__main__":
    main()
