#!/usr/bin/env python3
"""
Phase 1 validation — proves the new security checks (a) DON'T false-positive on clean
files and (b) DO fire on the tampered corpus.

Run:  python3 _attack_test/validate_phase1.py   (after make_tampered_corpus.py)
"""

import glob
import os
import sys

import pydicom

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
sys.path.insert(0, PROJECT)

from scanner.file_security import (  # noqa: E402
    check_preamble, check_length_amplification,
    check_sequence_depth, check_pixel_dimension_bomb, check_private_tag_payloads,
)
from scanner.codec_cve import check_codec_cve_exposure  # noqa: E402

ORDER = {"pass": 0, "info": 1, "warn": 2, "fail": 3, "critical": 4, "none": 0, "err": 5}
ALARM = {"fail", "critical"}  # what counts as "this check fired"
WARN = {"warn"}


def worst(findings):
    if not findings:
        return "none"
    return max((f.severity for f in findings), key=lambda s: ORDER.get(s, 0))


def run(fp):
    res = {"preamble": worst(check_preamble(fp)),
           "length_amp": worst(check_length_amplification(fp))}
    try:
        ds = pydicom.dcmread(fp, force=True)
        res["seq_depth"] = worst(check_sequence_depth(ds))
        res["pixel_bomb"] = worst(check_pixel_dimension_bomb(ds))
        res["private"] = worst(check_private_tag_payloads(ds))
        res["codec"] = worst(check_codec_cve_exposure(ds))
    except Exception:
        res["seq_depth"] = res["pixel_bomb"] = res["private"] = res["codec"] = "err"
    return res


COLS = ["preamble", "length_amp", "seq_depth", "pixel_bomb", "private", "codec"]


def header():
    print(f"{'file':<26}" + "".join(f"{c:<12}" for c in COLS))
    print("-" * (26 + 12 * len(COLS)))


def row(fp):
    r = run(fp)
    line = f"{os.path.basename(fp):<26}"
    for c in COLS:
        v = r.get(c, "-")
        mark = "!" if v in ALARM else " "
        line += f"{v + mark:<12}"
    print(line)
    return r


def main():
    print("\n=== CLEAN SAMPLES — expect NO fail/critical (warn on codec/preamble is OK) ===")
    header()
    clean = sorted(glob.glob(os.path.join(PROJECT, "samples", "*.dcm")))
    false_positives = 0
    for fp in clean:
        r = row(fp)
        false_positives += sum(1 for c in COLS if r.get(c) in ALARM)

    print("\n=== TAMPERED CORPUS — expect the matching check to FIRE (!) ===")
    header()
    tampered = sorted(glob.glob(os.path.join(PROJECT, "samples", "tampered", "*.dcm")))
    # filename -> (check that should fire, severities that count as a catch)
    expected = {
        "polyglot_pe.dcm":          ("preamble", ALARM),
        "polyglot_elf.dcm":         ("preamble", ALARM),
        "polyglot_macho.dcm":       ("preamble", ALARM),
        "polyglot_zip.dcm":         ("preamble", ALARM),
        "polyglot_pdf.dcm":         ("preamble", ALARM),
        "polyglot_gzip.dcm":        ("preamble", ALARM),
        "polyglot_shell.dcm":       ("preamble", ALARM),
        "bad_magic.dcm":            ("preamble", ALARM),
        "high_entropy_preamble.dcm": ("preamble", WARN),
        "length_bomb.dcm":          ("length_amp", ALARM),
        "length_bomb_explicit.dcm": ("length_amp", ALARM),
        "pixel_dimension_bomb.dcm": ("pixel_bomb", ALARM),
        "pixel_decompress_bomb.dcm": ("pixel_bomb", ALARM),
        "private_payload.dcm":      ("private", ALARM),
        "deep_nesting.dcm":         ("seq_depth", ALARM),
        # codec-CVE exposure fixtures — expected signal is a WARN, not a fail/critical
        # (exposure is reported honestly as exposure, never as a proven exploit).
        "video_h264.dcm":           ("codec", WARN),
        "video_hevc.dcm":           ("codec", WARN),
        "htj2k.dcm":                ("codec", WARN),
        "jpip_reference.dcm":       ("codec", WARN),
        "deflated_zlib.dcm":        ("codec", WARN),
    }
    detected = 0
    missed = []
    for fp in tampered:
        r = row(fp)
        name = os.path.basename(fp)
        want = expected.get(name)
        if want and r.get(want[0]) in want[1]:
            detected += 1
        elif want:
            missed.append(name)

    print("\n" + "=" * 78)
    print(f"Clean files:    {len(clean)}   false positives (fail/critical): {false_positives}")
    print(f"Tampered files: {len(tampered)}   detected by expected check:    {detected}/{len(expected)}")
    if missed:
        print(f"MISSED: {missed}")
    print("=" * 78)


if __name__ == "__main__":
    main()
