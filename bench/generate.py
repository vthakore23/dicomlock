#!/usr/bin/env python3
"""Adversarial structural-mutation corpus generator.

Goal: FALSIFY the defense. Produce a large set of inert, labeled, malformed DICOM files designed to
slip past the scanner or defeat CDR, then let the benchmark engine find the failures. Everything is
inert (executable signatures are header bytes plus zero padding, exactly like make_tampered_corpus).

It writes files plus a manifest.json (name -> attack_class, expected_verdict, note) into the output
dir so the engine scores actual-vs-expected. Default output samples/generated/ (gitignored).

Run:  python -m bench.generate            # -> samples/generated/
      python -m bench                     # picks up samples/generated/ automatically
"""

import argparse
import json
import math
import os
import struct

import pydicom
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence
from pydicom.encaps import encapsulate

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
SAMPLES = os.path.join(PROJECT, "samples")
BASE = os.path.join(SAMPLES, "CT_small_pydicom.dcm")

# block = scanner should raise fail/critical; warn = exposure/suspicion; clean = benign.
ITEMS = []  # (name, writer_fn, attack_class, expected_verdict, note)


def _save(ds, path):
    try:
        ds.save_as(path)
    except TypeError:
        ds.save_as(path, enforce_file_format=False)


def _base_bytes():
    return bytearray(open(BASE, "rb").read())


def _entropy_block(n_distinct, length=128):
    """length bytes drawn from exactly n_distinct values -> Shannon entropy = log2(n_distinct)."""
    vals = [(i * 167 + 13) % 256 for i in range(n_distinct)]
    return bytes(vals[i % n_distinct] for i in range(length))


def add(name, fn, cls, verdict, note=""):
    ITEMS.append((name, fn, cls, verdict, note))


# ---------------------------------------------------------------------------
# 1. Polyglots: known signatures, real-but-maybe-unlisted formats, shifted offset.
#    CDR zeroes the preamble regardless of signature, so neutralization should always hold;
#    the interesting failure is a scanner MISS on an unlisted/shifted signature.
# ---------------------------------------------------------------------------
_SIGS = {
    "pe": b"MZ", "elf": b"\x7fELF", "macho": b"\xca\xfe\xba\xbe", "zip": b"PK\x03\x04",
    "pdf": b"%PDF", "gzip": b"\x1f\x8b", "shell": b"#!/bin/sh\n",
    # real formats that may NOT be in the check's signature list (evasion probes):
    "wasm": b"\x00asm", "dex": b"dex\n035\x00", "class": b"\xca\xfe\xba\xbe",
    "rar": b"Rar!\x1a\x07", "sevenz": b"7z\xbc\xaf\x27\x1c", "lua": b"\x1bLua",
}


def _polyglot(sig, offset=0):
    def fn(path):
        raw = _base_bytes()
        raw[offset:offset + len(sig)] = sig
        open(path, "wb").write(raw)
    return fn


for _k, _s in _SIGS.items():
    add(f"poly_{_k}.dcm", _polyglot(_s), "polyglot", "block", f"{_k} signature at offset 0")
# offset-shifted: ELF magic away from offset 0 is not a loadable executable, so warn is acceptable.
for _off in (1, 2, 4):
    add(f"poly_elf_off{_off}.dcm", _polyglot(b"\x7fELF", _off), "polyglot", "warn",
        f"ELF signature shifted to offset {_off} (not a valid executable)")


# ---------------------------------------------------------------------------
# 2. Preamble entropy sweep: find the threshold; sub-threshold high entropy = evasion.
# ---------------------------------------------------------------------------
def _entropy_preamble(n_distinct):
    def fn(path):
        raw = _base_bytes()
        raw[0:128] = _entropy_block(n_distinct)
        open(path, "wb").write(raw)
    return fn


for _nd in (2, 4, 8, 16, 32, 48, 64, 80, 96, 112, 120, 128):
    _ent = round(math.log2(_nd), 2)
    # label: a non-zero non-standard preamble carrying real entropy is at least suspicious.
    _verdict = "warn" if _ent >= 6.0 else "clean"
    add(f"entropy_nd{_nd:03d}_e{_ent}.dcm", _entropy_preamble(_nd), "preamble_anomaly",
        _verdict, f"preamble of {_nd} distinct bytes, entropy {_ent}")


# ---------------------------------------------------------------------------
# 3. Length amplification: declared length around the remaining-bytes boundary.
# ---------------------------------------------------------------------------
def _length_amp(declared):
    def fn(path):
        # implicit-VR element (7FE0,0010) declaring `declared` bytes, with a small real value.
        body = struct.pack("<HHI", 0x7FE0, 0x0010, declared) + b"\x00" * 64
        open(path, "wb").write(b"\x00" * 128 + b"DICM" + body)
    return fn


# Bare pixel-data element, no Rows/Columns -> malformed regardless of declared length; over the
# boundary it is also a length bomb. All should be blocked. (A clean length-amp boundary probe would
# need a complete dataset; length-amp is already validated at 0 FP across 590 real/benign files.)
for _d in (60, 63, 64, 65, 66, 80, 4096, 0xFFFFFFF0):
    add(f"lenamp_{_d}.dcm", _length_amp(_d), "length_bomb", "block", f"declares {_d} bytes, 64 remain")


# ---------------------------------------------------------------------------
# 4. Sequence nesting depth sweep around the limit.
# ---------------------------------------------------------------------------
def _nesting(levels):
    def fn(path):
        ds = pydicom.dcmread(BASE, force=True)
        node = Dataset()
        node.PatientComments = "x"
        for _ in range(levels):
            parent = Dataset()
            parent.ReferencedImageSequence = Sequence([node])
            node = parent
        ds.ReferencedImageSequence = Sequence([node])
        _save(ds, path)
    return fn


for _lv in (3, 8, 9, 10, 11, 12, 20, 50):
    _v = "block" if _lv >= 10 else "clean"  # check blocks at depth 10
    add(f"nest_{_lv:02d}.dcm", _nesting(_lv), "nesting_bomb", _v, f"sequence nesting depth {_lv}")


# ---------------------------------------------------------------------------
# 5. Private-tag payloads: signature variants, low-entropy, hidden under a known vendor creator.
# ---------------------------------------------------------------------------
def _priv_payload(payload, creator="DICOMLOCK_TEST"):
    def fn(path):
        ds = pydicom.dcmread(BASE, force=True)
        block = ds.private_block(0x0009, creator, create=True)
        block.add_new(0x01, "OB", payload)
        _save(ds, path)
    return fn


add("priv_elf.dcm", _priv_payload(b"\x7fELF" + b"\x00" * 4096), "private_payload", "block",
    "ELF header in private tag")
add("priv_mz.dcm", _priv_payload(b"MZ" + b"\x00" * 4096), "private_payload", "block",
    "MZ header in private tag")
# low-entropy non-signature blob: may slip an entropy/exe heuristic (evasion probe)
add("priv_lowentropy.dcm", _priv_payload(b"A" * 6000), "private_payload", "warn",
    "large low-entropy private blob (no signature)")
# payload hidden UNDER a recognized vendor creator (the allowlist exe-override path)
add("priv_under_ge.dcm", _priv_payload(b"\x7fELF" + b"\x00" * 4096, creator="GEMS_IDEN_01"),
    "private_payload", "block", "ELF payload hidden under a known GE creator")


# ---------------------------------------------------------------------------
# 6. Pixel-dimension / decompression bombs around the threshold + packing edges.
# ---------------------------------------------------------------------------
def _dim_bomb(rows, cols, bits=16, frames=1, samples=1):
    def fn(path):
        ds = pydicom.dcmread(BASE, force=True)
        ds.Rows, ds.Columns = rows, cols
        ds.BitsAllocated, ds.BitsStored, ds.HighBit = bits, bits, bits - 1
        ds.SamplesPerPixel = samples
        ds.NumberOfFrames = frames
        ds.PixelData = b"\x00" * 256
        _save(ds, path)
    return fn


for _r in (512, 4096, 16000, 60000):
    # 256B of data for an RxR 16-bit image is always a dimension mismatch / bomb -> block.
    add(f"dim_{_r}.dcm", _dim_bomb(_r, _r), "dimension_bomb", "block", f"{_r}x{_r} declared, 256B data")


def _valid_1bit(path):
    # A genuinely valid 1-bit packed image: 512x512 / 8 = 32768 bytes, exactly one frame.
    # Regression guard for the S8 1-bit-packing FP fix; must NOT be flagged.
    ds = pydicom.dcmread(BASE, force=True)
    ds.Rows, ds.Columns = 512, 512
    ds.BitsAllocated, ds.BitsStored, ds.HighBit = 1, 1, 0
    ds.SamplesPerPixel = 1
    ds.PixelRepresentation = 0
    ds.PhotometricInterpretation = "MONOCHROME2"
    if "NumberOfFrames" in ds:
        del ds.NumberOfFrames
    ds.PixelData = b"\x00" * (512 * 512 // 8)
    _save(ds, path)


add("dim_1bit.dcm", _valid_1bit, "benign_edge", "clean",
    "valid 1-bit packed image (32768B) — regression guard for the S8 1-bit FP fix")


# ---------------------------------------------------------------------------
# 7. Benign-but-unusual VALID files: stress CDR fidelity (must stay bit-exact / not corrupt).
# ---------------------------------------------------------------------------
def _benign_variant(mutate):
    def fn(path):
        ds = pydicom.dcmread(BASE, force=True)
        mutate(ds)
        _save(ds, path)
    return fn


def _multiframe(ds):
    import numpy as np
    arr = ds.pixel_array
    ds.NumberOfFrames = 3
    ds.PixelData = np.stack([arr, arr, arr]).tobytes()


add("benign_multiframe.dcm", _benign_variant(_multiframe), "benign_edge", "clean",
    "valid 3-frame file (fidelity stress)")
add("benign_extra_private.dcm",
    _benign_variant(lambda ds: ds.private_block(0x0011, "ACME_VENDOR", create=True).add_new(
        0x01, "LO", "vendor metadata")),
    "benign_edge", "clean", "valid file with an unknown-vendor private string tag")


def main():
    ap = argparse.ArgumentParser(prog="bench.generate")
    ap.add_argument("--out", default=os.path.join(SAMPLES, "generated"))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    manifest = []
    ok = 0
    for name, fn, cls, verdict, note in ITEMS:
        path = os.path.join(args.out, name)
        try:
            fn(path)
        except Exception as e:
            print(f"  (skipped {name}: {e})")
            continue
        manifest.append({"name": name, "attack_class": cls,
                         "expected_verdict": verdict, "note": note})
        ok += 1

    with open(os.path.join(args.out, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"Wrote {ok} inert generated files + manifest.json to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
