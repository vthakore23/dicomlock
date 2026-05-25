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


def _clean_ds():
    """Base dataset with incidental quirks normalized, so a probe's verdict reflects ONLY the
    injected attack. CT_small_pydicom.dcm has Study-after-Acquisition dates (a metadata warn) and
    a TIFF-magic preamble; clearing the dates keeps warn-level probes meaningful."""
    ds = pydicom.dcmread(BASE, force=True)
    for t in ("AcquisitionDate", "SeriesDate", "ContentDate"):
        if t in ds:
            del ds[t]
    return ds


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
    # installer / archive containers that a non-DICOM handler executes or expands (added after the
    # S9 falsification pass found these were missed — now block):
    "ole": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "cab": b"MSCF", "zstd": b"\x28\xb5\x2f\xfd",
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
        ds = _clean_ds()
        block = ds.private_block(0x0009, creator, create=True)
        block.add_new(0x01, "OB", payload)
        _save(ds, path)
    return fn


add("priv_elf.dcm", _priv_payload(b"\x7fELF" + b"\x00" * 4096), "private_payload", "block",
    "ELF header in private tag")
add("priv_mz.dcm", _priv_payload(b"MZ" + b"\x00" * 4096), "private_payload", "block",
    "MZ header in private tag")
# small (< 1 KiB) signatured payload — must still be caught regardless of size (S9 fix)
add("priv_small_elf.dcm", _priv_payload(b"\x7fELF" + b"\x00" * 196), "private_payload", "block",
    "200-byte ELF in a private tag (below the old 1 KiB size floor)")
# signature padded so it is not at offset 0 — windowed signature scan must still find it (S9 fix)
add("priv_padded_elf.dcm", _priv_payload(b"\x00" * 64 + b"\x7fELF" + b"\x00" * 4096),
    "private_payload", "block", "ELF padded to offset 64 inside the private value")

# --- CDR-escape regression probes: payload hidden UNDER an allowlisted vendor creator ---
# Before S9 these survived disarm (the exe-override only matched a listed signature at offset 0).
# Now: signatured (any), padded, and high-entropy payloads are stripped even under a known creator.
add("priv_under_ge_elf.dcm", _priv_payload(b"\x7fELF" + b"\x00" * 4096, creator="GEMS_IDEN_01"),
    "private_payload", "block", "ELF payload hidden under a known GE creator")
add("priv_under_ge_ole.dcm",
    _priv_payload(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 5000, creator="GEMS_IDEN_01"),
    "private_payload", "block", "OLE/MSI payload under a known GE creator (unlisted sig pre-S9)")
add("priv_under_ge_padded.dcm",
    _priv_payload(b"\x00" * 64 + b"\x7fELF" + b"\x00" * 5000, creator="GEMS_IDEN_01"),
    "private_payload", "block", "padded ELF under a known GE creator")
add("priv_under_ge_highentropy.dcm",
    _priv_payload(os.urandom(6000), creator="GEMS_IDEN_01"),
    "private_payload", "warn", "high-entropy opaque blob under a known GE creator")

# DOCUMENTED RESIDUAL: a low-entropy, signature-less blob is indistinguishable from legitimate
# vendor metadata (measured real vendor binary tags: median 4 B, max entropy 3.75). Under an
# allowlisted creator CDR preserves it by design; under an unknown creator CDR strips it. Either
# way the scanner does not flag it. Labeled clean so the corpus does not overclaim detection.
add("priv_lowentropy_residual.dcm", _priv_payload(b"A" * 6000),
    "benign_edge", "clean",
    "RESIDUAL: low-entropy signature-less private blob — not flagged (looks like vendor data); "
    "CDR strips it here only because the creator is unknown")


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


# ---------------------------------------------------------------------------
# 8. File Meta (group 0002) length bombs. The byte-walk used to validate only the main data set,
#    so a length bomb in the File Meta group (which every parser reads first) pushed the offset
#    past EOF and was never seen. Added after the S9 falsification pass found this gap.
# ---------------------------------------------------------------------------
def _filemeta_bomb(declared):
    def fn(path):
        raw = _base_bytes()
        el = struct.pack("<HH", 0x0002, 0x00FF) + b"OB" + b"\x00\x00" + struct.pack("<I", declared)
        open(path, "wb").write(bytes(raw[:132]) + el + bytes(raw[132:]))
    return fn


for _d in (0xFFFFFFF0, 0x10000000, 0x00100000):
    add(f"filemeta_bomb_{_d:08x}.dcm", _filemeta_bomb(_d), "length_bomb", "block",
        f"File Meta (group 0002) element declares {_d:,} value bytes")


# ---------------------------------------------------------------------------
# 9. Encapsulated decompression bombs around the amplification band. A tiny "compressed" payload
#    that claims a huge decoded image: >1000x -> block, 100-1000x -> warn (S9 added the warn tier),
#    <256 MiB declared -> only codec exposure (warn). Pixels are inert zeros, not real J2K.
# ---------------------------------------------------------------------------
def _encap_amp(rows, cols, frames, stored_kib, ts="1.2.840.10008.1.2.4.90"):
    def fn(path):
        ds = _clean_ds()
        ds.file_meta.TransferSyntaxUID = ts
        ds.Rows, ds.Columns = rows, cols
        ds.BitsAllocated = ds.BitsStored = 16
        ds.HighBit = 15
        ds.SamplesPerPixel = 1
        ds.NumberOfFrames = frames
        ds.PhotometricInterpretation = "MONOCHROME2"
        ds.PixelData = encapsulate([b"\x00" * (stored_kib * 1024)])
        ds["PixelData"].is_undefined_length = True
        _save(ds, path)
    return fn


# declared 288 MiB / 16 KiB stored ~= 18000x -> critical
add("encap_bomb_extreme.dcm", _encap_amp(12000, 12000, 1, 16), "decompression_bomb", "block",
    "J2K declares 288 MiB decoded from 16 KiB (~18000x)")
# declared 288 MiB / 512 KiB stored ~= 576x -> warn (the S9 moderate-amplification tier)
add("encap_bomb_moderate.dcm", _encap_amp(12000, 12000, 1, 512), "decompression_bomb", "warn",
    "J2K declares 288 MiB decoded from 512 KiB (~576x) — moderate-amplification warn band")
# declared ~128 MiB (< 256 MiB floor) -> not a bomb, only codec exposure (warn)
add("encap_amp_subfloor.dcm", _encap_amp(8000, 8000, 1, 256), "codec_exposure", "warn",
    "J2K 128 MiB declared (below the 256 MiB amplification floor) — codec exposure only")


# ---------------------------------------------------------------------------
# 10. Multiframe dimension bomb: a normal per-frame size but an enormous frame count, so the total
#     declared buffer is huge while a single frame stays under the frame cap.
# ---------------------------------------------------------------------------
def _multiframe_bomb(frames):
    def fn(path):
        ds = _clean_ds()
        ds.Rows = ds.Columns = 512
        ds.BitsAllocated = ds.BitsStored = 16
        ds.HighBit = 15
        ds.SamplesPerPixel = 1
        ds.NumberOfFrames = frames
        ds.PixelData = b"\x00" * 4096
        _save(ds, path)
    return fn


add("multiframe_bomb.dcm", _multiframe_bomb(100000), "dimension_bomb", "block",
    "512x512x16 with 100000 frames declared (~52 GiB), 4 KiB stored")


# ---------------------------------------------------------------------------
# 11. Combination / chained attacks: multiple simultaneous vectors. All must be detected, and CDR
#     must neutralize every one (rebuild the recoverable parts, quarantine the rest).
# ---------------------------------------------------------------------------
def _combo_poly_lenbomb(path):
    body = struct.pack("<HHI", 0x7FE0, 0x0010, 0xFFFFFFF0) + b"\x00" * 64
    open(path, "wb").write(b"\x7fELF" + b"\x00" * 124 + b"DICM" + body)


add("combo_poly_lenbomb.dcm", _combo_poly_lenbomb, "combination", "block",
    "ELF polyglot preamble AND a length bomb (quarantine expected)")


def _combo_poly_priv(path):
    ds = _clean_ds()
    ds.private_block(0x0009, "DICOMLOCK_TEST", create=True).add_new(0x01, "OB", b"MZ" + b"\x00" * 4096)
    ds.preamble = b"\x7fELF" + b"\x00" * 124
    _save(ds, path)


add("combo_poly_priv.dcm", _combo_poly_priv, "combination", "block",
    "ELF polyglot preamble AND an MZ private payload (rebuild expected)")


def _combo_nest_priv(path):
    ds = _clean_ds()
    node = Dataset()
    node.PatientComments = "x"
    for _ in range(12):
        parent = Dataset()
        parent.ReferencedImageSequence = Sequence([node])
        node = parent
    ds.ReferencedImageSequence = Sequence([node])
    ds.private_block(0x0009, "GEMS_IDEN_01", create=True).add_new(0x01, "OB", b"\x7fELF" + b"\x00" * 4096)
    _save(ds, path)


add("combo_nest_priv_ge.dcm", _combo_nest_priv, "combination", "block",
    "depth-12 nesting AND an ELF payload under an allowlisted GE creator (quarantine expected)")


# ---------------------------------------------------------------------------
# 12. Benign fidelity / allowlist-keep guards: valid files that must NOT be blocked and whose
#     legitimate vendor data must survive disarm (guards against over-stripping from the S9 change).
# ---------------------------------------------------------------------------
def _benign_allowlisted_priv(blob):
    def fn(path):
        ds = _clean_ds()
        ds.private_block(0x0009, "GEMS_IDEN_01", create=True).add_new(0x01, "OB", blob)
        _save(ds, path)
    return fn


add("benign_allowlisted_small.dcm", _benign_allowlisted_priv(b"\x01\x02\x03\x04" * 8),
    "benign_edge", "clean", "allowlisted GE creator, 32 B low-entropy binary — must be kept")
add("benign_allowlisted_large.dcm", _benign_allowlisted_priv(bytes(range(8)) * 384),
    "benign_edge", "clean",
    "allowlisted GE creator, 3 KB low-entropy structured binary (entropy 3.0) — must be kept")


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
