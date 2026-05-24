#!/usr/bin/env python3
"""
Generate the samples/tampered/ regression corpus — INERT attack files for testing
DicomLock's security checks. No working malware: polyglots carry only magic bytes,
the payload tag carries an ELF header + zero padding.

Run:  python3 make_tampered_corpus.py
"""

import os
import struct

import pydicom
from pydicom.dataset import Dataset
from pydicom.sequence import Sequence
from pydicom.encaps import encapsulate
from pydicom.uid import DeflatedExplicitVRLittleEndian

HERE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(HERE, "samples")
OUT = os.path.join(SAMPLES, "tampered")
BASE = os.path.join(SAMPLES, "CT_small_pydicom.dcm")


def _save(ds, path):
    try:
        ds.save_as(path)
    except TypeError:
        ds.save_as(path, enforce_file_format=False)


def polyglot(sig: bytes, name: str) -> str:
    raw = bytearray(open(BASE, "rb").read())
    raw[0: len(sig)] = sig  # inject magic into the 128-byte preamble (inert)
    path = os.path.join(OUT, name)
    with open(path, "wb") as f:
        f.write(raw)
    return path


def high_entropy_preamble() -> str:
    # Non-standard preamble with no known magic but high entropy (obfuscated payload, no
    # signature to match). Deterministic full-period sequence -> 128 distinct bytes, entropy 7.0.
    raw = bytearray(open(BASE, "rb").read())
    raw[0:128] = bytes((i * 167 + 13) % 256 for i in range(128))
    path = os.path.join(OUT, "high_entropy_preamble.dcm")
    with open(path, "wb") as f:
        f.write(raw)
    return path


def bad_magic() -> str:
    # DICM magic corrupted — permissive parsers (force=True) skip it and parse anyway.
    raw = bytearray(open(BASE, "rb").read())
    raw[128:132] = b"XXXX"
    path = os.path.join(OUT, "bad_magic.dcm")
    with open(path, "wb") as f:
        f.write(raw)
    return path


def length_bomb() -> str:
    # 128 zero preamble + DICM + one Implicit-VR element (7FE0,0010) declaring ~4 GB, no value.
    blob = b"\x00" * 128 + b"DICM" + struct.pack("<HHI", 0x7FE0, 0x0010, 0xFFFFFFF0)
    path = os.path.join(OUT, "length_bomb.dcm")
    with open(path, "wb") as f:
        f.write(blob)
    return path


def length_bomb_explicit() -> str:
    # Same DoS via the EXPLICIT-VR path with a real File Meta group present (exercises the
    # File Meta walk + the long-VR 4-byte length branch, not just the implicit default).
    ts = b"1.2.840.10008.1.2.1\x00"  # Explicit VR LE, padded to even length
    meta = struct.pack("<HH", 0x0002, 0x0010) + b"UI" + struct.pack("<H", len(ts)) + ts
    # (7FE0,0010) OB, 2 reserved bytes, 4-byte length declaring ~4 GB
    bomb = struct.pack("<HH", 0x7FE0, 0x0010) + b"OB" + b"\x00\x00" + struct.pack("<I", 0xFFFFFFF0)
    blob = b"\x00" * 128 + b"DICM" + meta + bomb
    path = os.path.join(OUT, "length_bomb_explicit.dcm")
    with open(path, "wb") as f:
        f.write(blob)
    return path


def pixel_dimension_bomb() -> str:
    # Native pixel data but absurd Rows/Columns -> ~7 GiB header-driven allocation, tiny payload.
    ds = pydicom.dcmread(BASE, force=True)
    ds.Rows = 60000
    ds.Columns = 60000
    ds.BitsAllocated = 16
    ds.BitsStored = 16
    ds.HighBit = 15
    ds.SamplesPerPixel = 1
    ds.PixelData = b"\x00" * 256  # actual data tiny; the header lies about the size
    path = os.path.join(OUT, "pixel_dimension_bomb.dcm")
    _save(ds, path)
    return path


def pixel_decompress_bomb() -> str:
    # Encapsulated (JPEG2000) with a huge NumberOfFrames but a single tiny fragment ->
    # declares ~98 GiB decoded from a few dozen stored bytes (decompression bomb).
    ds = pydicom.dcmread(BASE, force=True)
    ds.file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.4.90"
    ds.Rows = 512
    ds.Columns = 512
    ds.BitsAllocated = 16
    ds.BitsStored = 16
    ds.HighBit = 15
    ds.SamplesPerPixel = 1
    ds.NumberOfFrames = 200000
    ds.PixelData = encapsulate([b"\x00" * 64])
    ds["PixelData"].VR = "OB"
    try:
        ds.is_implicit_VR = False
        ds.is_little_endian = True
    except Exception:
        pass
    path = os.path.join(OUT, "pixel_decompress_bomb.dcm")
    _save(ds, path)
    return path


def private_payload() -> str:
    ds = pydicom.dcmread(BASE, force=True)
    block = ds.private_block(0x0009, "DICOMLOCK_TEST", create=True)
    block.add_new(0x01, "OB", b"\x7fELF" + b"\x00" * 2048)  # ELF header + padding (inert)
    path = os.path.join(OUT, "private_payload.dcm")
    _save(ds, path)
    return path


def deep_nesting(levels: int = 15) -> str:
    ds = pydicom.dcmread(BASE, force=True)
    node = Dataset()
    node.PatientComments = "deepest"
    for _ in range(levels):
        parent = Dataset()
        parent.ReferencedImageSequence = Sequence([node])
        node = parent
    ds.ReferencedImageSequence = Sequence([node])
    path = os.path.join(OUT, "deep_nesting.dcm")
    _save(ds, path)
    return path


def codec_exposure(ts_uid: str, name: str) -> str:
    """A small, well-formed file whose TransferSyntaxUID routes pixel data through a
    third-party decoder (FFmpeg-class / OpenJPH / OpenJPEG). Exercises check_codec_cve_exposure.
    Header dimensions are deliberately tiny so no allocation/decompression-bomb check fires —
    the ONLY signal should be the codec-exposure WARN."""
    ds = pydicom.dcmread(BASE, force=True)
    ds.file_meta.TransferSyntaxUID = ts_uid
    ds.Rows = 64
    ds.Columns = 64
    ds.BitsAllocated = 16
    ds.BitsStored = 16
    ds.HighBit = 15
    ds.SamplesPerPixel = 1
    ds.NumberOfFrames = 1
    ds.PixelData = encapsulate([b"\x00" * 64])  # tiny encapsulated fragment (inert)
    ds["PixelData"].VR = "OB"
    try:
        ds.is_implicit_VR = False
        ds.is_little_endian = True
    except Exception:
        pass
    path = os.path.join(OUT, name)
    _save(ds, path)
    return path


def jpip_reference() -> str:
    """JPIP transfer syntax: pixel data is fetched from a REMOTE URL, not stored in the file.
    A crafted URL steers a PACS/viewer at an attacker/internal endpoint (SSRF-class) before any
    codec runs. The PixelDataProviderURL here points at the canonical cloud-metadata SSRF target
    (inert in a test fixture). Exercises the JPIP branch of check_codec_cve_exposure."""
    ds = pydicom.dcmread(BASE, force=True)
    ds.file_meta.TransferSyntaxUID = "1.2.840.10008.1.2.4.94"  # JPIP Referenced
    ds.Rows = 64
    ds.Columns = 64
    if "PixelData" in ds:
        del ds.PixelData
    ds.add_new(0x00287FE0, "UR", "http://169.254.169.254/latest/meta-data/")  # SSRF demo target
    try:
        ds.is_implicit_VR = False
        ds.is_little_endian = True
    except Exception:
        pass
    path = os.path.join(OUT, "jpip_reference.dcm")
    _save(ds, path)
    return path


def deflated_zlib() -> str:
    """Deflated Explicit VR LE: the whole dataset is zlib-inflated by the parser before any other
    processing — routing attacker-controlled bytes through zlib (CVE-2022-37434 class). Returns
    None if the local pydicom can't emit a valid deflated file (so the corpus stays well-formed)."""
    ds = pydicom.dcmread(BASE, force=True)
    ds.file_meta.TransferSyntaxUID = DeflatedExplicitVRLittleEndian
    try:
        ds.is_implicit_VR = False
        ds.is_little_endian = True
    except Exception:
        pass
    path = os.path.join(OUT, "deflated_zlib.dcm")
    try:
        _save(ds, path)
        pydicom.dcmread(path, force=True)  # round-trip check: must be a valid deflated file
    except Exception as e:
        print(f"  (skipped deflated_zlib.dcm — pydicom can't emit valid deflate here: {e})")
        return None
    return path


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    made = [
        # polyglots — exercise every executable/archive signature the preamble check claims
        polyglot(b"MZ", "polyglot_pe.dcm"),
        polyglot(b"\x7fELF", "polyglot_elf.dcm"),
        polyglot(b"\xca\xfe\xba\xbe", "polyglot_macho.dcm"),
        polyglot(b"PK\x03\x04", "polyglot_zip.dcm"),
        polyglot(b"%PDF", "polyglot_pdf.dcm"),
        polyglot(b"\x1f\x8b", "polyglot_gzip.dcm"),
        polyglot(b"#!", "polyglot_shell.dcm"),
        high_entropy_preamble(),
        bad_magic(),
        # parser-DoS — length amplification (implicit + explicit paths)
        length_bomb(),
        length_bomb_explicit(),
        # allocation / decompression bombs (the new pixel_dimension_bomb check)
        pixel_dimension_bomb(),
        pixel_decompress_bomb(),
        # payloads & nesting
        private_payload(),
        deep_nesting(),
        # codec-CVE exposure — route pixel data through each untrusted decoder family
        codec_exposure("1.2.840.10008.1.2.4.102", "video_h264.dcm"),    # FFmpeg-class (H.264)
        codec_exposure("1.2.840.10008.1.2.4.107", "video_hevc.dcm"),    # FFmpeg-class (HEVC)
        codec_exposure("1.2.840.10008.1.2.4.201", "htj2k.dcm"),         # OpenJPH (HTJ2K)
        jpip_reference(),                                               # JPIP SSRF-class fetch
        deflated_zlib(),                                                # zlib inflate path
    ]
    made = [m for m in made if m]  # drop any fixture the local env couldn't emit (e.g. deflate)
    print(f"Wrote {len(made)} inert tampered files to {OUT}:")
    for m in made:
        print("  -", os.path.basename(m))
