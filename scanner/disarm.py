"""
DicomLock — Content Disarm & Reconstruction (CDR) engine (Module 5).

Rebuilds a clean, clinically-equivalent DICOM from a parsed dataset:
  - zero the 128-byte preamble       -> neutralizes polyglots (CVE-2019-11687 / ELFDICOM)
  - transcode compressed pixel data  -> removes the codec attack surface. NO NEW LOSS: we decode
    the image once and store it uncompressed. For a LOSSLESS source the result is bit-exact vs the
    original acquisition; for a LOSSY source the pixels are preserved exactly as decoded (no new
    loss) but we do not claim bit-exact vs the acquisition. See DisarmResult.source_lossy.
  - strip private (odd-group) tags   -> removes payload-smuggling space + PHI risk

Design property: this neutralizes UNKNOWN attacks because it rebuilds from a validated
canonical form rather than detecting a specific exploit — the only defense that survives a
Mythos-class, infinite-bug adversary.

Files with no recoverable image (e.g. a 140-byte length bomb) are NOT disarmable — the
scanner rejects/quarantines those. CDR is for files that carry a real image to preserve.
"""

import json
import os
import tempfile
from dataclasses import dataclass, field
from typing import Optional

import numpy as np
import pydicom

from scanner.file_security import (
    _private_payload_threat,
    check_pixel_dimension_bomb,
    check_length_amplification,
)
from scanner._sandbox import safe_transcode_to_native, _unlink as _safe_unlink
from scanner._resources import data_file

# Native (non-encapsulated) transfer syntaxes — no third-party codec involved.
_NATIVE_TS = {
    "1.2.840.10008.1.2",     # Implicit VR LE
    "1.2.840.10008.1.2.1",   # Explicit VR LE
    "1.2.840.10008.1.2.2",   # Explicit VR BE
}

# Deflated Explicit VR LE: the whole data set is zlib-wrapped but the PIXELS are uncompressed,
# so transcoding off it is lossless.
_DEFLATE_TS = "1.2.840.10008.1.2.1.99"

# Encapsulated transfer syntaxes that are mathematically LOSSLESS — a transcode to native preserves
# the pixels bit-exact vs the original acquisition. Everything else encapsulated (JPEG baseline/
# extended lossy, JPEG2000 lossy .91/.93, JPEG-LS near-lossless .81, MPEG/H.264/HEVC video, HTJ2K
# .203) is LOSSY: we decode once and store the pixels exactly as decoded (no NEW loss), but we do
# NOT claim bit-exact vs the original acquisition (that loss already happened in the source).
_LOSSLESS_ENCAPSULATED = {
    "1.2.840.10008.1.2.5",      # RLE Lossless
    "1.2.840.10008.1.2.4.57",   # JPEG Lossless (P14)
    "1.2.840.10008.1.2.4.58",   # JPEG Lossless Hierarchical (P15) [retired]
    "1.2.840.10008.1.2.4.65",   # JPEG Lossless Hierarchical (P28) [retired]
    "1.2.840.10008.1.2.4.66",   # JPEG Lossless Hierarchical (P29) [retired]
    "1.2.840.10008.1.2.4.70",   # JPEG Lossless SV1 (P14)
    "1.2.840.10008.1.2.4.80",   # JPEG-LS Lossless
    "1.2.840.10008.1.2.4.90",   # JPEG 2000 Lossless
    "1.2.840.10008.1.2.4.92",   # JPEG 2000 P2 Multi-component Lossless
    "1.2.840.10008.1.2.4.201",  # HTJ2K Lossless
    "1.2.840.10008.1.2.4.202",  # HTJ2K Lossless RPCL
}


def _source_is_lossless(ts: str) -> bool:
    """True if a transcode off `ts` preserves the original acquisition bit-exact. Unknown/unlisted
    encapsulated syntaxes are treated as lossy (conservative: we only claim bit-exact when sure)."""
    return ts in _NATIVE_TS or ts == _DEFLATE_TS or ts in _LOSSLESS_ENCAPSULATED


@dataclass
class DisarmResult:
    out_path: Optional[str]
    changes: list = field(default_factory=list)
    transcoded: bool = False
    private_removed: int = 0
    # image_preserved = the disarmed native pixels equal the pixels as decoded from the source.
    # Interpret with source_lossy: if False, that means bit-exact vs the original acquisition; if
    # True, it means "preserved exactly as decoded" (no NEW loss) but the source was already lossy.
    image_preserved: Optional[bool] = None
    source_lossy: Optional[bool] = None  # None = native/no transcode; False = lossless; True = lossy
    error: Optional[str] = None


def _count_private(ds) -> int:
    return sum(1 for elem in ds if elem.tag.is_private)


_ALLOWLIST_PATH = data_file("vendor_private_tags.json")
_allowlist_cache = None


def _load_private_allowlist() -> set:
    global _allowlist_cache
    if _allowlist_cache is None:
        try:
            with open(_ALLOWLIST_PATH) as f:
                _allowlist_cache = set(json.load(f).get("safe_creators", []))
        except Exception:
            _allowlist_cache = set()
    return _allowlist_cache


def _private_creator_map(ds) -> dict:
    """group -> {creator_element_number: creator_string}."""
    m = {}
    for elem in ds:
        t = elem.tag
        if t.is_private and 0x0010 <= t.element <= 0x00FF:
            m.setdefault(t.group, {})[t.element] = str(elem.value)
    return m


def filter_private_tags(ds, allow_creators: set) -> list:
    """Default-deny private-tag filter: keep data elements whose private creator is
    allowlisted, strip everything else. Strip even an allowlisted tag if its value carries
    an executable signature. Drop orphaned creator elements. Returns the removed tags."""
    creators = _private_creator_map(ds)
    kept_blocks = set()  # (group, block_byte)
    removed = []

    # Pass 1 — private DATA elements
    for elem in list(ds):
        t = elem.tag
        if not t.is_private or t.element < 0x1000:
            continue
        block = t.element >> 8
        creator = creators.get(t.group, {}).get(block)
        keep = bool(creator) and creator in allow_creators
        # Never keep a smuggled payload, even under a recognized vendor creator: strip if the value
        # carries an executable/archive signature (at offset 0 or padded deeper) OR is opaque
        # high-entropy data. Real vendor metadata is small and low-entropy, so this preserves
        # legitimate tags while closing the "hide it under an allowlisted creator" escape.
        if keep and isinstance(elem.value, (bytes, bytearray)):
            severity, _ = _private_payload_threat(bytes(elem.value))
            if severity is not None:
                keep = False
        if keep:
            kept_blocks.add((t.group, block))
        else:
            removed.append(t)
            del ds[t]

    # Pass 2 — drop creator elements whose block retained nothing
    for elem in list(ds):
        t = elem.tag
        if t.is_private and 0x0010 <= t.element <= 0x00FF and (t.group, t.element) not in kept_blocks:
            removed.append(t)
            del ds[t]

    return removed


def disarm(filepath: str, out_path: Optional[str] = None,
           strip_private: bool = True, verify: bool = True) -> DisarmResult:
    try:
        ds = pydicom.dcmread(filepath, force=True)
    except Exception as e:
        return DisarmResult(None, error=f"unreadable: {e}")

    if "PixelData" not in ds:
        return DisarmResult(None, error="no image to preserve (reject/quarantine instead)")

    # Fail-safe: refuse allocation/decompression/length bombs BEFORE any pixel decode, so a
    # crafted file can't DoS the disarm step itself (these checks are header/byte-level only).
    blocking = [f for f in (check_pixel_dimension_bomb(ds) + check_length_amplification(filepath))
                if f.severity in ("fail", "critical")]
    if blocking:
        return DisarmResult(None, error="not disarmable (allocation/length bomb): "
                            + "; ".join(f.message for f in blocking))

    changes = []

    # Classify the source codec so fidelity is labeled honestly (see _source_is_lossless).
    # None = native (no transcode); False = lossless transcode (bit-exact); True = lossy source.
    ts = str(getattr(getattr(ds, "file_meta", None), "TransferSyntaxUID", "") or "")
    source_lossy = None if (not ts or ts in _NATIVE_TS) else (not _source_is_lossless(ts))

    # 1) Transcode compressed/encapsulated pixel data -> native, in a SANDBOXED subprocess.
    #    Decoding compressed pixels runs a third-party C/C++ codec (libjpeg/OpenJPEG/CharLS/...)
    #    on untrusted bytes — the deep RCE surface. We never run it in-process: a crash, OOM, or
    #    hang in the worker is contained and the file is quarantined. Allocation/length/
    #    decompression bombs were already rejected above, before any decode is attempted.
    transcoded = False
    if ts and ts not in _NATIVE_TS:
        fd, native_tmp = tempfile.mkstemp(suffix=".native.tmp.dcm")
        os.close(fd)
        ok, reason = safe_transcode_to_native(filepath, native_tmp)
        if not ok:
            _safe_unlink(native_tmp)
            return DisarmResult(None, error=f"not disarmable ({reason})", source_lossy=source_lossy)
        try:
            ds = pydicom.dcmread(native_tmp, force=True)  # native from here: no codec ever runs
        except Exception as e:
            _safe_unlink(native_tmp)
            return DisarmResult(None, error=f"sandboxed decode produced unreadable output: {e}",
                                source_lossy=source_lossy)
        _safe_unlink(native_tmp)
        transcoded = True
        if source_lossy:
            changes.append(f"transcoded {ts} -> Explicit VR LE in a sandboxed subprocess "
                           "(LOSSY source: pixels preserved exactly as decoded, no NEW loss, but "
                           "NOT bit-exact vs the original acquisition; codec attack surface removed)")
        else:
            changes.append(f"transcoded {ts} -> Explicit VR LE in a sandboxed subprocess "
                           "(lossless source: pixels bit-exact; codec attack surface removed)")

    # Decoded pixels for the equivalence check. ds is now native (either originally, or via the
    # sandboxed transcode above), so this read invokes no third-party codec.
    orig_px = None
    if verify:
        try:
            orig_px = ds.pixel_array.copy()
        except Exception as e:
            return DisarmResult(None, error=f"could not read native pixels: {e}")

    # 2) Filter private tags against the vendor allowlist (keep known-safe, strip the rest).
    n_priv = 0
    if strip_private:
        before = _count_private(ds)
        removed = filter_private_tags(ds, _load_private_allowlist())
        n_priv = len(removed)
        if removed:
            changes.append(f"stripped {n_priv} unknown/suspicious private tag(s); "
                           f"kept {_count_private(ds)} allowlisted vendor tag(s)")
        elif before:
            changes.append(f"kept all {before} private tag(s) (allowlisted vendor)")

    # 3) Zero the preamble (neutralize polyglots) and write the clean file.
    ds.preamble = b"\x00" * 128
    changes.append("zeroed 128-byte preamble")
    out_path = out_path or (os.path.splitext(filepath)[0] + ".disarmed.dcm")
    try:
        ds.save_as(out_path)
    except TypeError:
        ds.save_as(out_path, enforce_file_format=False)

    # Verify the image survived bit-exact.
    image_preserved = None
    if verify and orig_px is not None:
        try:
            re_px = pydicom.dcmread(out_path).pixel_array
            image_preserved = bool(np.array_equal(orig_px, re_px))
        except Exception:
            image_preserved = False

    return DisarmResult(out_path, changes, transcoded, n_priv, image_preserved, source_lossy)
