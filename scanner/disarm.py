"""
DicomLock — Content Disarm & Reconstruction (CDR) engine (Module 5).

Rebuilds a clean, clinically-equivalent DICOM from a parsed dataset:
  - zero the 128-byte preamble       -> neutralizes polyglots (CVE-2019-11687 / ELFDICOM)
  - transcode compressed pixel data  -> removes the codec attack surface. NO NEW LOSS: we
    decode the image once and store it uncompressed; the pixels are preserved exactly.
  - strip private (odd-group) tags   -> removes payload-smuggling space + PHI risk

Design property: this neutralizes UNKNOWN attacks because it rebuilds from a validated
canonical form rather than detecting a specific exploit — the only defense that survives a
Mythos-class, infinite-bug adversary.

Files with no recoverable image (e.g. a 140-byte length bomb) are NOT disarmable — the
scanner rejects/quarantines those. CDR is for files that carry a real image to preserve.
"""

import json
import os
from dataclasses import dataclass, field
from typing import Optional

import numpy as np
import pydicom
from pydicom.uid import ExplicitVRLittleEndian

from scanner.file_security import (
    _match_signature,
    check_pixel_dimension_bomb,
    check_length_amplification,
)
from scanner._resources import data_file

# Native (non-encapsulated) transfer syntaxes — no third-party codec involved.
_NATIVE_TS = {
    "1.2.840.10008.1.2",     # Implicit VR LE
    "1.2.840.10008.1.2.1",   # Explicit VR LE
    "1.2.840.10008.1.2.2",   # Explicit VR BE
}


@dataclass
class DisarmResult:
    out_path: Optional[str]
    changes: list = field(default_factory=list)
    transcoded: bool = False
    private_removed: int = 0
    image_preserved: Optional[bool] = None  # True/False (bit-exact) or None if not verified
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
        # never keep an executable payload, even under a recognized vendor creator
        if keep and isinstance(elem.value, (bytes, bytearray)) and _match_signature(bytes(elem.value[:8])):
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

    # Decoded pixels BEFORE any change — the ground truth for the equivalence check.
    orig_px = None
    if verify:
        try:
            orig_px = ds.pixel_array.copy()
        except Exception as e:
            return DisarmResult(None, error=f"could not decode pixels: {e}")

    changes = []

    # 1) Transcode compressed/encapsulated pixel data -> native uncompressed.
    transcoded = False
    ts = str(getattr(getattr(ds, "file_meta", None), "TransferSyntaxUID", "") or "")
    if ts and ts not in _NATIVE_TS:
        try:
            ds.decompress()  # decodes pixels, sets TransferSyntaxUID = Explicit VR LE
        except Exception:
            arr = ds.pixel_array
            ds.PixelData = arr.tobytes()
            ds.file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
            ds["PixelData"].VR = "OW" if int(getattr(ds, "BitsAllocated", 16)) > 8 else "OB"
        transcoded = True
        changes.append(f"transcoded {ts} -> Explicit VR LE (codec attack surface removed)")

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

    return DisarmResult(out_path, changes, transcoded, n_priv, image_preserved)
