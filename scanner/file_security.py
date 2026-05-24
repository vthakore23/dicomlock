"""
DicomLock — File Security Module

File-level security checks for DICOM (the attack surface is the file itself):
  - check_preamble             : polyglot signatures + preamble entropy
  - check_length_amplification : declared element length vs remaining bytes (parser DoS)
  - check_sequence_depth       : nested-sequence bombs
  - check_private_tag_payloads : executables / opaque blobs smuggled in private tags

See ../ARCHITECTURE.md (Module 1) and ../../CLAUDE.md (DICOM file-structure reference).
"""

import math
import struct
from collections import Counter

from scanner.findings import Finding


# Executable / archive magic signatures (used for preamble + private-tag carving)
_EXE_SIGS = {
    b"MZ": "Windows PE executable",
    b"\x7fELF": "Linux ELF executable",
    b"\xca\xfe\xba\xbe": "macOS Mach-O binary",
    b"PK\x03\x04": "ZIP/JAR archive",
    b"\x1f\x8b": "Gzip data",
    b"%PDF": "PDF document",
    b"#!": "shell script",
}

# Explicit-VR value representations that use 2 reserved bytes + a 4-byte length.
# Everything else uses a 2-byte length. (DICOM PS3.5)
_LONG_VR = {b"OB", b"OW", b"OF", b"OD", b"OL", b"OV", b"SQ", b"UC", b"UR", b"UT", b"UN"}
_UNDEFINED_LENGTH = 0xFFFFFFFF
_DEFLATED_TS = "1.2.840.10008.1.2.1.99"  # Deflated Explicit VR LE: dataset body is zlib-compressed


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def _match_signature(head: bytes):
    for sig, name in _EXE_SIGS.items():
        if head[: len(sig)] == sig:
            return name
    return None


def check_preamble(filepath: str) -> list[Finding]:
    """128-byte preamble: polyglot signatures + entropy heuristic."""
    findings = []
    with open(filepath, "rb") as f:
        preamble = f.read(128)
        magic = f.read(4)

    if magic != b"DICM":
        findings.append(Finding(
            "file_preamble", "critical",
            "Missing DICM magic bytes — file may not be valid DICOM",
            f"Found bytes: {magic!r}"))
        return findings

    if preamble == b"\x00" * 128:
        findings.append(Finding("file_preamble", "pass", "Standard zero-filled preamble"))
        return findings

    detected = _match_signature(preamble)
    if detected:
        findings.append(Finding(
            "file_preamble", "critical",
            f"POLYGLOT FILE DETECTED — preamble contains {detected} signature",
            "This file is simultaneously a valid DICOM file AND a valid "
            f"{detected} (CVE-2019-11687 / ELFDICOM). It can execute if opened by a non-DICOM "
            "handler. CDR neutralizes this by zeroing the preamble."))
    else:
        nonzero = sum(1 for b in preamble if b != 0)
        ent = _shannon_entropy(preamble)
        sev = "warn" if ent > 4.0 else "info"
        findings.append(Finding(
            "file_preamble", sev,
            f"Non-standard preamble — {nonzero}/128 bytes non-zero, entropy {ent:.1f}/8",
            "A standard preamble is all zeros. High-entropy content can hide an obfuscated "
            "payload even without a known signature. CDR zeroes the preamble regardless."))
    return findings


def _locate_dataset(data: bytes):
    """Return (main_dataset_offset, is_implicit_vr, is_little_endian).

    File Meta (group 0002) is always Explicit VR Little Endian. We walk it to find both
    the transfer syntax and where the main data set begins. If there is no File Meta,
    pydicom's force-read defaults to Implicit VR LE starting right after 'DICM'.
    """
    n = len(data)
    if data[132:134] == b"\x02\x00":  # File Meta group present
        off = 132
        ts = None
        while off + 8 <= n:
            grp = struct.unpack_from("<H", data, off)[0]
            if grp != 0x0002:
                break
            el = struct.unpack_from("<H", data, off + 2)[0]
            vr = data[off + 4: off + 6]
            if vr in _LONG_VR:
                length = struct.unpack_from("<I", data, off + 8)[0]
                voff = off + 12
            else:
                length = struct.unpack_from("<H", data, off + 6)[0]
                voff = off + 8
            if (grp, el) == (0x0002, 0x0010):
                ts = data[voff: voff + length].rstrip(b"\x00 ").decode("ascii", "ignore")
            off = voff + (0 if length == _UNDEFINED_LENGTH else length)
        is_implicit = (ts == "1.2.840.10008.1.2")
        is_le = (ts != "1.2.840.10008.1.2.2")
        is_deflated = (ts == _DEFLATED_TS)
        return off, is_implicit, is_le, is_deflated
    return 132, True, True, False


def check_length_amplification(filepath: str) -> list[Finding]:
    """Flag any element that declares more bytes than remain in the file (parser DoS)."""
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except OSError as e:
        return [Finding("length_amplification", "info", f"Could not read file: {e}")]

    n = len(data)
    if n < 132 or data[128:132] != b"DICM":
        return []  # not a Part-10 file; check_preamble handles this

    try:
        off, is_implicit, is_le, is_deflated = _locate_dataset(data)
    except Exception:
        return [Finding("length_amplification", "info",
                        "Structural scan skipped (could not resolve transfer syntax)")]

    if is_deflated:
        # Deflated Explicit VR LE: the data set after File Meta is zlib-compressed, so its raw
        # bytes are NOT element headers — walking them would desync into a bogus "length bomb".
        # We can't validate element lengths without inflating (the zlib codec path we distrust;
        # see codec_cve). The decoded-size guard (check_pixel_dimension_bomb) still applies once
        # pydicom inflates and parses.
        return [Finding(
            "length_amplification", "info",
            "Dataset body is zlib-deflated — byte-level length check not applicable",
            "Deflated Explicit VR LE compresses the whole data set; element lengths can only be "
            "checked after inflating through zlib (flagged separately as codec exposure). "
            "Disarm transcodes the file off the deflate path.")]

    endian = "<" if is_le else ">"
    count = 0
    while off + 8 <= n and count < 50000:
        count += 1
        try:
            if is_implicit:
                length = struct.unpack_from(endian + "I", data, off + 4)[0]
                voff = off + 8
            else:
                vr = data[off + 4: off + 6]
                if vr in _LONG_VR:
                    length = struct.unpack_from(endian + "I", data, off + 8)[0]
                    voff = off + 12
                else:
                    length = struct.unpack_from(endian + "H", data, off + 6)[0]
                    voff = off + 8
        except struct.error:
            break

        if length == _UNDEFINED_LENGTH:
            break  # sequence / encapsulated pixel data — stop to avoid desync false positives

        remaining = n - voff
        if length > remaining:
            ratio = length / max(n, 1)
            return [Finding(
                "length_amplification", "critical",
                f"Element at byte {off} declares {length:,} bytes but only {remaining:,} remain",
                f"Declared length is {ratio:,.0f}x the file size — a naive parser allocating this "
                "would exhaust memory and crash (GDCM CVE class). DicomLock rejects it before any "
                "allocation occurs.")]
        off = voff + length

    return [Finding("length_amplification", "pass", "All element lengths within file bounds")]


def check_sequence_depth(ds, limit: int = 10) -> list[Finding]:
    """Flag sequence nesting deep enough to exhaust a parser's memory or stack."""
    def depth(d, cur=0, cap=256):
        if cur > cap:
            return cur
        m = cur
        try:
            for elem in d:
                if elem.VR == "SQ" and elem.value is not None:
                    for item in elem.value:
                        m = max(m, depth(item, cur + 1, cap))
        except Exception:
            pass
        return m

    d = depth(ds)
    if d > limit:
        return [Finding(
            "sequence_depth", "fail",
            f"Sequence nesting depth {d} exceeds the safe limit ({limit})",
            "Deeply nested sequences can exhaust memory or overflow the parser stack. "
            "Legitimate files rarely exceed 3–5 levels.")]
    return [Finding("sequence_depth", "pass", f"Sequence nesting depth {d} within limits")]


def check_pixel_dimension_bomb(ds) -> list[Finding]:
    """Flag images whose declared decoded buffer is absurdly large (allocation DoS).

    A parser/viewer typically allocates Rows×Columns×SamplesPerPixel×NumberOfFrames×
    bytes-per-pixel from the *header* before (or while) decoding. A crafted file can declare
    enormous dimensions — or, for encapsulated pixel data, a tiny compressed payload that claims
    to decode to gigabytes (a decompression bomb). check_length_amplification deliberately stops
    at the undefined length of encapsulated pixel data, so this is the check that covers that gap.

    Header-only: it never decodes pixels (decoding is exactly the codec path we distrust). All
    thresholds sit ~300-1000x above the largest real clinical image measured (3.1 MiB / 575 CTs).
    """
    FRAME_CAP = 1024 ** 3            # 1 GiB: implausible for a single real image frame
    AMP_FLOOR = 256 * 1024 ** 2      # 256 MiB: ignore amplification below this declared size
    AMP_RATIO = 1000                 # declared:stored ratio no real codec reaches

    def _int(v, default=0):
        try:
            return int(v)
        except (TypeError, ValueError):
            return default

    rows = _int(getattr(ds, "Rows", 0))
    cols = _int(getattr(ds, "Columns", 0))
    if rows <= 0 or cols <= 0:
        return [Finding("pixel_dimension_bomb", "pass", "No image dimensions to evaluate")]

    samples = max(1, _int(getattr(ds, "SamplesPerPixel", 1), 1))
    frames = max(1, _int(getattr(ds, "NumberOfFrames", 1), 1))
    bits = max(1, _int(getattr(ds, "BitsAllocated", 8), 8))
    bytes_per = (bits + 7) // 8
    frame_bytes = rows * cols * samples * bytes_per
    declared = frame_bytes * frames

    # T1 — a single frame's buffer is already implausibly large (crafted dimensions).
    if frame_bytes > FRAME_CAP:
        return [Finding(
            "pixel_dimension_bomb", "critical",
            f"Declared frame buffer is {frame_bytes / 1024**3:.1f} GiB "
            f"({rows}x{cols}, {samples} ch, {bits}-bit)",
            "These header dimensions force a multi-gigabyte allocation before the image is even "
            "decoded — a denial-of-service against any viewer/PACS that sizes its buffer from the "
            "header. No real clinical frame approaches this. CDR quarantines it.")]

    # T2 — encapsulated/tiny payload claims to decode to a huge buffer (decompression bomb).
    stored = None
    try:
        pd = ds.get("PixelData", None)   # raw stored bytes — NOT decoded
        if pd is not None:
            stored = len(pd)
    except Exception:
        stored = None

    if stored and declared > AMP_FLOOR and declared / stored > AMP_RATIO:
        return [Finding(
            "pixel_dimension_bomb", "critical",
            f"Pixel payload is {stored:,} bytes but declares a {declared / 1024**3:.1f} GiB "
            f"decoded image ({declared // max(stored,1):,}x amplification)",
            "A tiny encapsulated payload that claims to decode to gigabytes is a decompression "
            "bomb: the decoder allocates the full buffer and exhausts memory. Real compression "
            "ratios are well under 100x. CDR quarantines it.")]

    return [Finding("pixel_dimension_bomb", "pass",
                    f"Declared image buffer {declared / 1024**2:.1f} MiB within sane limits")]


def check_private_tag_payloads(ds, min_size: int = 1024) -> list[Finding]:
    """Scan private (odd-group) tags for embedded executables / opaque high-entropy blobs."""
    findings = []
    try:
        for elem in ds:
            if not elem.tag.is_private:
                continue
            val = elem.value
            if not isinstance(val, (bytes, bytearray)) or len(val) < min_size:
                continue
            sig = _match_signature(bytes(val[:8]))
            if sig:
                findings.append(Finding(
                    "private_tag_payload", "critical",
                    f"Private tag {elem.tag} carries a {sig} payload ({len(val):,} bytes)",
                    "Private (odd-group) tags hold arbitrary binary. An executable signature here "
                    "indicates a smuggled payload. CDR strips/quarantines private tags."))
            else:
                ent = _shannon_entropy(bytes(val[:4096]))
                if ent > 7.2:
                    findings.append(Finding(
                        "private_tag_payload", "warn",
                        f"Private tag {elem.tag} holds {len(val):,} bytes of high-entropy data "
                        f"(entropy {ent:.1f}/8)",
                        "High-entropy private binary can conceal encrypted or compressed payloads. "
                        "Review or strip via CDR."))
    except Exception:
        pass

    if not findings:
        findings.append(Finding("private_tag_payload", "pass", "No suspicious private-tag payloads"))
    return findings
