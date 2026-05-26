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


# Executable / archive magic signatures (used for preamble + private-tag carving).
# Longer/more-specific signatures first so _match_signature reports the most precise hit.
_EXE_SIGS = {
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": "OLE compound file (MSI installer / legacy Office macro)",
    b"\x7fELF": "Linux ELF executable",
    b"\xca\xfe\xba\xbe": "macOS Mach-O / Java class",
    b"\xcf\xfa\xed\xfe": "macOS Mach-O 64-bit",
    b"\xce\xfa\xed\xfe": "macOS Mach-O 32-bit",
    b"PK\x03\x04": "ZIP/JAR archive",
    b"Rar!\x1a\x07": "RAR archive",
    b"7z\xbc\xaf\x27\x1c": "7-Zip archive",
    b"\xfd7zXZ\x00": "XZ archive",
    b"\x28\xb5\x2f\xfd": "Zstandard archive",
    b"MSCF": "Microsoft Cabinet archive",
    b"BZh": "bzip2 archive",
    b"\x04\x22\x4d\x18": "LZ4 frame",
    b"\x00asm": "WebAssembly module",
    b"dex\n": "Android DEX bytecode",
    b"\x1bLua": "Lua bytecode",
    b"!<arch>": "ar/.deb archive",
    b"\xed\xab\xee\xdb": "RPM package",
    b"%PDF": "PDF document",
    b"\x1f\x8b": "Gzip data",
    b"MZ": "Windows PE executable",
    b"#!": "shell script",
}

# NOTE: an image/media polyglot tier (PNG/JPEG/TIFF/RIFF magic in the preamble -> warn) was
# prototyped and removed: a 128-byte preamble is too small to hold a real image, image-format
# magic there is usually a benign artifact (e.g. pydicom's own CT_small_pydicom.dcm carries a
# TIFF header whose IFD offset points past EOF), and the non-standard-preamble entropy finding
# plus preamble-zeroing in CDR already cover any non-zero preamble. Flagging it produced false
# alarms on clean files for no added defense. Executable/installer/archive magic (above) is the
# part that warrants a polyglot verdict; those signatures do not appear benignly in a preamble.

# Signatures specific enough (>= 4 bytes) to scan for *inside* a payload window, so a payload
# padded so its header is not at offset 0 is still caught. Short 2-3 byte signatures (MZ, BZh,
# gzip, shell) are only matched at offset 0 to avoid coincidental hits in benign binary data.
_LONG_EXE_SIGS = {sig: name for sig, name in _EXE_SIGS.items() if len(sig) >= 4}

# Explicit-VR value representations that use 2 reserved bytes + a 4-byte length.
# Everything else uses a 2-byte length. (DICOM PS3.5)
_LONG_VR = {b"OB", b"OW", b"OF", b"OD", b"OL", b"OV", b"SQ", b"UC", b"UR", b"UT", b"UN"}
# Every valid DICOM VR (PS3.5). In Explicit-VR mode the 2 bytes after a tag MUST be one of
# these; if they are not, the file's actual encoding does not match its declared transfer
# syntax (or the walk has desynced), so byte-level length validation can no longer be trusted.
_VALID_VRS = {
    b"AE", b"AS", b"AT", b"CS", b"DA", b"DS", b"DT", b"FL", b"FD", b"IS", b"LO", b"LT",
    b"OB", b"OD", b"OF", b"OL", b"OV", b"OW", b"PN", b"SH", b"SL", b"SQ", b"SS", b"ST",
    b"SV", b"TM", b"UC", b"UI", b"UL", b"UN", b"UR", b"US", b"UT", b"UV",
}
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


def _scan_for_signature(data: bytes, window: int = 4096):
    """Find an executable/archive signature at offset 0 (any signature) or a long, specific
    signature anywhere within the leading window (catches a payload padded so its header is not at
    byte 0). Returns (name, offset) or (None, -1)."""
    name = _match_signature(data)
    if name:
        return name, 0
    head = data[:window]
    for sig, sname in _LONG_EXE_SIGS.items():
        idx = head.find(sig)
        if idx > 0:
            return sname, idx
    return None, -1


def _private_payload_threat(value: bytes):
    """Classify a private-tag binary value as a smuggled payload.

    Returns (severity, description) or (None, None). Grounded in measured real vendor data
    (575 CTs + pydicom test files: max private-binary entropy 3.75, p95 size 12 bytes), so the
    entropy floor of 7.0 and the 256-byte window never fire on legitimate vendor metadata.
    """
    name, idx = _scan_for_signature(value)
    if name:
        where = "header" if idx == 0 else f"offset {idx}"
        return "critical", f"{name} signature at {where}"
    if len(value) >= 256:
        ent = _shannon_entropy(value[:4096])
        if ent > 7.0:
            return "warn", f"opaque high-entropy data (entropy {ent:.1f}/8)"
    return None, None


def check_preamble(filepath: str) -> list[Finding]:
    """128-byte preamble: polyglot signatures + entropy heuristic."""
    findings = []
    with open(filepath, "rb") as f:
        preamble = f.read(128)
        magic = f.read(4)

    if magic != b"DICM":
        findings.append(Finding(
            "file_preamble", "critical",
            "Missing DICM magic bytes (file may not be valid DICOM)",
            f"Found bytes: {magic!r}"))
        return findings

    if preamble == b"\x00" * 128:
        findings.append(Finding("file_preamble", "pass", "Standard zero-filled preamble"))
        return findings

    detected = _match_signature(preamble)
    if detected:
        findings.append(Finding(
            "file_preamble", "critical",
            f"POLYGLOT FILE DETECTED. Preamble contains {detected} signature",
            "This file is simultaneously a valid DICOM file AND a valid "
            f"{detected} (CVE-2019-11687 / ELFDICOM). It can execute if opened by a non-DICOM "
            "handler. CDR neutralizes this by zeroing the preamble."))
    else:
        nonzero = sum(1 for b in preamble if b != 0)
        ent = _shannon_entropy(preamble)
        sev = "warn" if ent > 4.0 else "info"
        findings.append(Finding(
            "file_preamble", sev,
            f"Non-standard preamble ({nonzero}/128 bytes non-zero, entropy {ent:.1f}/8)",
            "A standard preamble is all zeros. High-entropy content can hide an obfuscated "
            "payload even without a known signature. CDR zeroes the preamble regardless."))
    return findings


def _locate_dataset(data: bytes):
    """Return (main_dataset_offset, is_implicit_vr, is_little_endian, is_deflated, meta_bomb).

    File Meta (group 0002) is always Explicit VR Little Endian. We walk it to find both
    the transfer syntax and where the main data set begins, and we validate each element's
    declared length against the bytes that remain (a length bomb in the File Meta group is
    just as much an allocation DoS as one in the main data set, and the main-dataset walk
    would otherwise never see it because a bomb here pushes the offset past EOF). meta_bomb is
    (byte_offset, declared_length, remaining) or None. If there is no File Meta, pydicom's
    force-read defaults to Implicit VR LE starting right after 'DICM'.
    """
    n = len(data)
    if data[132:134] == b"\x02\x00":  # File Meta group present
        off = 132
        ts = None
        meta_bomb = None
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
            if length != _UNDEFINED_LENGTH and length > n - voff:
                meta_bomb = (off, length, n - voff)
                break
            if (grp, el) == (0x0002, 0x0010):
                ts = data[voff: voff + length].rstrip(b"\x00 ").decode("ascii", "ignore")
            off = voff + (0 if length == _UNDEFINED_LENGTH else length)
        is_implicit = (ts == "1.2.840.10008.1.2")
        is_le = (ts != "1.2.840.10008.1.2.2")
        is_deflated = (ts == _DEFLATED_TS)
        return off, is_implicit, is_le, is_deflated, meta_bomb
    return 132, True, True, False, None


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
        off, is_implicit, is_le, is_deflated, meta_bomb = _locate_dataset(data)
    except Exception:
        return [Finding("length_amplification", "info",
                        "Structural scan skipped (could not resolve transfer syntax)")]

    if meta_bomb is not None:
        boff, length, remaining = meta_bomb
        ratio = length / max(n, 1)
        return [Finding(
            "length_amplification", "critical",
            f"File Meta element at byte {boff} declares {length:,} bytes but only "
            f"{remaining:,} remain",
            f"Declared length is {ratio:,.0f}x the file size, and it sits in the File Meta "
            "group (0002), which every DICOM parser reads first. A naive parser allocating this "
            "would exhaust memory before it even reaches the image. DicomLock rejects it before "
            "any allocation occurs.")]

    if is_deflated:
        # Deflated Explicit VR LE: the data set after File Meta is zlib-compressed, so its raw
        # bytes are NOT element headers — walking them would desync into a bogus "length bomb".
        # We can't validate element lengths without inflating (the zlib codec path we distrust;
        # see codec_cve). The decoded-size guard (check_pixel_dimension_bomb) still applies once
        # pydicom inflates and parses.
        return [Finding(
            "length_amplification", "info",
            "Dataset body is zlib-deflated, byte-level length check not applicable",
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
                if vr not in _VALID_VRS:
                    # Declared Explicit VR, but these bytes are not a valid VR: the file's actual
                    # encoding does not match its transfer syntax (e.g. an implicitly-encoded data
                    # set that declares a JPEG/Explicit TS) or the walk has desynced. Continuing
                    # would misread value bytes as element headers and fabricate a "length bomb"
                    # (an FP). Stop and report honestly; pydicom parses such files leniently and
                    # --disarm re-emits a conformant file.
                    return [Finding(
                        "length_amplification", "info",
                        "Structural length check stopped: element encoding does not match the "
                        "declared Explicit VR transfer syntax",
                        "The bytes where a VR is expected are not a valid DICOM VR, so byte-level "
                        "length validation cannot continue without desyncing. The decoded-size "
                        "guard (check_pixel_dimension_bomb) still applies after pydicom parses.")]
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
                f"Declared length is {ratio:,.0f}x the file size. A naive parser allocating this "
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
            "Legitimate files rarely exceed 3 to 5 levels.")]
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
    AMP_RATIO = 1000                 # declared:stored ratio no real codec reaches -> block
    AMP_WARN_RATIO = 100             # "real ratios are well under 100x" -> warn in the 100-1000 band

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
            "decoded. A denial-of-service against any viewer/PACS that sizes its buffer from the "
            "header. No real clinical frame approaches this. CDR quarantines it.")]

    # T2 — encapsulated/tiny payload claims to decode to a huge buffer (decompression bomb).
    stored = None
    try:
        pd = ds.get("PixelData", None)   # raw stored bytes — NOT decoded
        if pd is not None:
            stored = len(pd)
    except Exception:
        stored = None

    if stored and declared > AMP_FLOOR:
        ratio = declared / stored
        if ratio > AMP_RATIO:
            return [Finding(
                "pixel_dimension_bomb", "critical",
                f"Pixel payload is {stored:,} bytes but declares a {declared / 1024**3:.1f} GiB "
                f"decoded image ({int(ratio):,}x amplification)",
                "A tiny encapsulated payload that claims to decode to gigabytes is a decompression "
                "bomb: the decoder allocates the full buffer and exhausts memory. Real compression "
                "ratios are well under 100x. CDR quarantines it.")]
        if ratio > AMP_WARN_RATIO:
            return [Finding(
                "pixel_dimension_bomb", "warn",
                f"Pixel payload is {stored:,} bytes but declares a {declared / 1024**2:.0f} MiB "
                f"decoded image ({int(ratio):,}x amplification)",
                "This amplification is well above any real codec (lossless ~3x, lossy ~20x), so a "
                "decoder sizing its buffer from the header would over-allocate. Below the hard "
                "quarantine threshold, but disarm decodes it in the resource-limited sandbox so "
                "the over-allocation is contained.")]

    return [Finding("pixel_dimension_bomb", "pass",
                    f"Declared image buffer {declared / 1024**2:.1f} MiB within sane limits")]


def check_private_tag_payloads(ds, min_size: int = 8) -> list[Finding]:
    """Scan private (odd-group) tags for embedded executables / opaque high-entropy blobs.

    Uses the same _private_payload_threat classifier the CDR engine uses to decide what to strip,
    so detection and disarm never disagree (a payload the scanner flags is one CDR removes, even
    under an allowlisted vendor creator). It catches a signature at offset 0, a long signature
    padded deeper into the value, and high-entropy opaque blobs.
    """
    findings = []
    try:
        for elem in ds:
            if not elem.tag.is_private:
                continue
            val = elem.value
            if not isinstance(val, (bytes, bytearray)) or len(val) < min_size:
                continue
            severity, desc = _private_payload_threat(bytes(val))
            if severity == "critical":
                findings.append(Finding(
                    "private_tag_payload", "critical",
                    f"Private tag {elem.tag} carries a payload ({len(val):,} bytes): {desc}",
                    "Private (odd-group) tags hold arbitrary binary. An executable/archive "
                    "signature here indicates a smuggled payload. CDR strips/quarantines it."))
            elif severity == "warn":
                findings.append(Finding(
                    "private_tag_payload", "warn",
                    f"Private tag {elem.tag} holds {len(val):,} bytes of {desc}",
                    "High-entropy private binary can conceal encrypted or compressed payloads. "
                    "Review or strip via CDR."))
    except Exception:
        pass

    if not findings:
        findings.append(Finding("private_tag_payload", "pass", "No suspicious private-tag payloads"))
    return findings
