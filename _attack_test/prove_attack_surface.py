#!/usr/bin/env python3
"""
Empirical proof that the DICOM attack surface is real.

Defensive security testing for DicomLock. Run against the project's own files.
Creates only INERT artifacts (magic-byte headers, oversized length fields) —
NOT working malware — to prove the *file format permits* these constructions.

Demos:
  1. Codec attack surface  — which library each real sample routes pixel data through
  2. Polyglot permissiveness — a file that is simultaneously a valid CT and an ELF
  3. Length amplification   — a ~140-byte file that declares a ~4 GB allocation
"""

import glob
import os
import struct
import subprocess
import sys

import pydicom

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
SAMPLES = os.path.join(PROJECT, "samples")
SCRATCH = HERE

sys.path.insert(0, PROJECT)
from scanner.file_security import check_preamble  # noqa: E402


# Transfer Syntax UID -> (human name, decoder library actually invoked)
TS_CODEC = {
    "1.2.840.10008.1.2":        ("Implicit VR LE",        "native (no codec)"),
    "1.2.840.10008.1.2.1":      ("Explicit VR LE",        "native (no codec)"),
    "1.2.840.10008.1.2.1.99":   ("Deflated Explicit LE",  "zlib"),
    "1.2.840.10008.1.2.2":      ("Explicit VR BE",        "native (no codec)"),
    "1.2.840.10008.1.2.5":      ("RLE Lossless",          "RLE decoder"),
    "1.2.840.10008.1.2.4.50":   ("JPEG Baseline",         "libjpeg"),
    "1.2.840.10008.1.2.4.51":   ("JPEG Extended",         "libjpeg"),
    "1.2.840.10008.1.2.4.57":   ("JPEG Lossless",         "libjpeg"),
    "1.2.840.10008.1.2.4.70":   ("JPEG Lossless SV1",     "libjpeg"),
    "1.2.840.10008.1.2.4.80":   ("JPEG-LS Lossless",      "CharLS"),
    "1.2.840.10008.1.2.4.81":   ("JPEG-LS Near-Lossless", "CharLS"),
    "1.2.840.10008.1.2.4.90":   ("JPEG 2000 Lossless",    "OpenJPEG"),
    "1.2.840.10008.1.2.4.91":   ("JPEG 2000",             "OpenJPEG"),
    "1.2.840.10008.1.2.4.100":  ("MPEG2 Main Profile",    "FFmpeg-class video"),
    "1.2.840.10008.1.2.4.102":  ("H.264 / MPEG-4 AVC",    "FFmpeg-class video"),
    "1.2.840.10008.1.2.4.107":  ("HEVC / H.265",          "FFmpeg-class video"),
}

LINE = "=" * 72


def demo1_codec_surface():
    print(LINE)
    print("DEMO 1  Codec attack surface — your own sample files")
    print(LINE)
    files = sorted(glob.glob(os.path.join(SAMPLES, "*.dcm")))
    nonnative = 0
    print(f"{'file':<34}{'transfer syntax':<24}{'decoder lib'}")
    print("-" * 72)
    for fp in files:
        name = os.path.basename(fp)
        try:
            ds = pydicom.dcmread(fp, force=True)
            ts = ""
            if getattr(ds, "file_meta", None):
                ts = str(getattr(ds.file_meta, "TransferSyntaxUID", "") or "")
            human, codec = TS_CODEC.get(ts, ("(none / implicit)", "native (no codec)"))
            if codec not in ("native (no codec)", "RLE decoder"):
                nonnative += 1
            print(f"{name:<34}{human:<24}{codec}")
        except Exception as e:
            print(f"{name:<34}PARSE FAILED: {str(e)[:30]}")
    print("-" * 72)
    print(f"  {nonnative}/{len(files)} files route pixel data through a 3rd-party C/C++ codec")
    print("  (libjpeg / OpenJPEG / CharLS / FFmpeg-class) — the exact bug class")
    print("  Mythos proved it owns. These decoders run deep inside the PACS/viewer.\n")


def demo2_polyglot():
    print(LINE)
    print("DEMO 2  Polyglot — one file, two valid identities")
    print(LINE)
    # pick first sample that has pixel data
    src = None
    for fp in sorted(glob.glob(os.path.join(SAMPLES, "*.dcm"))):
        try:
            ds = pydicom.dcmread(fp, force=True)
            if "PixelData" in ds:
                src = fp
                break
        except Exception:
            continue
    if not src:
        print("  no sample with PixelData found\n")
        return

    raw = bytearray(open(src, "rb").read())
    # Inject ONLY the inert ELF magic into the 128-byte preamble. No payload.
    elf_magic = b"\x7fELF"
    raw[0:len(elf_magic)] = elf_magic
    out = os.path.join(SCRATCH, "polyglot_ct.dcm")
    with open(out, "wb") as f:
        f.write(raw)

    print(f"  source: {os.path.basename(src)}  ->  {os.path.basename(out)}")
    print("  (injected only the 4-byte ELF magic into the preamble — inert, no payload)\n")

    # Identity A: still a valid medical image?
    ds = pydicom.dcmread(out, force=True)
    mod = getattr(ds, "Modality", "?")
    rows = getattr(ds, "Rows", "?")
    cols = getattr(ds, "Columns", "?")
    shape = ds.pixel_array.shape if "PixelData" in ds else "n/a"
    print(f"  AS DICOM (pydicom):  Modality={mod}  {rows}x{cols}  pixels={shape}  -> VALID")

    # Identity B: what does the OS think it is?
    first4 = bytes(raw[0:4])
    try:
        ftype = subprocess.run(["file", "-b", out], capture_output=True, text=True).stdout.strip()
    except Exception:
        ftype = "(file cmd unavailable)"
    print(f"  AS BINARY (os):      first4={first4!r}  ->  file says: {ftype}")

    # Does the current scanner catch it?
    findings = check_preamble(out)
    flagged = [f for f in findings if f.severity in ("warn", "fail", "critical")]
    verdict = flagged[0].message if flagged else "NOT FLAGGED"
    print(f"  scanner verdict:     {verdict}")
    print("  -> The format PERMITS this. AV skips medical imagery; a real ELF/PE payload")
    print("     (CVE-2019-11687 / ELFDICOM) executes if the file lands on the wrong handler.\n")


def demo3_length_amplification():
    print(LINE)
    print("DEMO 3  Length amplification — a tiny file that demands gigabytes")
    print(LINE)
    # Hand-build a minimal Part-10 shell with one Implicit-VR element (7FE0,0010)
    # whose 4-byte length field claims ~4 GB while carrying zero value bytes.
    preamble = b"\x00" * 128
    dicm = b"DICM"
    group, elem = 0x7FE0, 0x0010          # PixelData
    declared_len = 0xFFFFFFF0             # ~4.29 GB
    # Implicit VR LE element header: group(2) elem(2) length(4)
    element = struct.pack("<HHI", group, elem, declared_len)
    blob = preamble + dicm + element       # NO actual value bytes follow
    out = os.path.join(SCRATCH, "length_bomb.dcm")
    with open(out, "wb") as f:
        f.write(blob)

    file_size = len(blob)
    # A naive parser reads the length field, then does f.read(length) / np.empty(length)
    off = 128 + 4 + 4                      # past preamble, DICM, tag
    parsed_len = struct.unpack("<I", blob[off:off + 4])[0]
    amplification = parsed_len / file_size

    print(f"  file on disk:        {file_size} bytes")
    print(f"  declared element len: {parsed_len:,} bytes ({parsed_len / 1024**3:.2f} GB)")
    print(f"  amplification:       {amplification:,.0f}x")
    print(f"  bytes actually present after header: {len(blob) - (off + 4)}")
    print("  A naive parser doing `buf = f.read(declared_len)` (or np.empty) attempts a")
    print("  ~4 GB allocation from a 140-byte file -> OOM / DoS. This is the GDCM class")
    print("  (CVE-2026-3650: 150-byte file -> 4.2 GB alloc). [No allocation performed here.]")
    # show the safe defensive check
    remaining = file_size - (off + 4)
    print(f"  defensive check:     declared_len({parsed_len:,}) >> remaining_bytes({remaining}) "
          f"=> REJECT\n")


if __name__ == "__main__":
    print()
    demo1_codec_surface()
    demo2_polyglot()
    demo3_length_amplification()
    print(LINE)
    print("All three constructions are permitted by the DICOM format. The problem is real.")
    print(LINE)
