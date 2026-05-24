"""
DicomLock — Codec CVE Exposure Module (Module 2)

Maps a file's TransferSyntaxUID to the decoder library that will actually process its
pixel data, then reports the known memory-safety CVE history of that decoder.

This reports EXPOSURE (this file routes through a CVE-bearing decoder deep inside the
PACS/viewer), NOT proof of an exploit. That honesty is deliberate — it keeps the tool
credible. See ../data/dicom_codec_cve.json (a maintained seed list, verify vs NVD/CISA).
"""

import json

from scanner.findings import Finding
from scanner._resources import data_file


# TransferSyntaxUID -> (human name, decoder key matching dicom_codec_cve.json)
# Mapping verified against the DICOM transfer-syntax registry (PS3.5 / PS3.6, table A-1).
TS_CODEC = {
    # Uncompressed / trivial
    "1.2.840.10008.1.2":       ("Implicit VR LE",        "native"),
    "1.2.840.10008.1.2.1":     ("Explicit VR LE",        "native"),
    "1.2.840.10008.1.2.1.99":  ("Deflated Explicit LE",  "zlib"),
    "1.2.840.10008.1.2.2":     ("Explicit VR BE",        "native"),
    "1.2.840.10008.1.2.5":     ("RLE Lossless",          "RLE"),
    # JPEG family (libjpeg / libjpeg-turbo)
    "1.2.840.10008.1.2.4.50":  ("JPEG Baseline (P1)",          "libjpeg"),
    "1.2.840.10008.1.2.4.51":  ("JPEG Extended (P2&4)",        "libjpeg"),
    "1.2.840.10008.1.2.4.52":  ("JPEG Extended (P3&5) [ret]",  "libjpeg"),
    "1.2.840.10008.1.2.4.53":  ("JPEG Spectral Sel. (P6&8) [ret]",  "libjpeg"),
    "1.2.840.10008.1.2.4.54":  ("JPEG Spectral Sel. (P7&9) [ret]",  "libjpeg"),
    "1.2.840.10008.1.2.4.55":  ("JPEG Full Prog. (P10&12) [ret]",   "libjpeg"),
    "1.2.840.10008.1.2.4.56":  ("JPEG Full Prog. (P11&13) [ret]",   "libjpeg"),
    "1.2.840.10008.1.2.4.57":  ("JPEG Lossless (P14)",         "libjpeg"),
    "1.2.840.10008.1.2.4.58":  ("JPEG Lossless (P15) [ret]",   "libjpeg"),
    "1.2.840.10008.1.2.4.59":  ("JPEG Ext. Hier. (P16&18) [ret]",   "libjpeg"),
    "1.2.840.10008.1.2.4.60":  ("JPEG Ext. Hier. (P17&19) [ret]",   "libjpeg"),
    "1.2.840.10008.1.2.4.61":  ("JPEG Spectral Hier. (P20&22) [ret]", "libjpeg"),
    "1.2.840.10008.1.2.4.62":  ("JPEG Spectral Hier. (P21&23) [ret]", "libjpeg"),
    "1.2.840.10008.1.2.4.63":  ("JPEG Full Prog. Hier. (P24&26) [ret]", "libjpeg"),
    "1.2.840.10008.1.2.4.64":  ("JPEG Full Prog. Hier. (P25&27) [ret]", "libjpeg"),
    "1.2.840.10008.1.2.4.65":  ("JPEG Lossless Hier. (P28) [ret]",  "libjpeg"),
    "1.2.840.10008.1.2.4.66":  ("JPEG Lossless Hier. (P29) [ret]",  "libjpeg"),
    "1.2.840.10008.1.2.4.70":  ("JPEG Lossless SV1 (P14)",     "libjpeg"),
    # JPEG-LS (CharLS)
    "1.2.840.10008.1.2.4.80":  ("JPEG-LS Lossless",      "CharLS"),
    "1.2.840.10008.1.2.4.81":  ("JPEG-LS Near-Lossless", "CharLS"),
    # JPEG 2000 (OpenJPEG)
    "1.2.840.10008.1.2.4.90":  ("JPEG 2000 Lossless",          "OpenJPEG"),
    "1.2.840.10008.1.2.4.91":  ("JPEG 2000",                   "OpenJPEG"),
    "1.2.840.10008.1.2.4.92":  ("JPEG 2000 P2 Multi-comp Lossless", "OpenJPEG"),
    "1.2.840.10008.1.2.4.93":  ("JPEG 2000 P2 Multi-comp",     "OpenJPEG"),
    "1.2.840.10008.1.2.4.94":  ("JPIP Referenced",             "OpenJPEG"),
    "1.2.840.10008.1.2.4.95":  ("JPIP Referenced Deflate",     "OpenJPEG"),
    # High-Throughput JPEG 2000 (OpenJPH / newer C++)
    "1.2.840.10008.1.2.4.201": ("HTJ2K Lossless",              "OpenJPH"),
    "1.2.840.10008.1.2.4.202": ("HTJ2K Lossless RPCL",         "OpenJPH"),
    "1.2.840.10008.1.2.4.203": ("HTJ2K",                       "OpenJPH"),
    # Video — FFmpeg-class demuxers/decoders
    "1.2.840.10008.1.2.4.100": ("MPEG2 Main/Main",       "FFmpeg-class"),
    "1.2.840.10008.1.2.4.101": ("MPEG2 Main/High",       "FFmpeg-class"),
    "1.2.840.10008.1.2.4.102": ("H.264 High 4.1",        "FFmpeg-class"),
    "1.2.840.10008.1.2.4.103": ("H.264 BD 4.1",          "FFmpeg-class"),
    "1.2.840.10008.1.2.4.104": ("H.264 High 4.2 (2D)",   "FFmpeg-class"),
    "1.2.840.10008.1.2.4.105": ("H.264 High 4.2 (3D)",   "FFmpeg-class"),
    "1.2.840.10008.1.2.4.106": ("H.264 Stereo 4.2",      "FFmpeg-class"),
    "1.2.840.10008.1.2.4.107": ("HEVC/H.265 Main 5.1",   "FFmpeg-class"),
    "1.2.840.10008.1.2.4.108": ("HEVC/H.265 Main10 5.1", "FFmpeg-class"),
}

# JPIP transfer syntaxes reference pixel data by URL — the parser fetches remote
# data, an external-reference / SSRF-class risk distinct from codec memory safety.
_JPIP = {"1.2.840.10008.1.2.4.94", "1.2.840.10008.1.2.4.95"}

_SAFE_DECODERS = {"native", "RLE"}
_CVE_DB = None


def _load_db() -> dict:
    global _CVE_DB
    if _CVE_DB is None:
        try:
            with open(data_file("dicom_codec_cve.json")) as f:
                _CVE_DB = json.load(f)
        except Exception:
            _CVE_DB = {"decoders": {}}
    return _CVE_DB


def check_codec_cve_exposure(ds) -> list[Finding]:
    ts = ""
    if getattr(ds, "file_meta", None):
        ts = str(getattr(ds.file_meta, "TransferSyntaxUID", "") or "")

    findings = []

    # JPIP references pixel data by URL — flag the external-fetch/SSRF surface separately.
    if ts in _JPIP:
        findings.append(Finding(
            "codec_cve", "warn",
            "Pixel data is JPIP-referenced — the parser fetches it from a remote URL",
            "JPIP transfer syntaxes point pixel data at an external server. A crafted file can "
            "steer a PACS/viewer to attacker-controlled or internal endpoints (SSRF-class) before "
            "any codec runs. CDR resolves/strips the reference rather than fetching it."))

    name, decoder = TS_CODEC.get(ts, ("unknown / unlisted", "native"))

    if decoder in _SAFE_DECODERS:
        if not findings:
            findings.append(Finding("codec_cve", "pass",
                                    f"Pixel data is {name} — no third-party image codec invoked"))
        return findings

    db = _load_db()
    info = db.get("decoders", {}).get(decoder, {})
    cves = info.get("cves", [])
    template = db.get("_meta", {}).get("nvd_url_template", "")
    if cves:
        cve_str = ", ".join(c["id"] for c in cves[:3])
        tail = f"known issues e.g. {cve_str}"
        audit = (f" Audit at {template.format(id=cves[0]['id'])} (substitute any CVE id)."
                 if template else "")
    else:
        tail = "third-party C/C++ code parsing attacker-controlled data — audit-worthy"
        audit = ""

    findings.append(Finding(
        "codec_cve", "warn",
        f"Encapsulated pixel data decodes via {decoder} ({name})",
        f"{decoder} is {tail}. This file routes through that decoder deep inside the PACS/viewer, "
        "on devices that are slow to patch. This is exposure, not proof of exploit — verify "
        f"current NVD/CISA advisories.{audit} CDR can transcode through a hardened path."))
    return findings
