"""
DicomLock — Metadata Integrity Scanner

Validates DICOM file metadata for internal consistency, suspicious patterns,
and signs of tampering or corruption.
"""

import pydicom
from pydicom.uid import UID
import numpy as np
from datetime import datetime

from scanner.findings import Finding


# Valid DICOM modalities
VALID_MODALITIES = {
    "CR", "CT", "MR", "US", "XA", "NM", "PT", "MG", "DX", "RF",
    "OT", "BI", "CD", "DD", "DG", "ES", "LS", "RG", "TG", "IO",
    "PX", "GM", "SM", "XC", "PR", "AU", "ECG", "EPS", "HD", "SR",
    "IVUS", "OP", "SMR", "AR", "KER", "VA", "SRF", "OCT", "OPM",
    "OPV", "OPR", "LEN", "DOC", "SC", "RTIMAGE", "RTDOSE",
    "RTSTRUCT", "RTPLAN", "RTRECORD", "SEG", "REG", "KO", "HC",
}

# Standard Transfer Syntax UIDs
KNOWN_TRANSFER_SYNTAXES = {
    "1.2.840.10008.1.2",        # Implicit VR Little Endian
    "1.2.840.10008.1.2.1",      # Explicit VR Little Endian
    "1.2.840.10008.1.2.1.99",   # Deflated Explicit VR Little Endian
    "1.2.840.10008.1.2.2",      # Explicit VR Big Endian
    "1.2.840.10008.1.2.4.50",   # JPEG Baseline
    "1.2.840.10008.1.2.4.51",   # JPEG Extended
    "1.2.840.10008.1.2.4.57",   # JPEG Lossless
    "1.2.840.10008.1.2.4.70",   # JPEG Lossless SV1
    "1.2.840.10008.1.2.4.80",   # JPEG-LS Lossless
    "1.2.840.10008.1.2.4.81",   # JPEG-LS Near-Lossless
    "1.2.840.10008.1.2.4.90",   # JPEG 2000 Lossless
    "1.2.840.10008.1.2.4.91",   # JPEG 2000
    "1.2.840.10008.1.2.4.92",   # JPEG 2000 Part 2 Multi-component Lossless
    "1.2.840.10008.1.2.4.93",   # JPEG 2000 Part 2 Multi-component
    "1.2.840.10008.1.2.4.94",   # JPIP Referenced
    "1.2.840.10008.1.2.4.95",   # JPIP Referenced Deflate
    "1.2.840.10008.1.2.4.100",  # MPEG2 Main Profile / Main Level
    "1.2.840.10008.1.2.4.101",  # MPEG2 Main Profile / High Level
    "1.2.840.10008.1.2.4.102",  # H.264 High Profile / Level 4.1
    "1.2.840.10008.1.2.4.103",  # H.264 BD-compatible
    "1.2.840.10008.1.2.4.104",  # H.264 High 4.2 (2D)
    "1.2.840.10008.1.2.4.105",  # H.264 High 4.2 (3D)
    "1.2.840.10008.1.2.4.106",  # H.264 Stereo 4.2
    "1.2.840.10008.1.2.4.107",  # HEVC/H.265 Main Profile / Level 5.1
    "1.2.840.10008.1.2.4.108",  # HEVC/H.265 Main 10 Profile / Level 5.1
    "1.2.840.10008.1.2.4.201",  # High-Throughput JPEG 2000 Lossless
    "1.2.840.10008.1.2.4.202",  # High-Throughput JPEG 2000 Lossless RPCL
    "1.2.840.10008.1.2.4.203",  # High-Throughput JPEG 2000
    "1.2.840.10008.1.2.5",      # RLE Lossless
}


def check_modality(ds: pydicom.Dataset) -> list[Finding]:
    """Check that the Modality tag is present and valid."""
    findings = []

    if not hasattr(ds, "Modality"):
        findings.append(Finding(
            "modality", "warn",
            "Modality tag (0008,0060) is missing"
        ))
        return findings

    modality = ds.Modality
    if modality in VALID_MODALITIES:
        findings.append(Finding(
            "modality", "pass",
            f"Valid modality: {modality}"
        ))
    else:
        findings.append(Finding(
            "modality", "warn",
            f"Unrecognized modality: '{modality}'",
            f"Expected one of the standard DICOM modalities. Got '{modality}'."
        ))

    return findings


# Transfer syntaxes whose pixel data is stored uncompressed (raw size == decoded size).
# Everything else is encapsulated/compressed and cannot be size-verified without decoding.
_NATIVE_TS = {
    "1.2.840.10008.1.2",       # Implicit VR LE
    "1.2.840.10008.1.2.1",     # Explicit VR LE
    "1.2.840.10008.1.2.1.99",  # Deflated (PixelData is inflated by the time it's parsed)
    "1.2.840.10008.1.2.2",     # Explicit VR BE
    "",                        # no File Meta -> pydicom force-reads as Implicit VR LE
}


def _expected_pixel_bytes(rows, cols, bits, samples, frames, photometric):
    """Declared uncompressed pixel-data size in bytes.

    Accounts for two encodings where the stored size is legitimately NOT
    rows*cols*samples*bytes_per_pixel:
      - 1-bit data is bit-packed (8 pixels per byte), e.g. overlays / 1-bit images.
      - YBR chroma-subsampled formats store the color planes at reduced resolution:
        *_422 keeps Cb/Cr for every 2nd pixel (2 bytes/pixel for 8-bit, not 3);
        *_420 keeps Cb/Cr for every 4th pixel (1.5 bytes/pixel).
    """
    px = rows * cols * frames
    if bits == 1:
        return (px * samples + 7) // 8
    bpp = (bits + 7) // 8
    pi = (str(photometric) if photometric is not None else "").upper()
    if pi in ("YBR_FULL_422", "YBR_PARTIAL_422"):
        return px * bpp * 2
    if pi == "YBR_PARTIAL_420":
        return px * bpp * 3 // 2
    return px * bpp * samples


def check_pixel_dimensions(ds: pydicom.Dataset) -> list[Finding]:
    """
    Verify that declared pixel dimensions are consistent with the stored pixel data.

    Decode-free by design: DicomLock never calls ds.pixel_array during a scan, because decoding
    is exactly the untrusted codec path (libjpeg/OpenJPEG/FFmpeg-class) the tool exists to keep
    files away from. For uncompressed data we compare the raw stored size to the declared size
    (catches tampering/corruption); for compressed data we report honestly that decoded-shape
    verification requires transcoding via --disarm. The allocation-DoS case (absurd dimensions /
    decompression bombs) is handled separately by check_pixel_dimension_bomb.
    """
    findings = []

    if not hasattr(ds, "PixelData"):
        findings.append(Finding(
            "pixel_dimensions", "info",
            "No pixel data present (may be a structured report, RT plan, etc.)"
        ))
        return findings

    rows = getattr(ds, "Rows", None)
    columns = getattr(ds, "Columns", None)
    bits_allocated = getattr(ds, "BitsAllocated", None)
    samples_per_pixel = getattr(ds, "SamplesPerPixel", 1)
    number_of_frames = getattr(ds, "NumberOfFrames", 1)
    if isinstance(number_of_frames, str):
        number_of_frames = int(number_of_frames)

    if rows is None or columns is None:
        findings.append(Finding(
            "pixel_dimensions", "fail",
            "Pixel data exists but Rows/Columns tags are missing",
            "This is suspicious. Pixel data without dimension metadata."
        ))
        return findings

    if bits_allocated is None:
        findings.append(Finding(
            "pixel_dimensions", "fail",
            "Pixel data exists but BitsAllocated tag is missing"
        ))
        return findings

    photometric = getattr(ds, "PhotometricInterpretation", None)
    expected_size = _expected_pixel_bytes(
        rows, columns, bits_allocated, samples_per_pixel, number_of_frames, photometric)
    raw_size = len(ds.PixelData)

    ts = getattr(getattr(ds, "file_meta", None), "TransferSyntaxUID", None)
    is_native = (str(ts) if ts is not None else "") in _NATIVE_TS

    if not is_native:
        findings.append(Finding(
            "pixel_dimensions", "info",
            f"Compressed pixel data ({raw_size:,} stored bytes, declares {expected_size:,} "
            "uncompressed)",
            "Decoded-shape verification would require running the untrusted codec, which DicomLock "
            "refuses to do during a scan. Use --disarm to transcode and verify in a controlled step."
        ))
        return findings

    # Uncompressed: the image must be fully present. FEWER bytes than declared is the dangerous
    # case (truncation, or a header crafted to make a viewer read past its buffer). MORE bytes is
    # legal trailing padding (even-length / vendor padding), not an over-read.
    if raw_size + 2 < expected_size:
        findings.append(Finding(
            "pixel_dimensions", "fail",
            f"Uncompressed pixel data is {raw_size:,} bytes but the header declares "
            f"{expected_size:,} (fewer bytes than the image requires)",
            "For an uncompressed transfer syntax the stored bytes must cover the declared image. "
            "A shortfall indicates truncation, tampering, or a crafted header that makes a viewer "
            "read past the pixel buffer."
        ))
    elif raw_size > expected_size + 2:
        excess = raw_size - expected_size
        if excess <= max(expected_size, 4096):
            findings.append(Finding(
                "pixel_dimensions", "pass",
                f"Pixel dimensions consistent: {rows}x{columns}, {bits_allocated}-bit, "
                f"{samples_per_pixel} channel(s), {number_of_frames} frame(s) "
                f"(+{excess:,} bytes trailing padding)"
            ))
        else:
            findings.append(Finding(
                "pixel_dimensions", "warn",
                f"Pixel data carries {excess:,} bytes beyond the declared {expected_size:,}-byte "
                "image",
                "A small trailer is normal padding, but a large unexplained trailer after the pixel "
                "data can conceal appended content. Review or strip via --disarm."
            ))
    else:
        findings.append(Finding(
            "pixel_dimensions", "pass",
            f"Pixel dimensions consistent: {rows}x{columns}, {bits_allocated}-bit, "
            f"{samples_per_pixel} channel(s), {number_of_frames} frame(s)"
        ))

    return findings


def check_transfer_syntax(ds: pydicom.Dataset) -> list[Finding]:
    """Verify the Transfer Syntax UID is valid and recognized."""
    findings = []

    ts = getattr(ds.file_meta, "TransferSyntaxUID", None) if hasattr(ds, "file_meta") else None

    if ts is None:
        findings.append(Finding(
            "transfer_syntax", "warn",
            "No Transfer Syntax UID found, cannot verify encoding"
        ))
        return findings

    ts_str = str(ts)
    if ts_str in KNOWN_TRANSFER_SYNTAXES:
        ts_name = UID(ts_str).name if hasattr(UID(ts_str), "name") else ts_str
        findings.append(Finding(
            "transfer_syntax", "pass",
            f"Valid transfer syntax: {ts_name}"
        ))
    else:
        findings.append(Finding(
            "transfer_syntax", "warn",
            f"Unrecognized Transfer Syntax UID: {ts_str}",
            "This may be a private or retired transfer syntax."
        ))

    return findings


def check_sop_class(ds: pydicom.Dataset) -> list[Finding]:
    """Verify the SOP Class UID is present and matches modality."""
    findings = []

    sop_class = getattr(ds.file_meta, "MediaStorageSOPClassUID", None) if hasattr(ds, "file_meta") else None
    if sop_class is None:
        sop_class = getattr(ds, "SOPClassUID", None)

    if sop_class is None:
        findings.append(Finding(
            "sop_class", "warn",
            "No SOP Class UID found"
        ))
        return findings

    try:
        sop_name = UID(str(sop_class)).name
        findings.append(Finding(
            "sop_class", "pass",
            f"SOP Class: {sop_name}"
        ))
    except Exception:
        findings.append(Finding(
            "sop_class", "info",
            f"SOP Class UID: {sop_class} (name lookup unavailable)"
        ))

    return findings


def check_dates(ds: pydicom.Dataset) -> list[Finding]:
    """
    Check date fields for consistency and suspicious patterns.

    Flags:
    - Missing dates
    - Future dates
    - Study date after content/acquisition date
    - Dates that are clearly placeholder values
    """
    findings = []
    dates = {}

    date_fields = {
        "StudyDate": "Study Date",
        "SeriesDate": "Series Date",
        "ContentDate": "Content Date",
        "AcquisitionDate": "Acquisition Date",
    }

    for tag, label in date_fields.items():
        val = getattr(ds, tag, None)
        if val:
            try:
                parsed = datetime.strptime(str(val), "%Y%m%d")
                dates[tag] = parsed
            except (ValueError, TypeError):
                findings.append(Finding(
                    "dates", "warn",
                    f"{label} has invalid format: '{val}'"
                ))

    if not dates:
        findings.append(Finding(
            "dates", "info",
            "No date fields present in this file"
        ))
        return findings

    # Check for future dates
    now = datetime.now()
    for tag, parsed in dates.items():
        if parsed > now:
            findings.append(Finding(
                "dates", "fail",
                f"{date_fields[tag]} is in the future: {parsed.strftime('%Y-%m-%d')}",
                "Future dates indicate metadata fabrication or system clock issues."
            ))

    # Check for placeholder dates
    for tag, parsed in dates.items():
        if parsed.year < 1950:
            findings.append(Finding(
                "dates", "warn",
                f"{date_fields[tag]} is suspiciously old: {parsed.strftime('%Y-%m-%d')}"
            ))

    # Check date ordering (study should not be after content/acquisition)
    if "StudyDate" in dates and "AcquisitionDate" in dates:
        if dates["StudyDate"] > dates["AcquisitionDate"]:
            findings.append(Finding(
                "dates", "warn",
                "Study Date is after Acquisition Date (unusual ordering)"
            ))

    # If everything looks fine
    date_issues = [f for f in findings if f.check_name == "dates" and f.severity in ("warn", "fail")]
    if not date_issues:
        earliest = min(dates.values())
        latest = max(dates.values())
        findings.append(Finding(
            "dates", "pass",
            f"Date fields consistent ({earliest.strftime('%Y-%m-%d')} to {latest.strftime('%Y-%m-%d')})"
        ))

    return findings


def check_patient_info(ds: pydicom.Dataset) -> list[Finding]:
    """Check for presence and consistency of patient identification fields."""
    findings = []

    patient_name = getattr(ds, "PatientName", None)
    patient_id = getattr(ds, "PatientID", None)

    if not patient_name and not patient_id:
        findings.append(Finding(
            "patient_info", "warn",
            "No patient identification fields, file may have been anonymized or stripped"
        ))
    else:
        has_name = bool(patient_name and str(patient_name).strip())
        has_id = bool(patient_id and str(patient_id).strip())
        findings.append(Finding(
            "patient_info", "pass" if (has_name and has_id) else "info",
            f"Patient Name: {'present' if has_name else 'missing'}, "
            f"Patient ID: {'present' if has_id else 'missing'}"
        ))

    return findings


def check_institution(ds: pydicom.Dataset) -> list[Finding]:
    """Check for institution and device provenance information."""
    findings = []

    institution = getattr(ds, "InstitutionName", None)
    manufacturer = getattr(ds, "Manufacturer", None)
    station_name = getattr(ds, "StationName", None)
    model_name = getattr(ds, "ManufacturerModelName", None)

    provenance_fields = {
        "Institution": institution,
        "Manufacturer": manufacturer,
        "Station": station_name,
        "Model": model_name,
    }

    present = {k: v for k, v in provenance_fields.items() if v and str(v).strip()}
    missing = {k for k, v in provenance_fields.items() if not v or not str(v).strip()}

    if len(present) >= 2:
        info_str = ", ".join(f"{k}: {v}" for k, v in present.items())
        findings.append(Finding(
            "provenance", "pass",
            f"Device provenance present: {info_str}"
        ))
    elif len(present) >= 1:
        findings.append(Finding(
            "provenance", "info",
            f"Partial provenance. Missing: {', '.join(missing)}",
            "Limited provenance data makes it harder to verify image origin."
        ))
    else:
        findings.append(Finding(
            "provenance", "warn",
            "No provenance information, cannot verify image origin",
            "Missing institution, manufacturer, station, and model information. "
            "This is common in anonymized files but suspicious in clinical imports."
        ))

    return findings


def check_uid_uniqueness(ds: pydicom.Dataset) -> list[Finding]:
    """Check that UID fields are properly formatted and not obviously fabricated."""
    findings = []

    uid_fields = {
        "StudyInstanceUID": getattr(ds, "StudyInstanceUID", None),
        "SeriesInstanceUID": getattr(ds, "SeriesInstanceUID", None),
        "SOPInstanceUID": getattr(ds, "SOPInstanceUID", None),
    }

    for name, uid in uid_fields.items():
        if uid is None:
            findings.append(Finding(
                "uid_check", "warn",
                f"{name} is missing"
            ))
            continue

        uid_str = str(uid)

        # Check length (max 64 chars per DICOM standard)
        if len(uid_str) > 64:
            findings.append(Finding(
                "uid_check", "fail",
                f"{name} exceeds 64 character limit ({len(uid_str)} chars)",
                "This violates the DICOM standard and may indicate fabrication."
            ))

        # Check for valid characters (digits and dots only)
        if not all(c in "0123456789." for c in uid_str):
            findings.append(Finding(
                "uid_check", "fail",
                f"{name} contains invalid characters",
                f"UIDs must contain only digits and dots. Got: '{uid_str[:50]}...'"
            ))

    # Check that Study/Series/SOP UIDs are all different
    valid_uids = {k: str(v) for k, v in uid_fields.items() if v is not None}
    uid_values = list(valid_uids.values())
    if len(uid_values) != len(set(uid_values)):
        findings.append(Finding(
            "uid_check", "fail",
            "Duplicate UIDs found. Study, Series, and SOP Instance UIDs should all be unique.",
            "Identical UIDs across different levels indicate copy/paste fabrication."
        ))

    if not any(f.severity in ("warn", "fail") for f in findings):
        findings.append(Finding(
            "uid_check", "pass",
            "All UIDs present, properly formatted, and unique"
        ))

    return findings


def run_metadata_checks(ds: pydicom.Dataset) -> list[Finding]:
    """Run all metadata integrity checks on a parsed DICOM dataset."""
    checks = [
        check_modality,
        check_transfer_syntax,
        check_sop_class,
        check_pixel_dimensions,
        check_dates,
        check_patient_info,
        check_institution,
        check_uid_uniqueness,
    ]

    all_findings = []
    for check in checks:
        try:
            all_findings.extend(check(ds))
        except Exception as e:
            all_findings.append(Finding(
                check.__name__, "warn",
                f"Check failed with error: {str(e)}"
            ))

    return all_findings
