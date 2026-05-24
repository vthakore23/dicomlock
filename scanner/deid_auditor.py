"""
DicomLock — De-identification Auditor (Module 4)

Checks whether DICOM files have been properly de-identified and flags
residual PHI (Personally Identifiable Information) exposure risks.

Four checks:
  1. check_deid_profile_completeness — PS3.15 Table E.1-1 Basic Profile tag audit
  2. check_private_tags_phi         — private (odd-group) tags scanned for PHI patterns
  3. check_burned_in_phi            — pixel heuristics for burned-in text (no OCR required)
  4. check_facial_geometry           — re-identification risk for head CT/MR scans
"""

import re
from typing import Optional

import numpy as np
import pydicom

try:
    from scipy import ndimage
except ImportError:
    ndimage = None

from scanner.findings import Finding


# ---------------------------------------------------------------------------
# DICOM PS3.15 Table E.1-1 — Basic Confidentiality Profile
# Tags that MUST be removed or emptied for proper de-identification.
# Format: (group, element): ("Tag Name", action)
# Actions: D = replace with dummy, Z = zero-length, X = remove, K = keep but clean
# ---------------------------------------------------------------------------
BASIC_PROFILE_TAGS = {
    (0x0008, 0x0050): ("AccessionNumber", "Z"),
    (0x0008, 0x0080): ("InstitutionName", "X"),
    (0x0008, 0x0081): ("InstitutionAddress", "X"),
    (0x0008, 0x0090): ("ReferringPhysicianName", "Z"),
    (0x0008, 0x0092): ("ReferringPhysicianAddress", "X"),
    (0x0008, 0x0094): ("ReferringPhysicianTelephoneNumbers", "X"),
    (0x0008, 0x1010): ("StationName", "X"),
    (0x0008, 0x1030): ("StudyDescription", "X"),
    (0x0008, 0x103E): ("SeriesDescription", "X"),
    (0x0008, 0x1040): ("InstitutionalDepartmentName", "X"),
    (0x0008, 0x1048): ("PhysiciansOfRecord", "X"),
    (0x0008, 0x1050): ("PerformingPhysicianName", "X"),
    (0x0008, 0x1060): ("NameOfPhysiciansReadingStudy", "X"),
    (0x0008, 0x1070): ("OperatorsName", "X"),
    (0x0010, 0x0010): ("PatientName", "Z"),
    (0x0010, 0x0020): ("PatientID", "Z"),
    (0x0010, 0x0030): ("PatientBirthDate", "Z"),
    (0x0010, 0x0032): ("PatientBirthTime", "X"),
    (0x0010, 0x0040): ("PatientSex", "Z"),
    (0x0010, 0x1000): ("OtherPatientIDs", "X"),
    (0x0010, 0x1001): ("OtherPatientNames", "X"),
    (0x0010, 0x1010): ("PatientAge", "X"),
    (0x0010, 0x1020): ("PatientSize", "X"),
    (0x0010, 0x1030): ("PatientWeight", "X"),
    (0x0010, 0x1040): ("PatientAddress", "X"),
    (0x0010, 0x2154): ("PatientTelephoneNumbers", "X"),
    (0x0010, 0x2160): ("EthnicGroup", "X"),
    (0x0010, 0x21B0): ("AdditionalPatientHistory", "X"),
    (0x0010, 0x4000): ("PatientComments", "X"),
    (0x0020, 0x0010): ("StudyID", "Z"),
    (0x0020, 0x4000): ("ImageComments", "X"),
    (0x0032, 0x1032): ("RequestingPhysician", "X"),
    (0x0038, 0x0010): ("AdmissionID", "X"),
    (0x0038, 0x0500): ("PatientState", "X"),
    (0x0040, 0x0006): ("ScheduledPerformingPhysicianName", "X"),
    (0x0040, 0x0244): ("PerformedProcedureStepStartDate", "X"),
    (0x0040, 0x0245): ("PerformedProcedureStepStartTime", "X"),
    (0x0040, 0x0253): ("PerformedProcedureStepID", "X"),
    (0x0040, 0x1001): ("RequestedProcedureID", "X"),
    (0x0040, 0x2016): ("PlacerOrderNumberImagingServiceRequest", "Z"),
    (0x0040, 0x2017): ("FillerOrderNumberImagingServiceRequest", "Z"),
    (0x0040, 0xA730): ("ContentSequence", "X"),
    (0x0088, 0x0140): ("StorageMediaFileSetUID", "U"),
    (0x3006, 0x0024): ("ReferencedFrameOfReferenceUID", "U"),
    (0x3006, 0x00C2): ("RelatedFrameOfReferenceUID", "U"),
}

# Subset of high-severity tags — these are almost always PHI
CRITICAL_PHI_TAGS = {
    (0x0010, 0x0010),  # PatientName
    (0x0010, 0x0020),  # PatientID
    (0x0010, 0x0030),  # PatientBirthDate
    (0x0008, 0x0050),  # AccessionNumber
    (0x0008, 0x0080),  # InstitutionName
    (0x0008, 0x0090),  # ReferringPhysicianName
    (0x0010, 0x1000),  # OtherPatientIDs
}

# Known vendor-specific private tags that often carry PHI
VENDOR_PHI_PRIVATE_TAGS = {
    (0x0043, 0x1029): "GE — may contain patient/exam info",
    (0x0019, 0x100C): "Siemens — may contain referring physician",
    (0x0019, 0x100D): "Siemens — may contain body part text",
    (0x2001, 0x1003): "Philips — may contain exam description",
    (0x2005, 0x100E): "Philips — may contain station/institution info",
    (0x7053, 0x1000): "Toshiba — may contain exam protocol info",
}

# Regex patterns for common PHI in text
PHI_PATTERNS = [
    (r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b", "SSN pattern (###-##-####)"),
    (r"\b\d{6,10}\b", "MRN-like number (6-10 digits)"),
    (r"\b(0[1-9]|1[0-2])[/-](0[1-9]|[12]\d|3[01])[/-](19|20)\d{2}\b", "Date (MM/DD/YYYY)"),
    (r"\b(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\b", "Date (YYYYMMDD)"),
    (r"\b[A-Z][a-z]+\s+[A-Z][a-z]+\b", "Possible name (Firstname Lastname)"),
    (r"\b\d{1,5}\s+[A-Z][a-z]+\s+(St|Ave|Blvd|Dr|Rd|Ln|Way|Ct)\b", "Street address pattern"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "Email address"),
    (r"\b\(\d{3}\)\s?\d{3}[-.]?\d{4}\b", "Phone number"),
]

# Body part values indicating head/face region
HEAD_BODY_PARTS = {"HEAD", "BRAIN", "SKULL", "FACE", "SINUS", "ORBIT", "NECK",
                   "C-SPINE", "CSPINE", "HEADNECK", "HEAD_NECK"}


# ---------------------------------------------------------------------------
# Check 1: DICOM Basic Profile completeness
# ---------------------------------------------------------------------------

def check_deid_profile_completeness(ds: pydicom.Dataset) -> list[Finding]:
    """Check whether PS3.15 Basic Profile tags have been properly removed or emptied."""
    findings = []
    present_critical = []
    present_other = []

    for tag, (name, action) in BASIC_PROFILE_TAGS.items():
        try:
            elem = ds[tag]
        except KeyError:
            continue  # tag absent — good

        # Check if the value is effectively empty
        value = elem.value
        if value is None:
            continue
        if isinstance(value, (str, bytes)) and len(value) == 0:
            continue
        if isinstance(value, pydicom.sequence.Sequence) and len(value) == 0:
            continue

        # Convert to string for display (truncate long values)
        val_str = str(value)

        # Catch other empty types (PersonName(''), empty DA/TM, etc.)
        if len(val_str.strip()) == 0:
            continue
        if len(val_str) > 60:
            val_str = val_str[:57] + "..."

        entry = (name, f"({tag[0]:04X},{tag[1]:04X})", val_str)

        if tag in CRITICAL_PHI_TAGS:
            present_critical.append(entry)
        else:
            present_other.append(entry)

    total_present = len(present_critical) + len(present_other)

    if total_present == 0:
        findings.append(Finding(
            "deid_profile", "pass",
            "De-identification profile complete — no Basic Profile tags contain data"
        ))
    else:
        # Critical PHI tags present
        if present_critical:
            tag_list = "; ".join(f"{n} {t} = '{v}'" for n, t, v in present_critical)
            findings.append(Finding(
                "deid_profile", "fail",
                f"{len(present_critical)} critical PHI tag(s) still contain data",
                details=f"These tags almost always contain direct patient identifiers: {tag_list}"
            ))

        # Other profile tags present
        if present_other:
            tag_list = "; ".join(f"{n} {t}" for n, t, _ in present_other)
            severity = "warn" if len(present_other) <= 5 else "fail"
            findings.append(Finding(
                "deid_profile", severity,
                f"{len(present_other)} other Basic Profile tag(s) still present",
                details=f"Tags that should be removed/zeroed per PS3.15: {tag_list}"
            ))

    return findings


# ---------------------------------------------------------------------------
# Check 2: Private tags PHI scan
# ---------------------------------------------------------------------------

def check_private_tags_phi(ds: pydicom.Dataset) -> list[Finding]:
    """Scan private (odd-group) tags for PHI patterns."""
    findings = []
    private_tag_count = 0
    phi_hits = []

    for elem in ds:
        # Private tags have odd group numbers
        if elem.tag.group % 2 == 0:
            continue
        private_tag_count += 1

        # Try to decode the value as text
        text = _decode_element_text(elem)
        if not text or len(text) < 3:
            continue

        # Check against vendor known-PHI tags
        tag_tuple = (elem.tag.group, elem.tag.element)
        vendor_note = VENDOR_PHI_PRIVATE_TAGS.get(tag_tuple)

        # Check text against PHI patterns
        matched_patterns = []
        for pattern, desc in PHI_PATTERNS:
            if re.search(pattern, text):
                matched_patterns.append(desc)

        if vendor_note or matched_patterns:
            tag_str = f"({elem.tag.group:04X},{elem.tag.element:04X})"
            val_preview = text[:80] + ("..." if len(text) > 80 else "")
            reason_parts = []
            if vendor_note:
                reason_parts.append(f"vendor: {vendor_note}")
            if matched_patterns:
                reason_parts.append(f"patterns: {', '.join(matched_patterns)}")
            phi_hits.append((tag_str, val_preview, "; ".join(reason_parts)))

    if private_tag_count == 0:
        findings.append(Finding(
            "private_tags_phi", "pass",
            "No private tags present"
        ))
    elif not phi_hits:
        findings.append(Finding(
            "private_tags_phi", "pass",
            f"Scanned {private_tag_count} private tag(s) — no PHI patterns detected"
        ))
    else:
        hit_detail = "; ".join(
            f"{tag} = '{val}' [{reason}]"
            for tag, val, reason in phi_hits[:10]  # cap detail length
        )
        extra = f" (showing first 10 of {len(phi_hits)})" if len(phi_hits) > 10 else ""
        findings.append(Finding(
            "private_tags_phi", "warn",
            f"{len(phi_hits)} private tag(s) may contain PHI",
            details=f"Potential PHI in private tags{extra}: {hit_detail}"
        ))

    return findings


def _decode_element_text(elem) -> Optional[str]:
    """Try to decode a DICOM element value as a string."""
    try:
        val = elem.value
        if isinstance(val, str):
            return val
        if isinstance(val, bytes):
            # Try common encodings
            for enc in ("utf-8", "latin-1"):
                try:
                    decoded = val.decode(enc)
                    # Only return if it looks like text (mostly printable)
                    printable_ratio = sum(c.isprintable() or c.isspace() for c in decoded) / max(len(decoded), 1)
                    if printable_ratio > 0.7:
                        return decoded
                except (UnicodeDecodeError, ZeroDivisionError):
                    continue
        if isinstance(val, pydicom.valuerep.PersonName):
            return str(val)
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Check 3: Burned-in PHI detection (pixel heuristics — no OCR)
# ---------------------------------------------------------------------------

# Regions to crop and analyze for burned-in text.
# Fractions of (height, width) for each edge strip.
EDGE_CROPS = {
    "top":    (0.00, 0.08, 0.00, 1.00),    # top 8%
    "bottom": (0.92, 1.00, 0.00, 1.00),    # bottom 8%
    "left":   (0.08, 0.92, 0.00, 0.10),    # left 10% (excluding corners)
    "right":  (0.08, 0.92, 0.90, 1.00),    # right 10%
}

# Thresholds (tuned for DICOM images)
TEXT_CONTRAST_THRESH = 0.25    # min fraction of high-contrast pixels in a strip
MIN_COMPONENT_SIZE = 4         # min pixels per connected component (text character)
MAX_COMPONENT_SIZE_FRAC = 0.02 # max fraction of strip area per component (ignore blobs)
MIN_TEXT_COMPONENTS = 5        # need this many text-like components to flag


def check_burned_in_phi(ds: pydicom.Dataset) -> list[Finding]:
    """Detect potential burned-in text/PHI in pixel data edge regions using heuristics."""
    findings = []

    # Check BurnedInAnnotation tag first
    burned_in_tag = getattr(ds, "BurnedInAnnotation", None)
    if burned_in_tag == "YES":
        findings.append(Finding(
            "burned_in_phi", "warn",
            "BurnedInAnnotation tag is 'YES' — file declares burned-in text",
            details="Image contains overlaid text per DICOM header. "
                    "This may include patient names, dates, or institution info."
        ))

    # Try to access pixel data
    try:
        pixels = ds.pixel_array
    except Exception:
        findings.append(Finding(
            "burned_in_phi", "info",
            "Cannot access pixel data for burned-in PHI analysis"
        ))
        return findings

    # Handle multi-frame: analyze first frame
    if pixels.ndim > 2 and pixels.shape[0] > 1:
        pixels = pixels[0]
    # Handle color images: convert to grayscale
    if pixels.ndim == 3 and pixels.shape[-1] in (3, 4):
        pixels = np.mean(pixels[..., :3], axis=-1)

    pixels = pixels.astype(np.float64)
    h, w = pixels.shape

    if h < 64 or w < 64:
        findings.append(Finding(
            "burned_in_phi", "info",
            "Image too small for burned-in PHI analysis"
        ))
        return findings

    # Normalize to 0-1
    pmin, pmax = pixels.min(), pixels.max()
    if pmax - pmin < 1e-6:
        # Flat image — no text possible
        if burned_in_tag != "YES":
            findings.append(Finding(
                "burned_in_phi", "pass",
                "No burned-in text indicators detected"
            ))
        return findings
    norm = (pixels - pmin) / (pmax - pmin)

    text_regions = []

    for region_name, (y0f, y1f, x0f, x1f) in EDGE_CROPS.items():
        y0, y1 = int(h * y0f), int(h * y1f)
        x0, x1 = int(w * x0f), int(w * x1f)
        strip = norm[y0:y1, x0:x1]

        sh, sw = strip.shape
        if sh < 4 or sw < 4:
            continue

        # Detect high-contrast pixels (bright text on dark background or vice versa)
        bright_mask = strip > 0.85
        dark_mask = strip < 0.15
        high_contrast_frac = max(bright_mask.mean(), dark_mask.mean())

        # Pick whichever polarity (bright or dark) has more high-contrast pixels
        if bright_mask.mean() >= dark_mask.mean():
            text_mask = bright_mask
        else:
            text_mask = dark_mask

        if text_mask.sum() < MIN_TEXT_COMPONENTS:
            continue

        # Connected component analysis for text-like structure
        if ndimage is None:
            # Fallback: just use contrast ratio
            if high_contrast_frac > TEXT_CONTRAST_THRESH:
                text_regions.append(region_name)
            continue

        labeled, num_components = ndimage.label(text_mask)
        if num_components < MIN_TEXT_COMPONENTS:
            continue

        # Count components that are text-sized (not too small, not too big)
        strip_area = sh * sw
        max_comp_size = strip_area * MAX_COMPONENT_SIZE_FRAC
        text_like_count = 0

        component_sizes = ndimage.sum(text_mask, labeled, range(1, num_components + 1))
        for size in component_sizes:
            if MIN_COMPONENT_SIZE <= size <= max_comp_size:
                text_like_count += 1

        if text_like_count >= MIN_TEXT_COMPONENTS:
            text_regions.append(region_name)

    if text_regions and burned_in_tag != "YES":
        findings.append(Finding(
            "burned_in_phi", "warn",
            f"Possible burned-in text detected in {len(text_regions)} edge region(s)",
            details=f"High-contrast text-like patterns found in: {', '.join(text_regions)}. "
                    "These regions may contain patient names, dates, or other overlaid text. "
                    "Manual review recommended."
        ))
    elif not text_regions and burned_in_tag != "YES":
        findings.append(Finding(
            "burned_in_phi", "pass",
            "No burned-in text indicators detected in edge regions"
        ))

    return findings


# ---------------------------------------------------------------------------
# Check 4: Facial geometry re-identification risk
# ---------------------------------------------------------------------------

def check_facial_geometry(ds: pydicom.Dataset) -> list[Finding]:
    """Assess re-identification risk from facial features in 3D head imaging."""
    findings = []

    modality = getattr(ds, "Modality", "").upper()
    if modality not in ("CT", "MR", "MRI", "PT", "PET"):
        findings.append(Finding(
            "facial_geometry", "pass",
            f"Facial re-identification N/A for modality '{modality}'"
        ))
        return findings

    # Check body part
    body_part = getattr(ds, "BodyPartExamined", "").upper().replace(" ", "")
    study_desc = getattr(ds, "StudyDescription", "").upper()
    series_desc = getattr(ds, "SeriesDescription", "").upper()

    is_head_scan = (
        body_part in HEAD_BODY_PARTS
        or any(kw in study_desc for kw in ("HEAD", "BRAIN", "SKULL", "FACE", "SINUS"))
        or any(kw in series_desc for kw in ("HEAD", "BRAIN", "SKULL", "FACE", "SINUS"))
    )

    if not is_head_scan:
        findings.append(Finding(
            "facial_geometry", "pass",
            f"Not a head scan (body part: '{body_part or 'unspecified'}') — low re-identification risk"
        ))
        return findings

    # It's a head CT/MR — assess volumetric risk
    num_frames = 1
    try:
        nf = getattr(ds, "NumberOfFrames", None)
        if nf is not None:
            num_frames = int(nf)
    except (ValueError, TypeError):
        pass

    # Check for ImagePositionPatient (indicates multi-slice series)
    has_position = hasattr(ds, "ImagePositionPatient")

    slice_thickness = None
    try:
        st = getattr(ds, "SliceThickness", None)
        if st is not None:
            slice_thickness = float(st)
    except (ValueError, TypeError):
        pass

    # Risk assessment
    if num_frames <= 1 and not has_position:
        # Single-slice — low but non-zero risk
        findings.append(Finding(
            "facial_geometry", "info",
            f"Head {modality} — single slice, low re-identification risk",
            details="Single 2D slice cannot be used for 3D facial reconstruction. "
                    "However, facial features may still be partially visible."
        ))
    else:
        # Multi-slice or volumetric — assess based on slice thickness
        risk_level = "warn"
        risk_detail = (
            f"Head {modality} with volumetric data "
            f"(frames={num_frames}, has_position={has_position}"
        )

        if slice_thickness is not None:
            risk_detail += f", slice_thickness={slice_thickness:.1f}mm"
            if slice_thickness <= 1.5:
                risk_level = "fail"
                risk_detail += "). Sub-2mm slices enable high-fidelity 3D facial reconstruction."
            elif slice_thickness <= 3.0:
                risk_level = "warn"
                risk_detail += "). Thin slices may allow facial reconstruction."
            else:
                risk_level = "info"
                risk_detail += "). Thick slices reduce but do not eliminate reconstruction risk."
        else:
            risk_detail += "). Slice thickness unknown — cannot fully assess risk."

        findings.append(Finding(
            "facial_geometry", risk_level,
            f"Head {modality} scan — facial re-identification risk",
            details=risk_detail + " Consider defacing (skull-stripping) before sharing."
        ))

    return findings


# ---------------------------------------------------------------------------
# Runner: execute all de-identification checks
# ---------------------------------------------------------------------------

def run_deid_checks(ds: pydicom.Dataset) -> list[Finding]:
    """Run all de-identification auditor checks and return combined findings."""
    findings = []
    for check_fn in (
        check_deid_profile_completeness,
        check_private_tags_phi,
        check_burned_in_phi,
        check_facial_geometry,
    ):
        try:
            findings.extend(check_fn(ds))
        except Exception as e:
            findings.append(Finding(
                check_fn.__name__.replace("check_", ""),
                "info",
                f"De-ID check '{check_fn.__name__}' failed: {e}"
            ))
    return findings
