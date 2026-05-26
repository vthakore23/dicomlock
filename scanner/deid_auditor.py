"""
DicomLock, De-identification Auditor (Module 4)

Checks whether DICOM files have been properly de-identified and flags
residual PHI (Personally Identifiable Information) exposure risks.

Four checks:
  1. check_deid_profile_completeness, PS3.15 Table E.1-1 Basic Profile tag audit
  2. check_private_tags_phi, private (odd-group) tags scanned for PHI patterns
  3. check_burned_in_phi, pixel heuristics for burned-in text (no OCR required)
  4. check_facial_geometry, re-identification risk for head CT/MR scans
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
# DICOM PS3.15 Table E.1-1, Basic Confidentiality Profile
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

# Subset of high-severity tags, these are almost always PHI
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
    (0x0043, 0x1029): "GE, may contain patient/exam info",
    (0x0019, 0x100C): "Siemens, may contain referring physician",
    (0x0019, 0x100D): "Siemens, may contain body part text",
    (0x2001, 0x1003): "Philips, may contain exam description",
    (0x2005, 0x100E): "Philips, may contain station/institution info",
    (0x7053, 0x1000): "Toshiba, may contain exam protocol info",
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
            continue  # tag absent, good

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
            "De-identification profile complete, no Basic Profile tags contain data"
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
            f"Scanned {private_tag_count} private tag(s), no PHI patterns detected"
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
# Check 3: Burned-in PHI detection (pixel heuristics, no OCR)
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
            "BurnedInAnnotation tag is 'YES', file declares burned-in text",
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
        # Flat image, no text possible
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
            f"Not a head scan (body part: '{body_part or 'unspecified'}'), low re-identification risk"
        ))
        return findings

    # It's a head CT/MR, assess volumetric risk
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
        # Single-slice, low but non-zero risk
        findings.append(Finding(
            "facial_geometry", "info",
            f"Head {modality}, single slice, low re-identification risk",
            details="Single 2D slice cannot be used for 3D facial reconstruction. "
                    "However, facial features may still be partially visible."
        ))
    else:
        # Multi-slice or volumetric, assess based on slice thickness
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
            risk_detail += "). Slice thickness unknown, cannot fully assess risk."

        findings.append(Finding(
            "facial_geometry", risk_level,
            f"Head {modality} scan carries facial re-identification risk",
            details=risk_detail + " Consider defacing (skull-stripping) before sharing."
        ))

    return findings


# ---------------------------------------------------------------------------
# Check 5: PHI in standard free-text fields (content-based, not just tag presence)
# ---------------------------------------------------------------------------

# Standard (non-private) descriptive fields that frequently leak identifiers in the clear even
# after a tag-level de-identification pass that only empties the obvious Patient* tags.
FREE_TEXT_PHI_TAGS = [
    (0x0008, 0x1030, "StudyDescription"),
    (0x0008, 0x103E, "SeriesDescription"),
    (0x0008, 0x4000, "IdentifyingComments"),
    (0x0010, 0x21B0, "AdditionalPatientHistory"),
    (0x0010, 0x4000, "PatientComments"),
    (0x0010, 0x2180, "Occupation"),
    (0x0018, 0x1030, "ProtocolName"),
    (0x0020, 0x4000, "ImageComments"),
    (0x0032, 0x4000, "StudyComments"),
    (0x0038, 0x4000, "VisitComments"),
    (0x0040, 0x0254, "PerformedProcedureStepDescription"),
]

# The broad "Firstname Lastname" pattern is dropped for free text (mixed-case clinical phrasing
# like "Chest Wall" trips it); it stays in the private-tag scan where context is more suspicious.
_FREE_TEXT_PATTERNS = [(p, d) for p, d in PHI_PATTERNS if "Possible name" not in d]

_SEV_RANK = {"pass": 0, "info": 1, "warn": 2, "fail": 3, "critical": 4}


def check_free_text_phi(ds: pydicom.Dataset) -> list[Finding]:
    """Scan standard free-text descriptive fields for embedded identifiers (MRN, SSN, dates,
    emails, phones, addresses) left in the clear after tag-level de-identification."""
    hits = []
    for grp, el, name in FREE_TEXT_PHI_TAGS:
        try:
            elem = ds[(grp, el)]
        except KeyError:
            continue
        text = _decode_element_text(elem)
        if not text or len(text.strip()) < 3:
            continue
        matched = [d for p, d in _FREE_TEXT_PATTERNS if re.search(p, text)]
        if matched:
            preview = text[:80] + ("..." if len(text) > 80 else "")
            hits.append((name, f"({grp:04X},{el:04X})", preview, matched))
    if not hits:
        return [Finding("free_text_phi", "pass",
                        "No identifier patterns in free-text descriptive fields")]
    detail = "; ".join(f"{n} {t} = '{v}' [{', '.join(m)}]" for n, t, v, m in hits[:8])
    return [Finding("free_text_phi", "warn",
                    f"{len(hits)} free-text field(s) contain identifier-like patterns",
                    details=detail)]


# ---------------------------------------------------------------------------
# Optional OCR for burned-in pixel PHI (graceful fallback to the heuristic if unavailable)
# ---------------------------------------------------------------------------

def _ocr_available() -> bool:
    try:
        import shutil
        import pytesseract  # noqa: F401
        return shutil.which("tesseract") is not None
    except Exception:
        return False


def _ocr_edge_phi(ds: pydicom.Dataset):
    """If OCR is available, read text from the image's top/bottom edge bands (where overlays live)
    and test it for identifier patterns. Edge-only keeps it fast and avoids OCR'ing the diagnostic
    image itself. Returns (ocr_available, text_found, [phi_descriptions])."""
    if not _ocr_available():
        return (False, False, [])
    try:
        import pytesseract
        from PIL import Image
        px = ds.pixel_array
        if px.ndim > 2 and px.shape[0] > 1:
            px = px[0]
        if px.ndim == 3 and px.shape[-1] in (3, 4):
            px = np.mean(px[..., :3], axis=-1)
        px = px.astype(np.float64)
        h, w = px.shape
        if h < 64 or w < 64:
            return (True, False, [])
        pmin, pmax = px.min(), px.max()
        if pmax - pmin < 1e-6:
            return (True, False, [])
        norm = ((px - pmin) / (pmax - pmin) * 255).astype(np.uint8)
        bands = [norm[: int(h * 0.12)], norm[int(h * 0.88):]]
        text_found, phi = False, []
        for band in bands:
            for img in (band, 255 - band):  # both text polarities
                txt = pytesseract.image_to_string(Image.fromarray(img))
                if txt and len(txt.strip()) >= 3:
                    text_found = True
                    for p, d in PHI_PATTERNS:
                        if re.search(p, txt) and d not in phi:
                            phi.append(d)
        return (True, text_found, phi)
    except Exception:
        return (True, False, [])


# ---------------------------------------------------------------------------
# Composite re-identification-risk score (the first-class "privacy pillar" output)
# ---------------------------------------------------------------------------

def _tag_has_data(ds, tag) -> bool:
    try:
        v = ds[tag].value
    except KeyError:
        return False
    if v is None:
        return False
    if isinstance(v, (str, bytes)) and len(v) == 0:
        return False
    if isinstance(v, pydicom.sequence.Sequence) and len(v) == 0:
        return False
    return len(str(v).strip()) > 0


def score_reidentification_risk(ds: pydicom.Dataset, use_ocr: bool = True) -> dict:
    """Composite, ORDINAL re-identification-risk score (0-100; NOT a calibrated probability).

    Aggregates four independent leakage channels so one number + band can gate a sharing pipeline:
      - residual structured identifiers (PS3.15 Basic Profile tags still populated),
      - identifiers in free text and private tags,
      - burned-in pixel text (header flag + edge heuristic, strengthened by OCR when available),
      - facial-geometry reconstructability for head CT/MR (the Mayo-2025 concern).

    Heuristic by design: it ranks/triages files, it does NOT certify de-identification. MINIMAL
    means none of the modeled channels fired (absence of evidence, not proof of safety).
    """
    crit = [t for t in CRITICAL_PHI_TAGS if _tag_has_data(ds, t)]
    other = [t for t in BASIC_PROFILE_TAGS
             if t not in CRITICAL_PHI_TAGS and _tag_has_data(ds, t)]
    struct = min(45, 18 * len(crit) + 3 * len(other))

    ft = any(f.severity == "warn" for f in check_free_text_phi(ds))
    pv = any(f.severity == "warn" for f in check_private_tags_phi(ds))
    text = min(22, (14 if ft else 0) + (10 if pv else 0))

    burned, bi_reason = 0, []
    if str(getattr(ds, "BurnedInAnnotation", "")).upper() == "YES":
        burned = max(burned, 18); bi_reason.append("BurnedInAnnotation=YES")
    if any(f.severity in ("warn", "fail") for f in check_burned_in_phi(ds)):
        burned = max(burned, 18); bi_reason.append("edge-text heuristic")
    ocr_av, ocr_text, ocr_phi = (_ocr_edge_phi(ds) if use_ocr else (False, False, []))
    if ocr_text:
        burned = max(burned, 20); bi_reason.append("OCR found edge text")
    if ocr_phi:
        burned = 25; bi_reason.append("OCR matched: " + ", ".join(ocr_phi))
    burned = min(25, burned)

    fg = check_facial_geometry(ds)
    fsev = max((f.severity for f in fg), key=lambda s: _SEV_RANK.get(s, 0)) if fg else "pass"
    face = {"fail": 30, "warn": 18, "info": 6}.get(fsev, 0)

    total = min(100, struct + text + burned + face)
    band = ("HIGH" if total >= 60 else "MODERATE" if total >= 25
            else "LOW" if total >= 1 else "MINIMAL")
    return {
        "score": total,
        "band": band,
        "dimensions": {
            "structured_identifiers": {
                "points": struct,
                "critical_tags": [f"{g:04X},{e:04X}" for g, e in crit],
                "other_profile_tags": len(other),
            },
            "text_identifiers": {"points": text, "free_text_phi": ft, "private_tag_phi": pv},
            "burned_in_pixels": {"points": burned, "reasons": bi_reason, "ocr_available": ocr_av},
            "facial_geometry": {"points": face, "severity": fsev,
                                "detail": "; ".join(f.message for f in fg)},
        },
        "note": "Ordinal triage score, not a probability. HIGH = multiple identifier channels "
                "remain; MINIMAL = none of the modeled channels fired (not a safety guarantee).",
    }


# ---------------------------------------------------------------------------
# Runner: execute all de-identification checks
# ---------------------------------------------------------------------------

def run_deid_checks(ds: pydicom.Dataset) -> list[Finding]:
    """Run all de-identification auditor checks and return combined findings."""
    findings = []
    for check_fn in (
        check_deid_profile_completeness,
        check_private_tags_phi,
        check_free_text_phi,
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
