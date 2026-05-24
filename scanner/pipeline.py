"""
DicomLock — scan + disarm pipeline (shared by the CLI and the API).

run_security_scan()    : the DEFAULT security scan — file-security + metadata (+ optional
                         de-id). The legacy deepfake/pixel-forensics modules are intentionally
                         NOT in the default scan (they produced false alarms on clean files).
disarm_or_quarantine() : attempt to rebuild a clean file, then RE-SCAN the output and only
                         accept it if it is actually clean — otherwise quarantine. This means
                         we never emit a still-dangerous file.
"""

import os
from datetime import datetime

from scanner.findings import Finding, summarize
from scanner.ingest import ingest
from scanner.file_security import (
    check_preamble,
    check_length_amplification,
    check_sequence_depth,
    check_pixel_dimension_bomb,
    check_private_tag_payloads,
)
from scanner.codec_cve import check_codec_cve_exposure
from scanner.metadata import run_metadata_checks
from scanner.deid_auditor import run_deid_checks
from scanner.disarm import disarm

SCANNER_VERSION = "DicomLock v0.6.0"
_DANGER = {"fail", "critical"}


def run_security_scan(filepath: str, run_deid: bool = False) -> dict:
    """Default security scan: file-security + metadata (+ optional de-id audit)."""
    ingested = ingest(filepath)
    findings = []

    # File security (pre-parse, byte-level)
    findings += check_preamble(ingested.filepath)
    findings += check_length_amplification(ingested.filepath)

    if ingested.dataset is None:
        findings.append(Finding("file_read", "critical",
                                f"Failed to read DICOM file: {ingested.error}"))
    else:
        # File security (post-parse, dataset-level)
        findings += check_sequence_depth(ingested.dataset)
        findings += check_pixel_dimension_bomb(ingested.dataset)
        findings += check_private_tag_payloads(ingested.dataset)
        findings += check_codec_cve_exposure(ingested.dataset)
        # Metadata integrity
        findings += run_metadata_checks(ingested.dataset)
        # Optional privacy pillar
        if run_deid:
            findings += run_deid_checks(ingested.dataset)

    finding_dicts = [f.to_dict() for f in findings]
    return {
        "file": ingested.filepath,
        "filename": ingested.filename,
        "file_size": ingested.file_size,
        "sha256": ingested.sha256,
        "scanner": SCANNER_VERSION,
        "scan_time": datetime.now().isoformat(),
        "findings": finding_dicts,
        "summary": summarize(finding_dicts),
    }


def is_dangerous(report: dict) -> bool:
    """True if the scan produced any fail/critical finding."""
    return any(f["severity"] in _DANGER for f in report["findings"])


def disarm_or_quarantine(filepath: str, out_path: str = None) -> dict:
    """Disarm, then verify by re-scanning the output. Emit only if actually clean."""
    out_path = out_path or (os.path.splitext(filepath)[0] + ".disarmed.dcm")
    res = disarm(filepath, out_path=out_path)

    if res.error:
        return {"action": "quarantined", "reason": res.error, "output": None}

    # Verify: re-scan the disarmed output; never emit a still-dangerous file.
    rescan = run_security_scan(res.out_path)
    residual = [f["message"] for f in rescan["findings"] if f["severity"] in _DANGER]
    if residual:
        try:
            os.unlink(res.out_path)
        except OSError:
            pass
        return {"action": "quarantined",
                "reason": "disarm did not fully neutralize: " + "; ".join(residual),
                "output": None}

    return {"action": "disarmed", "output": res.out_path,
            "changes": res.changes, "image_preserved": res.image_preserved}
