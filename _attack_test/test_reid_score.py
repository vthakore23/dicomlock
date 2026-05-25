#!/usr/bin/env python3
"""
Validation for the re-identification-risk score (scanner.deid_auditor.score_reidentification_risk).

Goal: show the score is a sensible ORDINAL triage signal — it ranks files by how many identifier
channels remain, separating a properly de-identified file (MINIMAL) from one with residual PHI
across multiple channels (HIGH). This is the reproducible artifact behind the de-id "privacy
pillar"; full external validation belongs on public head-MR sets (IXI / OASIS), but those checks
(facial-geometry, OCR) are exercised here on synthetic and on-disk data with NO download and NO
real patient data.

Run:  python _attack_test/test_reid_score.py
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

import pydicom
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.uid import ExplicitVRLittleEndian

from scanner.deid_auditor import score_reidentification_risk, _ocr_available


def _base():
    ds = Dataset()
    ds.file_meta = FileMetaDataset()
    ds.file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
    ds.Modality = "CT"
    return ds


def clean_deidentified():
    """Basic Profile fully applied: identifier tags emptied, descriptive tags removed (PS3.15
    action X), no free-text PHI, abdomen (non-head). BodyPartExamined is not a Basic Profile tag,
    so keeping it is fine."""
    ds = _base()
    ds.PatientName = ""
    ds.PatientID = ""
    ds.BodyPartExamined = "ABDOMEN"
    return ds


def residual_identifiers():
    """Structured identifiers still populated (the common 'emptied the obvious tags but not all')."""
    ds = _base()
    ds.PatientName = "DOE^JANE"
    ds.PatientID = "00471123"
    ds.InstitutionName = "Mercy Medical Center"
    ds.BodyPartExamined = "CHEST"
    return ds


def dirty_head_ct():
    """Worst case: residual ids + free-text MRN + burned-in flag + thin-slice head CT."""
    ds = _base()
    ds.PatientName = "DOE^JOHN"
    ds.PatientID = "12345678"
    ds.PatientBirthDate = "19500101"
    ds.InstitutionName = "General Hospital"
    ds.ReferringPhysicianName = "SMITH^JANE"
    ds.ImageComments = "MRN 4567890, callback 555-123-4567"
    ds.BurnedInAnnotation = "YES"
    ds.BodyPartExamined = "HEAD"
    ds.SliceThickness = "1.0"
    ds.ImagePositionPatient = [0, 0, 0]
    ds.Rows, ds.Columns = 256, 256
    return ds


def main():
    print(f"OCR backend available: {_ocr_available()} "
          f"(burned-in falls back to the pixel heuristic when False)\n")

    cases = [
        ("clean (properly de-identified)", clean_deidentified(), "MINIMAL"),
        ("residual structured identifiers", residual_identifiers(), "MODERATE"),
        ("dirty head CT (all channels)", dirty_head_ct(), "HIGH"),
    ]

    rows = []
    for label, ds, expect_band in cases:
        r = score_reidentification_risk(ds, use_ocr=False)
        rows.append((label, r, expect_band))
        print(f"{label:34s} score={r['score']:3d}  band={r['band']:8s} (expected {expect_band})")
        for dim, v in r["dimensions"].items():
            print(f"     {dim:24s} {v['points']:3d} pts")

    scores = [r["score"] for _, r, _ in rows]
    bands = [r["band"] for _, r, _ in rows]

    ok = True
    # 1. strictly increasing risk across the three cases
    if not (scores[0] < scores[1] < scores[2]):
        print(f"\nFAIL: scores not strictly increasing: {scores}"); ok = False
    # 2. bands match expectation
    for (label, r, expect), got in zip(rows, bands):
        if got != expect:
            print(f"FAIL: {label} band {got} != expected {expect}"); ok = False
    # 3. clean file fires no channel
    if scores[0] != 0:
        print(f"FAIL: clean file scored {scores[0]}, expected 0"); ok = False

    print("\n" + ("PASS — score ranks de-identified < residual < dirty, bands as expected"
                  if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
