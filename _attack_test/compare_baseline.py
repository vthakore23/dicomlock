#!/usr/bin/env python3
"""
Differentiation test (hardened): does DicomLock catch what the STANDARD tools miss?

Baselines (the software hospitals/AI pipelines actually run):
  - pydicom   : the Python DICOM parser nearly every imaging-AI tool is built on
  - GDCM      : an independent C++ DICOM toolkit (itself a CVE-bearing library)
  - dcmdump   : dcmtk's parser/dumper (does it parse — or crash/hang?)
  - dciodvfy  : dcmtk's DICOM CONFORMANCE validator (the closest thing to a checker)

None of these is a security tool. The point: parsers READ, validators check CONFORMANCE —
neither DEFENDS. DicomLock flags each attack by an exact security rule.
"""

import glob
import os
import shutil
import subprocess
import sys

import pydicom

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
sys.path.insert(0, PROJECT)

from scanner.file_security import (  # noqa: E402
    check_preamble, check_length_amplification,
    check_sequence_depth, check_pixel_dimension_bomb, check_private_tag_payloads,
)
from scanner.codec_cve import check_codec_cve_exposure  # noqa: E402

ORDER = {"pass": 0, "info": 1, "warn": 2, "fail": 3, "critical": 4}

# GDCM (optional)
try:
    import gdcm
    gdcm.Trace.WarningOff()
    gdcm.Trace.ErrorOff()
    gdcm.Trace.DebugOff()
    HAVE_GDCM = True
except Exception:
    HAVE_GDCM = False


def _tool(name):
    """Resolve a CLI tool from PATH or the anaconda bin dir."""
    p = shutil.which(name)
    if p:
        return p
    cand = os.path.join("/opt/anaconda3/bin", name)
    return cand if os.path.exists(cand) else None


DCMDUMP = _tool("dcmdump")
DCIODVFY = _tool("dciodvfy")


def pydicom_v(fp):
    try:
        pydicom.dcmread(fp, force=True)
        return "ACCEPTED (parsed, no warning)"
    except Exception as e:
        return f"raised {type(e).__name__}"


def gdcm_v(fp):
    if not HAVE_GDCM:
        return "n/a"
    try:
        r = gdcm.Reader()
        r.SetFileName(fp)
        return "ACCEPTED (Read=True)" if r.Read() else "read-failed (parse error, not a security flag)"
    except Exception as e:
        return f"err {type(e).__name__}"


def dcmdump_v(fp):
    if not DCMDUMP:
        return "n/a"
    try:
        p = subprocess.run([DCMDUMP, fp], capture_output=True, text=True, timeout=15)
        return "parsed OK (exit 0)" if p.returncode == 0 else f"exit {p.returncode} (parse error)"
    except subprocess.TimeoutExpired:
        return "TIMEOUT/hang (DoS!)"
    except Exception as e:
        return f"err {type(e).__name__}"


def dciodvfy_v(fp):
    if not DCIODVFY:
        return "n/a"
    try:
        p = subprocess.run([DCIODVFY, fp], capture_output=True, text=True, timeout=15)
        out = p.stdout + p.stderr
        errs = out.count("Error")
        warns = out.count("Warning")
        return f"conformance only: {errs} errors / {warns} warnings (no security concept)"
    except subprocess.TimeoutExpired:
        return "TIMEOUT/hang (DoS!)"
    except Exception as e:
        return f"err {type(e).__name__}"


def dicomlock_v(fp):
    findings = list(check_preamble(fp)) + list(check_length_amplification(fp))
    try:
        ds = pydicom.dcmread(fp, force=True)
        findings += check_sequence_depth(ds)
        findings += check_pixel_dimension_bomb(ds)
        findings += check_private_tag_payloads(ds)
        findings += check_codec_cve_exposure(ds)
    except Exception:
        pass
    # Report the worst signal DicomLock raises. warn = codec/SSRF EXPOSURE (still more than any
    # parser says); fail/critical = an attack blocked outright.
    flagged = [f for f in findings if f.severity in ("warn", "fail", "critical")]
    if not flagged:
        return "pass"
    f = max(flagged, key=lambda f: ORDER[f.severity])
    return f"{f.severity.upper()} — {f.message}"


def main():
    print(f"GDCM: {'available' if HAVE_GDCM else 'MISSING'} | "
          f"dcmdump: {'available' if DCMDUMP else 'MISSING'} | "
          f"dciodvfy: {'available' if DCIODVFY else 'MISSING'}\n")
    files = sorted(glob.glob(os.path.join(PROJECT, "samples", "tampered", "*.dcm")))
    for fp in files:
        name = os.path.basename(fp)
        print(name)
        print(f"   pydicom : {pydicom_v(fp)}")
        print(f"   GDCM    : {gdcm_v(fp)}")
        print(f"   dcmdump : {dcmdump_v(fp)}")
        print(f"   dciodvfy: {dciodvfy_v(fp)}")
        print(f"   ==> DicomLock: {dicomlock_v(fp)}")
        print()
    print("Parsers READ, the validator checks CONFORMANCE — none DEFEND. That is the gap.")


if __name__ == "__main__":
    main()
