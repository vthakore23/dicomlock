"""Sandboxed matrix of real DICOM parsers/codecs.

Each target parses AND decodes pixels in a resource-limited subprocess, so a C-level fault
(segfault / OOM kill) or a hang is observable as a process signal/timeout rather than swallowed
by an in-process try/except. This is what makes "the parser crashed" a measurable outcome.

Outcomes (normalized):
  clean      exit 0                     parsed + decoded cleanly
  rejected   exit 1 (refused)           parser declined it (a SAFE outcome)
  crash(sigN) killed by signal          the memory-safety bug class the CVEs represent
  hang       wall-clock timeout         denial of service
  dos(pre-identified)                   DicomLock flagged an alloc/decompression/length bomb;
                                        NOT executed raw (pre-parse rejection is the defense)
  n/a        target binary absent

Add a pinned-vulnerable target (e.g. OpenJPEG 2.3.0 + ASan from _attack_test/aim3/) to TARGETS to
turn the codec-exposure rows into real crash observations.
"""

import os
import shutil
import subprocess
import sys

import pydicom

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
if PROJECT not in sys.path:
    sys.path.insert(0, PROJECT)

from scanner.file_security import check_length_amplification, check_pixel_dimension_bomb  # noqa: E402

TIMEOUT_S = 15
MEM_LIMIT_BYTES = 2 * 1024 ** 3  # 2 GiB rlimit per worker so a bomb can't take down the host

_PYDICOM_WORKER = (
    "import sys,pydicom; ds=pydicom.dcmread(sys.argv[1],force=True); "
    "ds.pixel_array if 'PixelData' in ds else 0"
)
_GDCM_WORKER = (
    "import sys,gdcm; r=gdcm.ImageReader(); r.SetFileName(sys.argv[1]); "
    "sys.exit(0 if r.Read() else 1)"
)


def _limit():
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (MEM_LIMIT_BYTES, MEM_LIMIT_BYTES))
        resource.setrlimit(resource.RLIMIT_CPU, (TIMEOUT_S, TIMEOUT_S))
    except Exception:
        pass


def _discover():
    targets = [("pydicom", [sys.executable, "-c", _PYDICOM_WORKER, "{f}"])]
    try:
        import gdcm  # noqa: F401
        targets.append(("gdcm", [sys.executable, "-c", _GDCM_WORKER, "{f}"]))
    except ImportError:
        pass
    if shutil.which("dcmdump"):
        targets.append(("dcmtk", ["dcmdump", "{f}"]))
    return targets


TARGETS = _discover()
TARGET_NAMES = [name for name, _ in TARGETS]


def is_dos_bomb(fp):
    """DicomLock flags an allocation/decompression/length bomb -> do NOT decode it raw."""
    findings = list(check_length_amplification(fp))
    try:
        ds = pydicom.dcmread(fp, force=True)
        findings += list(check_pixel_dimension_bomb(ds))
    except Exception:
        pass
    return any(f.severity in ("fail", "critical") for f in findings)


def _run(argv_tmpl, fp):
    argv = [a.replace("{f}", fp) for a in argv_tmpl]
    try:
        p = subprocess.run(argv, capture_output=True, timeout=TIMEOUT_S, preexec_fn=_limit)
    except subprocess.TimeoutExpired:
        return "hang"
    except FileNotFoundError:
        return "n/a"
    if p.returncode == 0:
        return "clean"
    if p.returncode < 0:
        return f"crash(sig{-p.returncode})"
    return "rejected"


def run_matrix(fp, skip_raw_dos=True):
    """Run every target on a file. Returns {target_name: outcome}."""
    if skip_raw_dos and is_dos_bomb(fp):
        return {name: "dos(pre-identified)" for name in TARGET_NAMES}
    return {name: _run(argv, fp) for name, argv in TARGETS}


def is_dangerous(outcomes):
    """A target outcome set is dangerous if any target crashed, hung, or it was a DoS bomb."""
    return any(o.startswith("crash") or o == "hang" or o.startswith("dos")
               for o in outcomes.values())


def all_accept(outcomes):
    """True if every present target parsed the file as clean (the 'toolkits silently accept' case)."""
    present = [o for o in outcomes.values() if o != "n/a"]
    return bool(present) and all(o == "clean" for o in present)
