"""The benchmark engine: per file, measure detection, neutralization, and fidelity.

For each corpus entry:
  1. DETECTION   run DicomLock's scan; record verdict (block / warn / clean)
  2. RAW DANGER  run the target matrix on the raw file (observable crash/hang) + DoS pre-ID
  3. CDR         disarm_or_quarantine()
  4. NEUTRALIZE  re-run the target matrix AND DicomLock's scan on the disarmed output.
                 Neutralized = it was quarantined (never reaches a parser) OR the rebuilt file
                 is clean to every target and to DicomLock.
  5. FIDELITY    bit-exact pixel comparison raw vs disarmed where both decode.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
if PROJECT not in sys.path:
    sys.path.insert(0, PROJECT)

from scanner.pipeline import run_security_scan, is_dangerous, disarm_or_quarantine  # noqa: E402
from bench import corpus, targets  # noqa: E402


def _dl_verdict(report):
    if is_dangerous(report):
        return "block"
    if any(f["severity"] == "warn" for f in report["findings"]):
        return "warn"
    return "clean"


def _detected(entry, verdict):
    if entry.expected_verdict == "clean":
        return verdict != "block"          # benign must not be blocked
    if entry.expected_verdict == "block":
        return verdict == "block"
    if entry.expected_verdict == "warn":
        return verdict in ("warn", "block")  # flagged, possibly stricter
    return False


def _fidelity(raw_fp, out_fp):
    try:
        import numpy as np
        import pydicom
        a = pydicom.dcmread(raw_fp, force=True)
        b = pydicom.dcmread(out_fp, force=True)
        if "PixelData" not in a or "PixelData" not in b:
            return "n/a"
        return "bit-exact" if np.array_equal(a.pixel_array, b.pixel_array) else "CHANGED"
    except Exception:
        return "n/a"


def evaluate_entry(entry, tmpdir):
    report = run_security_scan(entry.path)
    verdict = _dl_verdict(report)

    raw = targets.run_matrix(entry.path)
    raw_dangerous = targets.is_dangerous(raw)

    out = os.path.join(tmpdir, entry.name.replace(".dcm", ".clean.dcm"))
    action = disarm_or_quarantine(entry.path, out_path=out)["action"]

    post = {}
    fidelity = "n/a"
    post_clean = True
    if action == "disarmed" and os.path.exists(out):
        post = targets.run_matrix(out, skip_raw_dos=False)
        post_clean = (not targets.is_dangerous(post)) and (not is_dangerous(run_security_scan(out)))
        fidelity = _fidelity(entry.path, out)
        os.unlink(out)
    elif action == "quarantined":
        post_clean = True  # danger never reaches a parser

    neutralized = None
    if entry.intrinsic_danger:
        neutralized = (action == "quarantined") or post_clean

    return {
        "name": entry.name,
        "attack_class": entry.attack_class,
        "expected_verdict": entry.expected_verdict,
        "benign": entry.benign,
        "intrinsic_danger": entry.intrinsic_danger,
        "dl_verdict": verdict,
        "detected": _detected(entry, verdict),
        "false_positive": entry.benign and verdict == "block",
        "raw_outcomes": raw,
        "raw_dangerous": raw_dangerous,
        "toolkits_accept": targets.all_accept(raw),
        "cdr_action": action,
        "post_outcomes": post,
        "neutralized": neutralized,
        "fidelity": fidelity,
    }


def fp_scan(entry):
    """Fast scan-only evaluation for a large benign set (false positives at scale).

    Skips the target matrix and CDR (those are for the attack corpus). Returns the same dict
    shape as evaluate_entry so the report aggregator can treat it as a benign result.
    """
    verdict = _dl_verdict(run_security_scan(entry.path))
    return {
        "name": entry.name,
        "attack_class": entry.attack_class,
        "expected_verdict": entry.expected_verdict,
        "benign": entry.benign,
        "intrinsic_danger": False,
        "dl_verdict": verdict,
        "detected": verdict != "block",
        "false_positive": entry.benign and verdict == "block",
        "raw_outcomes": {},
        "raw_dangerous": False,
        "toolkits_accept": False,
        "cdr_action": "scan-only",
        "post_outcomes": {},
        "neutralized": None,
        "fidelity": "n/a",
    }


def evaluate_all(tmpdir, entries=None):
    entries = entries if entries is not None else corpus.load_all()
    return [evaluate_entry(e, tmpdir) for e in entries]


def scan_only(entries):
    return [fp_scan(e) for e in entries]
