"""
DicomLock — Finding class and severity definitions.

Shared across all scanner modules.
"""

from typing import Optional


# Severity levels (ordered by impact)
SEVERITIES = ("pass", "info", "warn", "fail", "critical")


class Finding:
    """A single finding from a scan check."""

    def __init__(self, check_name: str, severity: str, message: str, details: Optional[str] = None):
        if severity not in SEVERITIES:
            raise ValueError(f"Invalid severity '{severity}'. Must be one of {SEVERITIES}")
        self.check_name = check_name
        self.severity = severity
        self.message = message
        self.details = details

    def to_dict(self) -> dict:
        d = {
            "check": self.check_name,
            "severity": self.severity,
            "message": self.message,
        }
        if self.details:
            d["details"] = self.details
        return d

    def __repr__(self):
        return f"Finding({self.check_name!r}, {self.severity!r}, {self.message!r})"


def summarize(findings: list[dict]) -> dict:
    """Generate a summary from a list of finding dicts."""
    severity_counts = {"pass": 0, "info": 0, "warn": 0, "fail": 0, "critical": 0}
    for f in findings:
        sev = f.get("severity", "info")
        if sev in severity_counts:
            severity_counts[sev] += 1

    if severity_counts["critical"] > 0:
        score = "CRITICAL"
        trust = 0.0
    elif severity_counts["fail"] > 0:
        score = "FAIL"
        trust = 0.2
    elif severity_counts["warn"] > 2:
        score = "SUSPICIOUS"
        trust = 0.4
    elif severity_counts["warn"] > 0:
        score = "CAUTION"
        trust = 0.7
    else:
        score = "CLEAN"
        trust = 1.0

    return {
        "overall": score,
        "trust_score": trust,
        "counts": severity_counts,
        "total_checks": sum(severity_counts.values()),
    }
