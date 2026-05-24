"""Locate packaged config data (codec-CVE map, vendor allowlist).

Resolves to scanner/data/<name> whether running from source or pip-installed. Falls back to a
project-root data/ dir so legacy/custom copies still work.
"""

import os

_HERE = os.path.dirname(os.path.abspath(__file__))


def data_file(name: str) -> str:
    candidates = [
        os.path.join(_HERE, "data", name),                       # packaged (canonical)
        os.path.join(os.path.dirname(_HERE), "data", name),      # project-root fallback
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return candidates[0]
