#!/usr/bin/env python3
"""
DicomLock — command-line interface.

Usage:
    dicomlock <dicom_file_or_directory> [--disarm] [--deid]
    dicomlock samples/ct_sample.dcm
    dicomlock samples/ --disarm        (scan + disarm/quarantine every .dcm in a directory)
"""

import sys
import os
import json
from pathlib import Path

from scanner.pipeline import (
    run_security_scan,
    disarm_or_quarantine,
    is_dangerous,
    SCANNER_VERSION,
)


# ANSI colors for terminal output
class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE = "\033[97m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"


SEVERITY_COLORS = {
    "pass": C.GREEN,
    "info": C.CYAN,
    "warn": C.YELLOW,
    "fail": C.RED,
    "critical": C.BG_RED + C.WHITE,
}

SEVERITY_ICONS = {
    "pass": "  PASS  ",
    "info": "  INFO  ",
    "warn": "  WARN  ",
    "fail": "  FAIL  ",
    "critical": " CRIT!! ",
}

SCORE_DISPLAY = {
    "CLEAN": (C.GREEN, "CLEAN"),
    "CAUTION": (C.YELLOW, "CAUTION"),
    "SUSPICIOUS": (C.YELLOW, "SUSPICIOUS"),
    "FAIL": (C.RED, "FAIL"),
    "CRITICAL": (C.BG_RED + C.WHITE, "CRITICAL"),
}


def print_banner():
    print(f"""
{C.CYAN}{C.BOLD}  ____  _                 _                _
 |  _ \\(_) ___ ___  _ __ | |    ___   ___| | __
 | | | | |/ __/ _ \\| '_ \\| |   / _ \\ / __| |/ /
 | |_| | | (_| (_) | | | | |__| (_) | (__|   <
 |____/|_|\\___\\___/|_| |_|_____\\___/ \\___|_|\\_\\{C.RESET}
{C.DIM}  {SCANNER_VERSION} — DICOM file-security + CDR{C.RESET}
""")


def print_report(report: dict):
    """Pretty-print a scan report to the terminal."""
    summary = report["summary"]
    score_color, score_text = SCORE_DISPLAY.get(summary["overall"], (C.WHITE, summary["overall"]))

    # Header
    print(f"{C.BOLD}{'=' * 70}{C.RESET}")
    print(f"  {C.BOLD}File:{C.RESET}  {report['filename']}")
    print(f"  {C.BOLD}Size:{C.RESET}  {report['file_size']:,} bytes")
    print(f"  {C.BOLD}SHA256:{C.RESET} {report['sha256'][:32]}...")
    print(f"  {C.BOLD}Scanned:{C.RESET} {report['scan_time']}")
    print(f"{C.BOLD}{'=' * 70}{C.RESET}")
    print()

    # Trust Score
    trust = summary["trust_score"]
    bar_width = 40
    filled = int(trust * bar_width)
    bar = f"{'█' * filled}{'░' * (bar_width - filled)}"

    if trust >= 0.7:
        bar_color = C.GREEN
    elif trust >= 0.4:
        bar_color = C.YELLOW
    else:
        bar_color = C.RED

    print(f"  {C.BOLD}INTEGRITY SCORE{C.RESET}")
    print(f"  {bar_color}{bar}{C.RESET}  {score_color}{C.BOLD}{score_text}{C.RESET}  ({trust:.0%})")
    print()

    # Findings
    print(f"  {C.BOLD}FINDINGS{C.RESET}  ({summary['total_checks']} checks)")
    print(f"  {C.DIM}{'─' * 66}{C.RESET}")

    for finding in report["findings"]:
        sev = finding["severity"]
        color = SEVERITY_COLORS.get(sev, C.WHITE)
        icon = SEVERITY_ICONS.get(sev, "  ???  ")

        print(f"  {color}[{icon}]{C.RESET} {finding['message']}")

        if "details" in finding:
            details = finding["details"]
            indent = "              "
            words = details.split()
            line = indent
            for word in words:
                if len(line) + len(word) + 1 > 70:
                    print(f"{C.DIM}{line}{C.RESET}")
                    line = indent + word
                else:
                    line += (" " if line.strip() else "") + word
            if line.strip():
                print(f"{C.DIM}{line}{C.RESET}")

    print(f"  {C.DIM}{'─' * 66}{C.RESET}")

    # Summary counts
    counts = summary["counts"]
    print(f"\n  {C.GREEN}{counts['pass']} passed{C.RESET}  "
          f"{C.CYAN}{counts['info']} info{C.RESET}  "
          f"{C.YELLOW}{counts['warn']} warnings{C.RESET}  "
          f"{C.RED}{counts['fail']} failures{C.RESET}  "
          f"{C.BG_RED}{C.WHITE}{counts['critical']} critical{C.RESET}")
    print()


def print_reid_risk(report: dict):
    """Print the composite re-identification-risk score (only present when --deid was used)."""
    r = report.get("reid_risk")
    if not r:
        return
    band = r.get("band", "?")
    band_color = {
        "MINIMAL": C.GREEN, "LOW": C.CYAN, "MODERATE": C.YELLOW,
        "HIGH": C.BG_RED + C.WHITE, "ERROR": C.RED,
    }.get(band, C.WHITE)
    score = r.get("score")
    score_str = f"{score}/100" if isinstance(score, int) else "n/a"
    print(f"  {C.BOLD}RE-IDENTIFICATION RISK{C.RESET}  "
          f"{band_color}{C.BOLD} {band} {C.RESET}  (score {score_str})")
    for dim, v in (r.get("dimensions") or {}).items():
        label = dim.replace("_", " ")
        print(f"    {C.DIM}{label:26s}{C.RESET} {v.get('points', 0):>3} pts")
    if r.get("note"):
        print(f"  {C.DIM}{r['note']}{C.RESET}")
    print()


def print_action(action: dict):
    """Print the disarm / quarantine outcome."""
    if not action:
        return
    a = action.get("action")
    if a == "disarmed":
        print(f"  {C.GREEN}{C.BOLD}DISARMED{C.RESET} → {action['output']}")
        for ch in action.get("changes", []):
            print(f"    {C.DIM}- {ch}{C.RESET}")
        ip = action.get("image_preserved")
        tag = "bit-exact" if ip else ("not verified" if ip is None else "CHANGED")
        print(f"    {C.DIM}image: {tag}{C.RESET}\n")
    elif a == "quarantined":
        print(f"  {C.BG_RED}{C.WHITE}{C.BOLD} QUARANTINED {C.RESET} cannot safely disarm")
        print(f"    {C.DIM}{action.get('reason', '')}{C.RESET}\n")
    elif a == "clean":
        print(f"  {C.DIM}No disarm needed — already clean.{C.RESET}\n")


def main():
    print_banner()

    args = sys.argv[1:]
    do_disarm = "--disarm" in args
    run_deid = "--deid" in args
    positional = [a for a in args if not a.startswith("--")]

    if not positional:
        print(f"  {C.YELLOW}Usage:{C.RESET} dicomlock <dicom_file_or_directory> [--disarm] [--deid]")
        print(f"  {C.DIM}--disarm  rebuild dangerous files clean, or quarantine the un-fixable{C.RESET}")
        print(f"  {C.DIM}--deid    also run the PHI / de-identification audit{C.RESET}")
        print()
        sys.exit(1)

    target = positional[0]

    # Collect files
    if os.path.isdir(target):
        files = sorted(Path(target).glob("**/*.dcm"))
        if not files:
            print(f"  {C.RED}No .dcm files found in {target}{C.RESET}")
            sys.exit(1)
        print(f"  {C.CYAN}Found {len(files)} DICOM file(s) in {target}{C.RESET}\n")
    elif os.path.isfile(target):
        files = [Path(target)]
    else:
        print(f"  {C.RED}File not found: {target}{C.RESET}")
        sys.exit(1)

    # Scan (and optionally disarm) each file
    reports = []
    for filepath in files:
        report = run_security_scan(str(filepath), run_deid=run_deid)
        print_report(report)
        print_reid_risk(report)
        if do_disarm:
            action = disarm_or_quarantine(str(filepath)) if is_dangerous(report) else {"action": "clean"}
            report["action"] = action
            print_action(action)
        reports.append(report)

    # Save JSON reports
    if len(reports) == 1:
        json_path = str(files[0]).replace(".dcm", "_report.json")
    else:
        json_path = os.path.join(str(target), "dicomlock_report.json")

    with open(json_path, "w") as f:
        json.dump(reports if len(reports) > 1 else reports[0], f, indent=2)

    print(f"  {C.DIM}Report saved: {json_path}{C.RESET}\n")


if __name__ == "__main__":
    main()
