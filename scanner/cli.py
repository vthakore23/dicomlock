#!/usr/bin/env python3
"""
DicomLock, command-line interface.

Usage:
    dicomlock <dicom_file_or_directory> [--disarm] [--deid]
    dicomlock samples/ct_sample.dcm
    dicomlock samples/ --disarm        (scan + disarm/quarantine every .dcm in a directory)
"""

import sys
import os
import json
import time
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
{C.DIM}  {SCANNER_VERSION}, DICOM file-security + CDR{C.RESET}
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


def _reid_descriptors(dims: dict) -> dict:
    """One short, human descriptor per channel: what actually fired."""
    out = {}
    s = dims.get("structured_identifiers", {})
    crit, other = len(s.get("critical_tags", [])), s.get("other_profile_tags", 0)
    out["structured_identifiers"] = (
        f"{crit} critical + {other} other profile tag(s) populated" if (crit or other)
        else "none populated")
    t = dims.get("text_identifiers", {})
    parts = ([("free-text PHI") ] if t.get("free_text_phi") else []) + \
            (["private-tag PHI"] if t.get("private_tag_phi") else [])
    out["text_identifiers"] = ", ".join(parts) if parts else "none detected"
    b = dims.get("burned_in_pixels", {})
    out["burned_in_pixels"] = "; ".join(b.get("reasons", [])) or "none detected"
    f = dims.get("facial_geometry", {})
    detail = f.get("detail", "") or f.get("severity", "")
    out["facial_geometry"] = (detail[:54] + "...") if len(detail) > 57 else (detail or "not a head scan")
    return out


def print_reid_risk(report: dict):
    """Print the composite re-identification-risk score (only present when --deid was used).

    First-class output: a colored score bar plus a per-channel breakdown of what fired, so a user can
    see at a glance which leakage channels (structured tags, free text, burned-in pixels, facial
    geometry) keep a file re-identifiable.
    """
    r = report.get("reid_risk")
    if not r:
        return
    band = r.get("band", "?")
    band_color = {
        "MINIMAL": C.GREEN, "LOW": C.GREEN, "MODERATE": C.YELLOW,
        "HIGH": C.BG_RED + C.WHITE, "ERROR": C.RED,
    }.get(band, C.WHITE)
    bar_color = (C.GREEN if band in ("MINIMAL", "LOW")
                 else C.YELLOW if band == "MODERATE" else C.RED)
    score = r.get("score")
    score_str = f"{score}/100" if isinstance(score, int) else "n/a"

    print(f"  {C.BOLD}RE-IDENTIFICATION RISK{C.RESET}  {band_color}{C.BOLD} {band} {C.RESET}  "
          f"(score {score_str})")
    if isinstance(score, int):
        width = 40
        filled = int(round(score / 100 * width))
        bar = "█" * filled + "░" * (width - filled)
        print(f"  {bar_color}{bar}{C.RESET}  {score_str}")

    dims = r.get("dimensions") or {}
    desc = _reid_descriptors(dims)
    labels = [
        ("structured_identifiers", "structured tags"),
        ("text_identifiers", "free text + private"),
        ("burned_in_pixels", "burned-in pixels"),
        ("facial_geometry", "facial geometry"),
    ]
    for key, label in labels:
        pts = dims.get(key, {}).get("points", 0)
        pts_color = C.DIM if pts == 0 else C.WHITE
        print(f"    {label:22s} {pts_color}{pts:>3} pts{C.RESET}  {C.DIM}{desc.get(key, '')}{C.RESET}")
    if r.get("note"):
        print(f"  {C.DIM}{r['note']}{C.RESET}")
    print()


def print_summary(reports: list, target_str: str, elapsed: float, do_disarm: bool):
    """Aggregate summary across a directory scan.

    Prints a verdict distribution, a finding-category prevalence over files that
    raised at least one warn/fail/critical, the disarm-action distribution if
    --disarm was set, and the path of every file that ended up FAIL or CRITICAL
    (so a researcher can find what to investigate). Skipped on single-file
    scans because the per-file report is already the summary there.
    """
    n = len(reports)
    if n <= 1:
        return

    # Verdict distribution across all files.
    verdict_counts: dict = {}
    for r in reports:
        v = r.get("summary", {}).get("overall", "UNKNOWN")
        verdict_counts[v] = verdict_counts.get(v, 0) + 1

    # For each finding category, count files that raised at least one warn/fail/critical
    # in that category (files-with, not raw findings-count, which is more useful).
    danger = {"warn", "fail", "critical"}
    cat_counts: dict = {}
    for r in reports:
        seen = set()
        for f in r.get("findings", []):
            if f.get("severity") in danger:
                c = f.get("check", "unknown")
                if c not in seen:
                    cat_counts[c] = cat_counts.get(c, 0) + 1
                    seen.add(c)

    # Disarm action distribution.
    action_counts: dict = {}
    if do_disarm:
        for r in reports:
            a = (r.get("action") or {}).get("action", "scanned")
            action_counts[a] = action_counts.get(a, 0) + 1

    # Header block.
    print()
    print(f"  {C.BOLD}Scan complete.{C.RESET}")
    print(f"    {C.DIM}files scanned    {C.RESET} {n}")
    print(f"    {C.DIM}target           {C.RESET} {target_str}")
    print(f"    {C.DIM}elapsed          {C.RESET} {elapsed:.2f} s")
    if elapsed > 0:
        print(f"    {C.DIM}throughput       {C.RESET} {n / elapsed:.1f} files/sec")

    # Verdict block.
    print(f"\n  {C.BOLD}Verdicts{C.RESET}")
    for v in ("CLEAN", "CAUTION", "SUSPICIOUS", "FAIL", "CRITICAL"):
        c = verdict_counts.get(v, 0)
        if c == 0:
            continue
        color = SCORE_DISPLAY.get(v, (C.WHITE, v))[0]
        pct = 100 * c / n
        print(f"    {color} {v:<10} {C.RESET} {c:>6}  ({pct:5.1f}%)")
    # Catch any unknown verdicts we did not whitelist above.
    for v, c in verdict_counts.items():
        if v in ("CLEAN", "CAUTION", "SUSPICIOUS", "FAIL", "CRITICAL"):
            continue
        pct = 100 * c / n
        print(f"    {C.DIM} {v:<10} {C.RESET} {c:>6}  ({pct:5.1f}%)")

    # Disarm action block.
    if do_disarm and action_counts:
        print(f"\n  {C.BOLD}Disarm actions{C.RESET}")
        color_for = {"clean": C.GREEN, "disarmed": C.GREEN, "quarantined": C.RED}
        for a in ("clean", "disarmed", "quarantined"):
            c = action_counts.get(a, 0)
            if c == 0:
                continue
            color = color_for.get(a, C.WHITE)
            pct = 100 * c / n
            print(f"    {color}{a:<14}{C.RESET} {c:>6}  ({pct:5.1f}%)")
        for a, c in action_counts.items():
            if a in ("clean", "disarmed", "quarantined"):
                continue
            pct = 100 * c / n
            print(f"    {C.DIM}{a:<14}{C.RESET} {c:>6}  ({pct:5.1f}%)")

    # Finding categories (files-with, not raw count).
    if cat_counts:
        print(f"\n  {C.BOLD}Finding categories (files with at least one warn/fail/critical){C.RESET}")
        for cat, c in sorted(cat_counts.items(), key=lambda kv: -kv[1])[:10]:
            pct = 100 * c / n
            print(f"    {cat:<28} {c:>6}  ({pct:5.1f}%)")

    # Investigate-these block: every file with a blocking verdict, with its path.
    dangerous = [
        r for r in reports
        if r.get("summary", {}).get("overall") in ("FAIL", "CRITICAL")
    ]
    if dangerous:
        show_n = min(20, len(dangerous))
        print(f"\n  {C.BOLD}Files flagged dangerous (showing {show_n} of {len(dangerous)}){C.RESET}")
        for r in dangerous[:show_n]:
            v = r.get("summary", {}).get("overall", "?")
            color = SCORE_DISPLAY.get(v, (C.WHITE, v))[0]
            path = r.get("file") or r.get("filename") or "?"
            print(f"    {color} {v:<8} {C.RESET} {path}")

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
        print(f"  {C.DIM}No disarm needed, already clean.{C.RESET}\n")


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

    # Scan (and optionally disarm) each file. Track wall time for the summary.
    reports = []
    t_start = time.perf_counter()
    for filepath in files:
        report = run_security_scan(str(filepath), run_deid=run_deid)
        print_report(report)
        print_reid_risk(report)
        if do_disarm:
            action = disarm_or_quarantine(str(filepath)) if is_dangerous(report) else {"action": "clean"}
            report["action"] = action
            print_action(action)
        reports.append(report)
    elapsed = time.perf_counter() - t_start

    # Aggregate summary on directory scans (skipped for single-file scans
    # because the per-file report is already the summary there).
    print_summary(reports, str(target), elapsed, do_disarm)

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
