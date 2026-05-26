"""
Performance benchmark for the DicomLock scanner and CDR engine.

Measures single-threaded wall time and throughput on representative real-clinical
DICOM files, plus peak resident memory. The scan path is what the CLI runs by
default; the disarm path adds the CDR rebuild (transcode plus re-scan) and is the
relevant number for a hostile-boundary deployment.

Usage:
    python -m bench.perf                              # data/tcia_ct, scan only
    python -m bench.perf --dir data/tcia_mr           # specific corpus (repeatable)
    python -m bench.perf --limit 200                  # cap files per directory
    python -m bench.perf --include-disarm             # also measure the CDR rebuild

The harness reports per-file wall time (mean, median, p95), throughput
(files/sec, MiB/sec), and peak resident memory. Disarm runs the codec sandbox in
a subprocess for encapsulated transfer syntaxes; the reported wall time includes
that subprocess overhead because that is the real production cost.
"""

from __future__ import annotations

import argparse
import glob
import os
import resource
import statistics
import sys
import tempfile
import time

# Resolve project root so this harness works whether run as `python -m bench.perf`
# from the repo root or invoked from elsewhere.
HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
if PROJECT not in sys.path:
    sys.path.insert(0, PROJECT)

from scanner import pipeline  # noqa: E402


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    k = (len(s) - 1) * p / 100.0
    lo = int(k)
    hi = min(lo + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def peak_rss_mib() -> float:
    """Peak resident set size since process start, in MiB."""
    r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Linux reports ru_maxrss in KiB; macOS reports it in bytes.
    if sys.platform == "darwin":
        return r / (1024 * 1024)
    return r / 1024


def measure(label: str, directory: str, limit: int, include_disarm: bool) -> dict | None:
    files = sorted(glob.glob(os.path.join(directory, "*.dcm")))
    if limit:
        files = files[:limit]
    if not files:
        print(f"\n(skipping {label}: no .dcm in {directory})")
        return None

    sizes = [os.path.getsize(f) for f in files]
    total_mib = sum(sizes) / (1024 * 1024)
    n = len(files)

    # Warm up. The first call pays import and Python-cache cost that has nothing
    # to do with the scanner's steady-state speed.
    pipeline.run_security_scan(files[0])

    scan_times: list[float] = []
    disarm_times: list[float] = []

    for f in files:
        t0 = time.perf_counter()
        pipeline.run_security_scan(f)
        scan_times.append(time.perf_counter() - t0)

    if include_disarm:
        for f in files:
            with tempfile.TemporaryDirectory() as td:
                out = os.path.join(td, "out.dcm")
                t0 = time.perf_counter()
                pipeline.disarm_or_quarantine(f, out_path=out)
                disarm_times.append(time.perf_counter() - t0)

    print(f"\n==============================================================================")
    print(f"{label}  ({n} files, {total_mib:.1f} MiB total)")
    print(f"==============================================================================")
    total_scan = sum(scan_times)
    print(f"  scan wall time per file:")
    print(f"    mean      {1000 * statistics.mean(scan_times):7.2f} ms")
    print(f"    median    {1000 * statistics.median(scan_times):7.2f} ms")
    print(f"    p95       {1000 * percentile(scan_times, 95):7.2f} ms")
    print(f"    total     {total_scan:7.2f} s")
    print(f"  scan throughput (single thread):")
    print(f"    files/sec {n / total_scan:7.1f}")
    print(f"    MiB/sec   {total_mib / total_scan:7.1f}")

    if include_disarm and disarm_times:
        total_disarm = sum(disarm_times)
        print(f"  disarm wall time per file (scan + CDR + re-scan):")
        print(f"    mean      {1000 * statistics.mean(disarm_times):7.2f} ms")
        print(f"    median    {1000 * statistics.median(disarm_times):7.2f} ms")
        print(f"    p95       {1000 * percentile(disarm_times, 95):7.2f} ms")
        print(f"    total     {total_disarm:7.2f} s")
        print(f"  disarm throughput (single thread):")
        print(f"    files/sec {n / total_disarm:7.1f}")
        print(f"    MiB/sec   {total_mib / total_disarm:7.1f}")

    return {
        "label": label,
        "directory": directory,
        "n": n,
        "total_mib": total_mib,
        "scan_times": scan_times,
        "disarm_times": disarm_times,
    }


# label, relative-path-from-PROJECT
DEFAULT_DIRS = [
    ("CT (chest, TCIA mixed)", os.path.join("data", "tcia_ct")),
]


def main() -> None:
    ap = argparse.ArgumentParser(prog="bench.perf")
    ap.add_argument("--dir", action="append", default=[],
                    help="extra directory of .dcm files (repeatable). Default is data/tcia_ct.")
    ap.add_argument("--label", action="append", default=[],
                    help="optional label paired positionally with --dir.")
    ap.add_argument("--limit", type=int, default=0,
                    help="cap files per directory (0 = all).")
    ap.add_argument("--include-disarm", action="store_true",
                    help="also measure the CDR rebuild path (slower; exercises codec sandbox).")
    args = ap.parse_args()

    dirs: list[tuple[str, str]]
    if args.dir:
        dirs = []
        for i, d in enumerate(args.dir):
            label = args.label[i] if i < len(args.label) else os.path.basename(d.rstrip("/"))
            path = d if os.path.isabs(d) else os.path.join(PROJECT, d)
            dirs.append((label, path))
    else:
        dirs = [(label, os.path.join(PROJECT, rel)) for label, rel in DEFAULT_DIRS]

    results = []
    t_wall_start = time.perf_counter()
    for label, path in dirs:
        r = measure(label, path, args.limit, args.include_disarm)
        if r is not None:
            results.append(r)
    t_wall_total = time.perf_counter() - t_wall_start

    # Cross-corpus summary.
    if results:
        total_n = sum(r["n"] for r in results)
        total_mib = sum(r["total_mib"] for r in results)
        total_scan = sum(sum(r["scan_times"]) for r in results)
        print(f"\n==============================================================================")
        print(f"SUMMARY  ({total_n} files across {len(results)} corpora, {total_mib:.1f} MiB total)")
        print(f"==============================================================================")
        print(f"  scan: {total_n / total_scan:.1f} files/sec, {total_mib / total_scan:.1f} MiB/sec")
        if args.include_disarm:
            total_disarm = sum(sum(r["disarm_times"]) for r in results)
            if total_disarm > 0:
                print(f"  disarm: {total_n / total_disarm:.1f} files/sec, "
                      f"{total_mib / total_disarm:.1f} MiB/sec")
        print(f"  peak resident memory across the run: {peak_rss_mib():.1f} MiB")
        print(f"  wall time end to end: {t_wall_total:.2f} s")

    out_path = os.path.join(HERE, "perf_results.txt")
    with open(out_path, "w") as f:
        for r in results:
            n, mib = r["n"], r["total_mib"]
            ts = sum(r["scan_times"])
            f.write(f"{r['label']}: n={n}, MiB={mib:.1f}, "
                    f"scan files/s={n/ts:.1f}, scan MiB/s={mib/ts:.1f}\n")
            if r["disarm_times"]:
                td = sum(r["disarm_times"])
                f.write(f"  disarm files/s={n/td:.1f}, disarm MiB/s={mib/td:.1f}\n")
    print(f"\nartifact: {out_path}")


if __name__ == "__main__":
    main()
