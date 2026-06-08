"""Measure pre vs post-disarm file size across a directory of DICOM files.

The paper's Storage and bandwidth cost paragraph reports the ratios this script
produces. Usage:

    python -m bench.storage_cost --dir data/tcia_mr --label "brain MR" --cap 100

Disarms each file (writing to a temp directory so the source tree stays clean),
records input and output bytes, and reports the aggregate ratio plus the
per-file median and p90.
"""
import argparse
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from scanner.disarm import disarm


def measure(label: str, d: Path, cap: int | None = None) -> None:
    if not d.exists():
        print(f"{label}: dir missing")
        return
    files = sorted(d.glob("*.dcm"))
    if cap:
        files = files[:cap]
    if not files:
        print(f"{label}: no .dcm files in {d}")
        return
    in_tot = 0
    out_tot = 0
    n_clean = 0
    n_quar = 0
    ratios = []
    with tempfile.TemporaryDirectory() as td:
        for i, p in enumerate(files):
            try:
                in_sz = p.stat().st_size
                op = os.path.join(td, f"{i}.dcm")
                res = disarm(str(p), out_path=op)
                if getattr(res, "out_path", None) and os.path.exists(res.out_path):
                    out_sz = os.path.getsize(res.out_path)
                    in_tot += in_sz
                    out_tot += out_sz
                    ratios.append(out_sz / in_sz if in_sz else 0)
                    n_clean += 1
                    os.unlink(res.out_path)
                else:
                    n_quar += 1
            except Exception:
                n_quar += 1
    if n_clean == 0:
        print(f"{label}: 0 disarmed, {n_quar} quarantined or error")
        return
    ratios.sort()
    med = ratios[len(ratios) // 2]
    p90 = ratios[int(len(ratios) * 0.9)] if len(ratios) > 9 else ratios[-1]
    print(
        f"{label}: n_disarmed={n_clean} n_quarantine={n_quar}  "
        f"in={in_tot/1024/1024:.1f} MiB  out={out_tot/1024/1024:.1f} MiB  "
        f"aggregate={out_tot/in_tot:.2f}x  median_per_file={med:.2f}x  p90={p90:.2f}x"
    )


def main() -> None:
    ap = argparse.ArgumentParser(description="Measure CDR storage cost on a directory.")
    ap.add_argument("--dir", required=True, help="Directory of .dcm files.")
    ap.add_argument("--label", default="dataset", help="Label for the report row.")
    ap.add_argument("--cap", type=int, default=None, help="Cap to first N files (default all).")
    args = ap.parse_args()
    measure(args.label, Path(args.dir).expanduser(), cap=args.cap)


if __name__ == "__main__":
    main()
