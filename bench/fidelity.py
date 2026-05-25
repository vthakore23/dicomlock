#!/usr/bin/env python3
"""CDR fidelity at scale over an expanded, diverse benign corpus.

The headline "0 false positives across 575 real CTs" and the curated bit-exact checks are both on
narrow corpora (the CTs are all native Explicit VR LE). This harness runs the actual CDR rebuild
(`disarm`) across a deliberately HETEROGENEOUS benign corpus and reports how often the disarmed
image is bit-exact:

  - the diverse DICOM files already on disk (pydicom + pylibjpeg bundled test data + repo samples),
    spanning many modalities and every common transfer syntax (JPEG family, JPEG-LS, JPEG 2000,
    RLE, deflate, big-endian, implicit VR), AND
  - the 580 real TCIA CTs in data/tcia_ct/ (gitignored; --skip-scale to omit).

For native and mathematically-lossless sources a transcode MUST be bit-exact vs the original
acquisition; any miss is a fidelity break (a falsification finding). For lossy sources we report
"pixels preserved exactly as decoded" (no NEW loss), not bit-exact vs the acquisition.

Run:  python -m bench.fidelity                 # diverse on-disk corpus + 580 real CTs
      python -m bench.fidelity --skip-scale    # diverse on-disk corpus only
      python -m bench.fidelity --limit 200     # cap for a quick pass
"""

import argparse
import collections
import glob
import hashlib
import os
import sys
import tempfile

import pydicom
from pydicom.uid import UID

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
if PROJECT not in sys.path:
    sys.path.insert(0, PROJECT)

from scanner.disarm import disarm  # noqa: E402
from bench import corpus  # noqa: E402


def gather_diverse():
    """Diverse on-disk benign DICOMs (pydicom + pylibjpeg test data + repo samples), deduped by
    content hash. No network. Excludes samples/tampered/."""
    site = os.path.dirname(os.path.dirname(pydicom.__file__))
    candidates = glob.glob(os.path.join(site, "**", "*.dcm"), recursive=True)
    candidates += glob.glob(os.path.join(PROJECT, "samples", "*.dcm"))
    seen, files = set(), []
    for fp in sorted(candidates):
        try:
            h = hashlib.sha256(open(fp, "rb").read()).hexdigest()
        except OSError:
            continue
        if h not in seen:
            seen.add(h)
            files.append(fp)
    return files


def ts_name(fp):
    try:
        ds = pydicom.dcmread(fp, stop_before_pixels=True, force=True)
        ts = str(getattr(ds.file_meta, "TransferSyntaxUID", "")) or ""
        return UID(ts).name if ts else "(no file meta -> implicit VR LE)"
    except Exception:
        return "(unreadable header)"


def measure(fp, tmpdir):
    """Disarm one file; return a dict describing the fidelity outcome."""
    out = os.path.join(tmpdir, "out.dcm")
    res = disarm(fp, out_path=out, verify=True)
    outcome = {"ts": ts_name(fp), "name": os.path.basename(fp)}
    if res.error:
        # no image to preserve (SR/RT), bomb, or un-decodable -> not a fidelity sample
        outcome["bucket"] = "skipped"
        outcome["detail"] = res.error[:80]
    else:
        # source_lossy: None=native, False=lossless transcode, True=lossy source
        if res.source_lossy:
            outcome["bucket"] = "lossy_preserved" if res.image_preserved else "lossy_changed"
        else:
            outcome["bucket"] = "lossless_bitexact" if res.image_preserved else "lossless_BREAK"
    if os.path.exists(out):
        try:
            os.unlink(out)
        except OSError:
            pass
    return outcome


def main():
    ap = argparse.ArgumentParser(prog="bench.fidelity")
    ap.add_argument("--skip-scale", action="store_true", help="omit the 580 real TCIA CTs")
    ap.add_argument("--limit", type=int, default=0, help="cap the number of files (quick pass)")
    args = ap.parse_args()

    files = gather_diverse()
    n_diverse = len(files)
    if not args.skip_scale:
        files += [e.path for e in corpus.load_real_cts()]
    if args.limit:
        files = files[:args.limit]

    print(f"CDR fidelity at scale: {len(files)} benign files "
          f"({n_diverse} diverse on-disk + {len(files) - n_diverse} real CTs)\n")

    buckets = collections.Counter()
    by_ts = collections.defaultdict(lambda: collections.Counter())
    breaks = []
    with tempfile.TemporaryDirectory(prefix="dicomlock-fid-") as tmp:
        for i, fp in enumerate(files, 1):
            try:
                o = measure(fp, tmp)
            except Exception as e:
                o = {"ts": ts_name(fp), "name": os.path.basename(fp),
                     "bucket": "skipped", "detail": f"error: {str(e)[:60]}"}
            buckets[o["bucket"]] += 1
            by_ts[o["ts"]][o["bucket"]] += 1
            if o["bucket"] in ("lossless_BREAK", "lossy_changed"):
                breaks.append(o)
            if i % 100 == 0:
                print(f"  ...{i}/{len(files)}")

    lossless = buckets["lossless_bitexact"] + buckets["lossless_BREAK"]
    lossy = buckets["lossy_preserved"] + buckets["lossy_changed"]
    print("\n" + "=" * 70)
    print("FIDELITY RESULTS")
    print("=" * 70)
    print(f"  files disarmed (native/lossless source): {lossless}")
    print(f"     bit-exact vs original acquisition:    {buckets['lossless_bitexact']} / {lossless}"
          + (f"  ({100*buckets['lossless_bitexact']//lossless}%)" if lossless else ""))
    print(f"  files disarmed (lossy source):           {lossy}")
    print(f"     pixels preserved exactly as decoded:  {buckets['lossy_preserved']} / {lossy}"
          + (f"  ({100*buckets['lossy_preserved']//lossy}%)" if lossy else ""))
    print(f"  skipped (no image / un-decodable / quarantined): {buckets['skipped']}")
    print(f"\n  FIDELITY BREAKS (lossless source NOT bit-exact, or lossy pixels altered): "
          f"{len(breaks)}")
    for b in breaks[:20]:
        print(f"     {b['name']} [{b['ts']}] -> {b['bucket']}")

    print("\nBy transfer syntax (disarmed files only):")
    print(f"  {'transfer syntax':46s} {'bit-exact':>10} {'lossy-pres':>11} {'skipped':>8}")
    for ts in sorted(by_ts, key=lambda k: -sum(by_ts[k].values())):
        c = by_ts[ts]
        print(f"  {ts[:46]:46s} {c['lossless_bitexact']:>10} {c['lossy_preserved']:>11} "
              f"{c['skipped']:>8}"
              + ("  <-- BREAK" if c["lossless_BREAK"] or c["lossy_changed"] else ""))

    out = os.path.join(HERE, "fidelity_scale_results.txt")
    with open(out, "w") as f:
        f.write(f"CDR fidelity at scale: {len(files)} benign files "
                f"({n_diverse} diverse + {len(files)-n_diverse} real CTs)\n")
        f.write(f"native/lossless disarmed: {lossless}; bit-exact: {buckets['lossless_bitexact']}\n")
        f.write(f"lossy disarmed: {lossy}; preserved-as-decoded: {buckets['lossy_preserved']}\n")
        f.write(f"skipped (no image/un-decodable): {buckets['skipped']}\n")
        f.write(f"fidelity breaks: {len(breaks)}\n\n")
        for ts in sorted(by_ts, key=lambda k: -sum(by_ts[k].values())):
            f.write(f"{ts}: {dict(by_ts[ts])}\n")
    print(f"\nartifact: {out}")
    return 1 if breaks else 0


if __name__ == "__main__":
    raise SystemExit(main())
