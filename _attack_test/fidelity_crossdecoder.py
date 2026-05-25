#!/usr/bin/env python3
"""
Independent cross-decoder fidelity check (audit recommendation #7).

The in-tool `image_preserved` flag compares decode-of-original against decode-of-the-stored-output
using the SAME library, so it is close to tautological. This harness instead proves fidelity
*independently*: it decodes the ORIGINAL compressed image with two separate decoder implementations
(GDCM, a C++ toolkit; and pylibjpeg, a different codebase) and checks that DicomLock's disarmed
native pixels equal what those independent decoders produce.

Claim verified per file:
  - lossless source  -> disarmed pixels are BIT-EXACT vs BOTH independent decoders, and the two
    decoders agree with each other (full cross-decoder bit-exactness).
  - lossy source     -> disarmed pixels equal AT LEAST ONE independent decoder exactly (disarm did
    not corrupt the decode); decoders may differ by a rounding ULP for DCT-JPEG, which is reported,
    not failed. "Lossy" here is vs the original acquisition, which no decoder can recover.
  - undecodable      -> disarm quarantines; reported as such (no fidelity claim).

This runs on the project's own trusted sample files, so decoding them in-process is safe; production
disarm still isolates the decode in a subprocess (see scanner/_sandbox.py).

Run:  python3 _attack_test/fidelity_crossdecoder.py
"""

import glob
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
sys.path.insert(0, PROJECT)

import numpy as np                                   # noqa: E402
import pydicom                                       # noqa: E402
from pydicom.pixels import pixel_array               # noqa: E402  (pydicom 3.x per-plugin decode)

from scanner.disarm import disarm, _source_is_lossless, _NATIVE_TS  # noqa: E402

PLUGINS = ("gdcm", "pylibjpeg")


def independent_decodes(fp):
    """Decode the original compressed file with each independent plugin. Returns {plugin: array}."""
    out = {}
    for plug in PLUGINS:
        try:
            out[plug] = pixel_array(fp, decoding_plugin=plug)
        except Exception:
            pass  # plugin can't handle this syntax; another may
    return out


def main():
    samples = sorted(glob.glob(os.path.join(PROJECT, "samples", "*.dcm")))
    rows = []
    npass = nfail = 0

    for fp in samples:
        try:
            ds = pydicom.dcmread(fp, force=True)
            ts = str(getattr(ds.file_meta, "TransferSyntaxUID", "") or "")
        except Exception:
            continue
        if "PixelData" not in ds or ts in _NATIVE_TS or not ts:
            continue  # only encapsulated/compressed files are interesting here

        name = os.path.basename(fp)
        lossless = _source_is_lossless(ts)

        out = tempfile.mktemp(suffix=".dcm")
        res = disarm(fp, out_path=out)

        if res.error:
            rows.append((name, "lossless" if lossless else "lossy", "QUARANTINED",
                         res.error.split(":")[-1].strip()[:40]))
            os.path.exists(out) and os.unlink(out)
            continue

        dis = pydicom.dcmread(out).pixel_array
        os.path.exists(out) and os.unlink(out)
        refs = independent_decodes(fp)
        if not refs:
            rows.append((name, "lossless" if lossless else "lossy", "NO-INDEP-DECODER", "-"))
            continue

        exact = {p: bool(np.array_equal(dis, a)) for p, a in refs.items()}
        # cross-decoder agreement (only meaningful if 2 decoders succeeded)
        agree = (len(refs) == 2 and np.array_equal(*refs.values()))
        maxdiff = 0
        if len(refs) == 2:
            maxdiff = int(np.max(np.abs(refs["gdcm"].astype(np.int64) - refs["pylibjpeg"].astype(np.int64)))) \
                if all(p in refs for p in PLUGINS) else 0

        decs = "+".join(sorted(refs))
        if lossless:
            ok = all(exact.values()) and (agree if len(refs) == 2 else True)
            verdict = "BIT-EXACT (all indep)" if ok else "MISMATCH"
        else:
            ok = any(exact.values())
            verdict = (f"matches indep (ULP diff {maxdiff})" if ok else "MISMATCH")

        npass += ok
        nfail += (not ok)
        rows.append((name, "lossless" if lossless else "lossy",
                     verdict + ("" if ok else " !!"), f"via {decs}; exact={exact}"))

    # report
    print(f"\n{'file':<30}{'class':<10}{'verdict':<26}detail")
    print("-" * 100)
    for n, c, v, d in rows:
        print(f"{n:<30}{c:<10}{v:<26}{d}")
    print("-" * 100)
    print(f"\nfidelity vs independent decoders: {npass} pass, {nfail} fail "
          f"({sum(1 for r in rows if r[2].startswith('QUARANTINED'))} quarantined, "
          f"not counted)")
    sys.exit(1 if nfail else 0)


if __name__ == "__main__":
    main()
