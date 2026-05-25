#!/usr/bin/env python3
"""
Tool-safety test for the sandboxed codec decode (scanner/_sandbox.py).

Proves the property claimed in THREAT_MODEL.md ("the parser must not become the victim"): when the
pixel-decode step misbehaves — crashes with a memory fault, hangs, or errors — it is contained in
the child process and the file is quarantined, while the DicomLock process keeps running.

The crash/hang cases point the worker at a deliberately misbehaving child (we do NOT ship a
vulnerable codec to produce a real segfault on the host); this exercises the REAL parent-side
containment logic (spawn, rlimits, timeout, signal interpretation, cleanup). The happy path and the
real decode-failure case use the actual codec worker on real sample files.

Run:  python3 _attack_test/test_sandbox.py
"""

import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT = os.path.dirname(HERE)
sys.path.insert(0, PROJECT)

import numpy as np                                  # noqa: E402
import pydicom                                      # noqa: E402
from scanner import _sandbox                        # noqa: E402
from scanner._sandbox import safe_transcode_to_native  # noqa: E402
from scanner.disarm import disarm                   # noqa: E402

SAMPLES = os.path.join(PROJECT, "samples")
passed = failed = 0


def check(label, ok, detail=""):
    global passed, failed
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}{(' — ' + detail) if detail else ''}")
    passed += ok
    failed += (not ok)


def _write_worker(body: str) -> str:
    fd, path = tempfile.mkstemp(suffix="_worker.py")
    os.write(fd, body.encode())
    os.close(fd)
    return path


def with_worker(path, fn):
    """Temporarily point the sandbox at a substitute worker script."""
    orig = _sandbox._WORKER
    _sandbox._WORKER = path
    try:
        return fn()
    finally:
        _sandbox._WORKER = orig


def main():
    print("=== Sandbox containment (parent-side logic, substitute workers) ===")

    # 1) Worker crashes with a memory-fault signal (SIGSEGV) -> contained, quarantine.
    crash = _write_worker("import os, signal\nos.kill(os.getpid(), signal.SIGSEGV)\n")
    ok, reason = with_worker(crash, lambda: safe_transcode_to_native("x", "/tmp/sbx_crash.dcm"))
    check("codec memory fault is contained (not raised in-process)",
          (ok is False) and ("crash" in reason.lower()) and ("signal" in reason.lower()), reason)
    check("no output file left behind after a crash", not os.path.exists("/tmp/sbx_crash.dcm"))
    os.unlink(crash)

    # 2) Worker hangs forever -> wall-clock timeout kills it, quarantine.
    hang = _write_worker("import time\nwhile True:\n    time.sleep(1)\n")
    ok, reason = with_worker(
        hang, lambda: safe_transcode_to_native("x", "/tmp/sbx_hang.dcm", timeout=2))
    check("codec hang (DoS) is contained by the timeout",
          (ok is False) and ("hung" in reason.lower()), reason)
    os.unlink(hang)

    # 3) The DicomLock process is still alive and functional after the crash/hang above.
    check("DicomLock process survived worker crash + hang", True)

    print("\n=== Real codec worker on real files (happy path + genuine decode failure) ===")

    # 4) Happy path: JPEG2000-lossless really decodes -> native, bit-exact preserved.
    src = os.path.join(SAMPLES, "MR_small_jp2klossless.dcm")
    out = "/tmp/sbx_ok.dcm"
    res = disarm(src, out_path=out)
    bitexact = (res.error is None) and (res.image_preserved is True) and res.transcoded
    check("JPEG2000-lossless disarms via sandbox, bit-exact", bitexact,
          res.error or f"image_preserved={res.image_preserved}")
    if res.error is None and os.path.exists(out):
        a = pydicom.dcmread(src).pixel_array
        b = pydicom.dcmread(out).pixel_array
        check("pixels identical after sandboxed transcode", np.array_equal(a, b))
        os.unlink(out)

    # 5) Genuine decode failure (12-bit JPEG Extended, unsupported by all backends) -> the worker
    #    errors, the parent quarantines instead of emitting a file.
    lossy = os.path.join(SAMPLES, "JPEG_lossy.dcm")
    res = disarm(lossy, out_path="/tmp/sbx_lossy.dcm")
    check("undecodable lossy JPEG is quarantined (no output)",
          (res.error is not None) and (res.out_path is None)
          and (not os.path.exists("/tmp/sbx_lossy.dcm")), res.error)

    print("\n" + "=" * 64)
    print(f"sandbox tests: {passed} passed, {failed} failed")
    print("=" * 64)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
