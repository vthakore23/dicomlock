"""
DicomLock — sandboxed pixel decode for CDR.

This is the ONE place DicomLock invokes a third-party image codec (libjpeg / OpenJPEG /
CharLS / OpenJPH / RLE) on untrusted bytes. Decoding compressed pixel data is the deep
memory-safety attack surface (the codec CVE class). We never run it in the tool's own process:
the decode happens in a resource-limited child process, so a codec segfault, OOM, or hang kills
the worker, and the caller quarantines the file instead of crashing the scanner.

This makes the "tool must not become the victim" property in THREAT_MODEL.md real rather than
just a deployment recommendation. Allocation/length/decompression bombs are still rejected by the
header-level checks BEFORE this worker is ever spawned; the rlimits here are defense in depth and
the timeout/signal handling is what contains a genuine codec memory fault.

The worker is invoked by file path (`python3 scanner/_sandbox.py <in> <out>`), so it has no
dependency on DicomLock's package imports and stays self-contained.
"""

import os
import subprocess
import sys

# A codec decode on real clinical data is fast (ms). A worker that needs more than this much
# wall-clock or memory is treating the input as hostile; we kill it and quarantine.
TIMEOUT_S = 30
MEM_LIMIT_BYTES = 2 * 1024 ** 3  # 2 GiB address-space cap per worker

# The child script the parent spawns. Module-level so a containment self-test can point it at a
# deliberately crashing/hanging worker without shipping a vulnerable codec (see test_sandbox.py).
_WORKER = os.path.abspath(__file__)


def _limit_resources():
    """Run in the child between fork and exec: cap address space + CPU time. Best-effort
    (RLIMIT_AS is weakly enforced on some platforms); the subprocess timeout and signal-exit
    detection below are the portable backstops for hang and crash."""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (MEM_LIMIT_BYTES, MEM_LIMIT_BYTES))
        resource.setrlimit(resource.RLIMIT_CPU, (TIMEOUT_S, TIMEOUT_S))
    except Exception:
        pass


def safe_transcode_to_native(in_path: str, out_path: str, timeout: int = TIMEOUT_S):
    """Decode `in_path` and rewrite it as native Explicit VR LE at `out_path`, in a sandboxed
    child process. Returns (ok: bool, reason: str).

    ok=False means the codec crashed, hung, exhausted memory, or otherwise failed — the file is
    NOT disarmable and the caller MUST quarantine it (we never trust a file whose decode
    misbehaved). ok=True means `out_path` is a clean native file the parent can safely re-open
    without ever invoking a codec again.
    """
    argv = [sys.executable, _WORKER, in_path, out_path]
    try:
        proc = subprocess.run(
            argv, capture_output=True, timeout=timeout,
            preexec_fn=_limit_resources if os.name == "posix" else None,
        )
    except subprocess.TimeoutExpired:
        _unlink(out_path)
        return False, f"sandboxed decode hung (> {timeout}s), denial-of-service codec input"

    if proc.returncode == 0 and os.path.exists(out_path) and os.path.getsize(out_path) > 0:
        return True, "ok"

    _unlink(out_path)
    if proc.returncode < 0:
        return False, (f"sandboxed decode crashed (killed by signal {-proc.returncode}): "
                       "codec memory fault; file quarantined")
    last = (proc.stderr.decode("utf-8", "ignore").strip().splitlines() or ["decode failed"])[-1]
    return False, f"sandboxed decode failed: {last[:200]}"


def _unlink(path: str):
    try:
        os.unlink(path)
    except OSError:
        pass


def _worker(in_path: str, out_path: str) -> int:
    """Child entry point: decode pixels (the dangerous codec call) and save native. Any failure
    exits non-zero so the parent quarantines; a memory fault exits via signal, also caught."""
    import pydicom
    from pydicom.uid import ExplicitVRLittleEndian

    ds = pydicom.dcmread(in_path, force=True)
    try:
        ds.decompress()  # primary path: decode + set TransferSyntaxUID = Explicit VR LE
    except Exception:
        # Fallback: decode to an array and store raw uncompressed.
        arr = ds.pixel_array
        ds.PixelData = arr.tobytes()
        ds.file_meta.TransferSyntaxUID = ExplicitVRLittleEndian
        ds["PixelData"].VR = "OW" if int(getattr(ds, "BitsAllocated", 16)) > 8 else "OB"

    try:
        ds.save_as(out_path)
    except TypeError:
        ds.save_as(out_path, enforce_file_format=False)
    return 0


if __name__ == "__main__":
    _limit_resources()
    sys.exit(_worker(sys.argv[1], sys.argv[2]))
