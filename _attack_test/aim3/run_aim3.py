#!/usr/bin/env python3
"""
Aim 3 — executed against a REAL pinned-vulnerable codec (not the inert corpus).

Runs inside the Docker image built by ./Dockerfile, which contains:
  - opj_decompress built from OpenJPEG v2.3.0 with AddressSanitizer  = the vulnerable TARGET
    (a stand-in for the OpenJPEG a slow-to-patch PACS/viewer routes JPEG2000 pixel data through)
  - DicomLock CDR using a MODERN, patched OpenJPEG bundled in pylibjpeg-openjpeg = the defense

Experiment (STUDY_DESIGN.md, Aim 3), for a real crashing input:
  1. fuzz the pinned target until a JPEG2000 input makes it fault (ASan abort / signal)
  2. wrap that crasher as encapsulated pixel data in a DICOM (the malicious carrier)
  3. RAW   : feed the carrier's J2K to the vulnerable target          -> expect CRASH
  4. CDR   : DicomLock disarm() the carrier                            -> disarmed or quarantined
  5. POST  : the target no longer hits the crash (codec path removed, or file was quarantined)
  6. CTRL  : a clean JPEG2000 image disarms bit-exact (fidelity preserved)

Result = neutralization: after CDR the vulnerable target is never driven into the fault.
"""

import argparse
import glob
import hashlib
import os
import random
import re
import shutil
import subprocess
import sys
import time

sys.path.insert(0, "/dicomlock")

import numpy as np
import pydicom
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.encaps import encapsulate
from pydicom.uid import JPEG2000Lossless, ExplicitVRLittleEndian, generate_uid

from scanner.disarm import disarm

WORK = "/tmp/aim3"
OUT = "/out" if os.path.isdir("/out") else WORK
FUZZ_SECONDS = int(os.environ.get("FUZZ_SECONDS", "180"))
os.makedirs(WORK, exist_ok=True)

# Bound the target's memory via ASan options (NOT ulimit -v, which breaks ASan's huge shadow
# mapping): a crafted gigapixel allocation then aborts fast and clean as an allocation error
# instead of OOM-killing the host, so the fuzzer can keep hunting for true memory-corruption
# (heap-buffer-overflow / use-after-free), which is the codec-CVE class we actually care about.
os.environ["ASAN_OPTIONS"] = ("detect_leaks=0:abort_on_error=1:"
                              "max_allocation_size_mb=1024:hard_rss_limit_mb=2048")

_ALLOC_RE = re.compile(
    r"(allocation-size-too-big|exceeds maximum supported size|out-of-memory|"
    r"requested allocation size|hard rss limit|Image size \(\d+ pixels\) exceeds)")
_BUG_RE = re.compile(
    r"(heap-buffer-overflow|stack-buffer-overflow|heap-use-after-free|global-buffer-overflow|"
    r"use-after-free|dynamic-stack-buffer-overflow|SEGV|FPE|alloc-dealloc-mismatch|"
    r"negative-size-param)")


def _find(name):
    hits = glob.glob(f"/src/openjpeg/build/**/{name}", recursive=True)
    return hits[0] if hits else name


OPJ_DEC = _find("opj_decompress")
OPJ_ENC = _find("opj_compress")


def run(argv, timeout=15):
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout)
        txt = p.stdout.decode("latin1", "ignore") + p.stderr.decode("latin1", "ignore")
        return p.returncode, txt
    except subprocess.TimeoutExpired:
        return None, "TIMEOUT"


def classify(rc, txt):
    """Separate a true memory-safety fault (the codec-CVE class) from a mere allocation/DoS bomb.
    CRASH/* = memory corruption or SEGV; OOM/* = giant-allocation or RSS blow-up (still a DoS, but
    a different and weaker class); rejected = graceful decode error."""
    if rc is None:
        return "HANG"
    if _ALLOC_RE.search(txt):
        return "OOM/alloc"
    if "AddressSanitizer" in txt or "runtime error" in txt:
        m = _BUG_RE.search(txt)
        return f"CRASH/ASan:{m.group(1) if m else 'fault'}"
    if rc < 0:
        return "OOM/kill" if -rc == 9 else f"CRASH/sig{-rc}"
    if rc == 0:
        return "ok"
    return "rejected"


def asan_stack_hash(txt):
    frames = re.findall(r"#\d+ 0x[0-9a-f]+ in (\S+)", txt)[:4]
    return (hashlib.sha1(" ".join(frames).encode()).hexdigest()[:12], frames) if frames else ("", [])


def make_seed():
    """A clean 64x64 gradient -> PGM -> J2K via the (pinned) opj_compress. Compressing a valid
    image does not trip the bug; this is just a well-formed seed to mutate from."""
    W = H = 64
    img = np.tile(np.arange(W, dtype=np.uint8), (H, 1))
    pgm = f"{WORK}/seed.pgm"
    with open(pgm, "wb") as f:
        f.write(b"P5\n%d %d\n255\n" % (W, H))
        f.write(img.tobytes())
    seed = f"{WORK}/seed.j2k"
    rc, txt = run([OPJ_ENC, "-i", pgm, "-o", seed])
    if not os.path.exists(seed):
        sys.exit(f"FATAL: could not build seed J2K with pinned opj_compress:\n{txt}")
    rc, txt = run([OPJ_DEC, "-i", seed, "-o", f"{WORK}/seed_dec.pgm"])
    print(f"  seed J2K decodes on the pinned target: {classify(rc, txt)}")
    return seed, img


def _siz_protect(data):
    """Byte offsets of the SIZ marker's size/grid fields. Leaving these intact keeps the declared
    image small, so mutations are far more likely to trip a DECODE-time overflow than a trivial
    gigapixel allocation bomb."""
    prot = set()
    i = data.find(b"\xff\x51")  # SIZ
    if i >= 0:
        for j in range(i, min(i + 40, len(data))):  # Lsiz..(X/Y)Osiz grid
            prot.add(j)
    return prot


def fuzz(seed):
    """Byte-mutation fuzzing of the seed J2K against the pinned ASan target. Prefer a true
    memory-corruption crasher (heap overflow / UAF / SEGV); keep an allocation/DoS bomb only as a
    fallback. This is Aim 1 in miniature."""
    base = bytearray(open(seed, "rb").read())
    free = [k for k in range(len(base)) if k not in _siz_protect(base)]
    random.seed(0xC0FFEE)
    t0 = time.time()
    iters = 0
    kinds = {}
    mem_crasher = oom_fallback = None
    cand = f"{WORK}/cand.j2k"
    while time.time() - t0 < FUZZ_SECONDS and mem_crasher is None:
        iters += 1
        m = bytearray(base)
        for _ in range(random.randint(1, 12)):
            m[random.choice(free)] = random.randrange(256)
        with open(cand, "wb") as f:
            f.write(m)
        rc, txt = run([OPJ_DEC, "-i", cand, "-o", f"{WORK}/cand.pgm"], timeout=8)
        c = classify(rc, txt)
        kinds[c.split(":")[0]] = kinds.get(c.split(":")[0], 0) + 1
        if c.startswith("CRASH"):
            shutil.copy(cand, f"{WORK}/crasher.j2k")
            mem_crasher = (f"{WORK}/crasher.j2k", c, txt)
        elif c.startswith("OOM") and oom_fallback is None:
            shutil.copy(cand, f"{WORK}/crasher.j2k")
            oom_fallback = (f"{WORK}/crasher.j2k", c, txt)
    dt = int(time.time() - t0)
    print(f"  fuzzed {iters} inputs in {dt}s; outcome breakdown = {kinds}")
    chosen = mem_crasher or oom_fallback
    if mem_crasher:
        h, frames = asan_stack_hash(mem_crasher[2])
        print(f"  MEMORY-CORRUPTION crasher: {mem_crasher[1]}")
        print(f"  ASan stack {h}: {' <- '.join(frames[:3]) or '(frames not parsed)'}")
    elif oom_fallback:
        print(f"  no memory-corruption in budget; falling back to allocation/DoS crasher: "
              f"{oom_fallback[1]}")
    return chosen if chosen else (None, None, "")


def save_dicom(ds, path):
    try:
        ds.save_as(path)
    except TypeError:
        ds.save_as(path, enforce_file_format=False)


def make_carrier(j2k_bytes, path, rows=64, cols=64):
    ds = Dataset()
    ds.file_meta = FileMetaDataset()
    ds.file_meta.MediaStorageSOPClassUID = "1.2.840.10008.5.1.4.1.1.7"
    ds.file_meta.MediaStorageSOPInstanceUID = generate_uid()
    ds.file_meta.TransferSyntaxUID = JPEG2000Lossless
    ds.SOPClassUID = "1.2.840.10008.5.1.4.1.1.7"
    ds.SOPInstanceUID = ds.file_meta.MediaStorageSOPInstanceUID
    ds.Rows, ds.Columns, ds.SamplesPerPixel = rows, cols, 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.BitsAllocated = ds.BitsStored = 8
    ds.HighBit = 7
    ds.PixelRepresentation = 0
    ds.PixelData = encapsulate([j2k_bytes])
    ds["PixelData"].VR = "OB"
    try:
        ds.is_implicit_VR, ds.is_little_endian = False, True
    except Exception:
        pass
    save_dicom(ds, path)
    return path


_MEMORY_BUGS = ("heap-buffer-overflow", "heap-use-after-free", "use-after-free",
                "stack-buffer-overflow", "global-buffer-overflow", "SEGV", "negative-size")


def pick_crash(crash_dir):
    """From a dir of AFL++ crashes, pick a true memory-corruption fault (preferred) over a mere
    allocation/DoS bomb, by replaying each against the pinned ASan target and classifying it."""
    # afl_entry.sh copies crashes with a per-instance prefix (".../out6_default_crashes__id:..."),
    # so match the "id:" anywhere in the name, not just a leading "id". Fall back to any real file.
    files = sorted(glob.glob(os.path.join(crash_dir, "*id:*")))
    if not files:
        files = [f for f in sorted(glob.glob(os.path.join(crash_dir, "*")))
                 if os.path.isfile(f) and "readme" not in os.path.basename(f).lower()]
    print(f"  scanning {len(files)} AFL crash input(s) for a memory-corruption fault...")
    best = fallback = None
    for fp in files:
        rc, txt = run([OPJ_DEC, "-i", fp, "-o", f"{WORK}/triage.pgm"], timeout=10)
        k = classify(rc, txt)
        if k.startswith("CRASH/ASan:") and any(b in k for b in _MEMORY_BUGS):
            best = (fp, k, txt)
            break
        if fallback is None and (k.startswith("CRASH") or k.startswith("OOM")):
            fallback = (fp, k, txt)
    chosen = best or fallback
    if not chosen:
        return (None, None, "")
    fp, k, txt = chosen
    shutil.copy(fp, f"{WORK}/crasher.j2k")
    h, frames = asan_stack_hash(txt)
    print(f"  selected crash {os.path.basename(fp)} -> {k}")
    print(f"  ASan stack {h}: {' <- '.join(frames[:3]) or '(frames not parsed)'}")
    return (f"{WORK}/crasher.j2k", k, txt)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--crasher", help="use this single pre-found crash file")
    ap.add_argument("--crash-dir", help="dir of AFL++ crashes; pick a memory-corruption one")
    args = ap.parse_args()

    print(f"OpenJPEG target : {OPJ_DEC}")
    run([OPJ_DEC, "-h"])
    print("=" * 78)
    print("STEP 1 — obtain a crashing input for the PINNED-VULNERABLE OpenJPEG 2.3.0 (ASan)")
    print("=" * 78)
    seed, seed_img = make_seed()
    if args.crash_dir:
        crasher, crash_kind, report = pick_crash(args.crash_dir)
    elif args.crasher:
        crasher = args.crasher
        rc, report = run([OPJ_DEC, "-i", crasher, "-o", f"{WORK}/triage.pgm"], timeout=10)
        crash_kind = classify(rc, report)
        h, frames = asan_stack_hash(report)
        print(f"  using supplied crasher {os.path.basename(crasher)} -> {crash_kind}")
        print(f"  ASan stack {h}: {' <- '.join(frames[:3]) or '(frames not parsed)'}")
    else:
        crasher, crash_kind, report = fuzz(seed)
    if not crasher:
        print("\nNo crasher found; raise the fuzz budget and retry.")
        sys.exit(2)

    print("\n" + "=" * 78)
    print("STEP 2-5 — paired RAW vs CDR vs POST on the malicious DICOM carrier")
    print("=" * 78)
    crasher_bytes = open(crasher, "rb").read()
    carrier = make_carrier(crasher_bytes, f"{WORK}/malicious.dcm")
    print(f"  built malicious DICOM carrier ({os.path.getsize(carrier)} bytes, TS=JPEG2000Lossless)")

    # RAW: the vulnerable target decodes the encapsulated J2K (what a PACS would do).
    rc, txt = run([OPJ_DEC, "-i", crasher, "-o", f"{WORK}/raw.pgm"], timeout=10)
    raw = classify(rc, txt)
    print(f"  RAW   : pinned target on the carrier's J2K        -> {raw}")

    # CDR: DicomLock disarms the carrier (decode happens in its SANDBOXED modern-OpenJPEG worker).
    out = f"{WORK}/malicious.disarmed.dcm"
    res = disarm(carrier, out_path=out)
    if res.error:
        verdict = f"QUARANTINED ({res.error[:90]})"
        disarmed_ok = False
    else:
        ts = str(res and pydicom.dcmread(res.out_path).file_meta.TransferSyntaxUID)
        verdict = f"DISARMED (TS now {ts}; transcoded={res.transcoded})"
        disarmed_ok = True
    print(f"  CDR   : DicomLock disarm()                        -> {verdict}")

    # POST: is the vulnerable target still driven into the crash?
    if not disarmed_ok:
        post = "blocked (file never reaches the target)"
        neutralized = True
    else:
        ds = pydicom.dcmread(out)
        native = str(ds.file_meta.TransferSyntaxUID) == str(ExplicitVRLittleEndian)
        # The disarmed file is native: a PACS decoding it never invokes OpenJPEG. Demonstrate the
        # codec path is gone by re-encoding the (clean) pixels and confirming a legit decode.
        clean_pgm = f"{WORK}/post.pgm"
        arr = ds.pixel_array.astype(np.uint8)
        with open(clean_pgm, "wb") as f:
            f.write(b"P5\n%d %d\n255\n" % (arr.shape[1], arr.shape[0]))
            f.write(arr.tobytes())
        clean_j2k = f"{WORK}/post.j2k"
        run([OPJ_ENC, "-i", clean_pgm, "-o", clean_j2k])
        rc2, txt2 = run([OPJ_DEC, "-i", clean_j2k, "-o", f"{WORK}/post_dec.pgm"], timeout=10)
        post = (f"native (no J2K to decode); re-encoded clean image decodes "
                f"{classify(rc2, txt2)}") if native else "transcoded"
        neutralized = native and not classify(rc2, txt2).startswith("CRASH")

    print(f"  POST  : same target after CDR                     -> {post}")

    print("\n" + "=" * 78)
    print("STEP 6 — fidelity control: a CLEAN JPEG2000 image must survive bit-exact")
    print("=" * 78)
    clean_carrier = make_carrier(open(seed, "rb").read(), f"{WORK}/clean.dcm")
    cres = disarm(clean_carrier, out_path=f"{WORK}/clean.disarmed.dcm")
    if cres.error:
        fidelity = f"FAIL ({cres.error[:80]})"
    else:
        got = pydicom.dcmread(cres.out_path).pixel_array.astype(np.uint8)
        fidelity = "bit-exact" if np.array_equal(got, seed_img) else "CHANGED"
    print(f"  clean JPEG2000 DICOM disarm -> image_preserved={getattr(cres,'image_preserved',None)},"
          f" vs original pixels: {fidelity}")

    print("\n" + "=" * 78)
    raw_crashed = raw.startswith("CRASH")
    print(f"VERDICT: raw={'CRASH' if raw_crashed else raw}  |  CDR={'neutralized' if neutralized else 'NOT neutralized'}"
          f"  |  clean-image fidelity={fidelity}")
    print("=" * 78)

    # Persist artifacts to the mounted host dir.
    with open(f"{OUT}/RESULTS.txt", "w") as f:
        f.write(f"target: OpenJPEG v2.3.0 + AddressSanitizer ({OPJ_DEC})\n")
        f.write(f"crasher kind: {crash_kind}\n")
        h, frames = asan_stack_hash(report)
        f.write(f"asan stack hash: {h}\nframes: {frames}\n")
        f.write(f"RAW (pinned target on malicious J2K): {raw}\n")
        f.write(f"CDR verdict: {verdict}\n")
        f.write(f"POST (target after CDR): {post}\n")
        f.write(f"neutralized: {neutralized}\n")
        f.write(f"clean-image fidelity: {fidelity}\n\n")
        f.write("--- ASan report (first 2KB) ---\n")
        f.write(report[:2048])
    for art in ("crasher.j2k", "malicious.dcm"):
        src = f"{WORK}/{art}"
        if os.path.exists(src):
            shutil.copy(src, f"{OUT}/{art}")
    print(f"\nartifacts + RESULTS.txt written to {OUT}")
    sys.exit(0 if (raw_crashed and neutralized) else 1)


if __name__ == "__main__":
    main()
