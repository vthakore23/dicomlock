# Aim 3 — CDR vs a real pinned-vulnerable codec

This is the executable version of [STUDY_DESIGN.md](../../STUDY_DESIGN.md) Aim 3, run against a
**real, pinned-vulnerable OpenJPEG** instead of the inert corpus. It answers the audit's strongest
objection ("the CDR-neutralizes-attacks claim is unproven; the inert corpus never actually crashes
anything") with a reproducible, end-to-end result.

## What it does

The Docker image contains two codecs on purpose:

- **the TARGET** — `opj_decompress` built from **OpenJPEG v2.3.0** with **AddressSanitizer**. The
  pin reintroduces the CVE-era memory bugs; ASan makes a heap over-read/-write abort and be
  observable instead of silently tolerated. This stands in for the slow-to-patch OpenJPEG a real
  PACS/viewer routes JPEG2000 pixel data through.
- **the DEFENSE** — DicomLock CDR, whose sandboxed decode uses a **modern, patched OpenJPEG**
  (bundled in `pylibjpeg-openjpeg`), independent of the system 2.3.0.

`run_aim3.py` then:

1. obtains a crashing JPEG2000 input for the pinned target (by fuzzing the seed, or via
   `--crasher FILE` / `--crash-dir DIR` for an AFL++ corpus), preferring a true
   memory-corruption fault (heap-buffer-overflow / use-after-free / SEGV) over a mere
   allocation/DoS bomb;
2. wraps that crasher as encapsulated pixel data in a DICOM (the malicious carrier);
3. **RAW** — feeds the carrier's J2K to the pinned target → records the fault;
4. **CDR** — runs DicomLock `disarm()` on the carrier → disarmed or quarantined;
5. **POST** — confirms the pinned target is no longer driven into the fault (the file was
   quarantined, or transcoded to native so the codec path is gone);
6. **fidelity control** — a clean JPEG2000 image must disarm bit-exact.

`neutralized = (raw faults) AND (after CDR the target no longer faults)`.

## Run it

```bash
# from the dicomlock/ repo root
docker build -t dicomlock-aim3 -f _attack_test/aim3/Dockerfile \
  $(mktemp -d)   # or stage scanner/ + run_aim3.py into a context dir (see below)

mkdir -p _attack_test/aim3/results
docker run --rm -e FUZZ_SECONDS=150 \
  -v "$PWD/_attack_test/aim3/results:/out" dicomlock-aim3
```

The Dockerfile copies `scanner/` and `run_aim3.py` from the build context, so build from a context
that contains both (e.g. stage them into a temp dir, or build from the repo root with a
`.dockerignore` that keeps the 575 CTs out). Results, the chosen crasher, and the malicious carrier
are written to `results/` (mounted at `/out`).

## What a run proves

The live numbers for the most recent run are in [`results/RESULTS.txt`](results/), including the
ASan fault class, the ASan stack hash (for de-duplication), the RAW / CDR / POST outcomes, and the
clean-image fidelity check. The headline to look for:

```
VERDICT: raw=<fault>  |  CDR=neutralized  |  clean-image fidelity=bit-exact
```

## Honest scope

- This measures **crash neutralization** on a pinned old version, not end-to-end exploitability
  today (a crash in 2.3.0 is not a live exploit). That boundary is stated in STUDY_DESIGN.md §6.
- One pinned target and a bounded fuzz budget is a **lower bound** on the surface, not a survey.
  Scale by adding pinned targets and pointing `--crash-dir` at a larger AFL++ corpus.
- Inert only: the crasher is a malformed-codestream input that faults a decoder. No working
  malware, consistent with [SECURITY.md](../../SECURITY.md).
