# DicomLock benchmark engine

A companion tool that pairs with the `dicomlock` package and measures it. It throws a labeled
corpus of inert attacks at both a matrix of real DICOM parsers/codecs and at DicomLock's Content
Disarm and Reconstruction, then reports how well the defense holds. This is the runnable execution
of [`STUDY_DESIGN.md`](../STUDY_DESIGN.md).

It imports `scanner` but is not part of the shipped package, so `pip install dicomlock` stays lean.

## Run

```bash
python -m bench
```

It prints a markdown report and writes `bench/results.json` (per-file detail plus the summary).

## What it measures

For every file in the corpus the engine:

1. Runs DicomLock's scan and records the verdict (block, warn, clean).
2. Runs a sandboxed matrix of real targets (pydicom, GDCM, dcmtk, and any pinned-vulnerable target
   you add) on the raw file. Each target parses and decodes in a resource-limited subprocess, so a
   crash or hang is observable as a process signal, not swallowed by a try/except. Allocation and
   decompression bombs are pre-identified and never executed raw, since that decode is the attack.
3. Disarms the file with CDR (rebuild clean, or quarantine the un-fixable).
4. Re-runs the same target matrix and DicomLock's scan on the disarmed output.

From that it computes:

- **Detection**: tampered files flagged at the expected severity.
- **Neutralization**: dangerous inputs that, after CDR, are quarantined or rebuilt clean to every
  target and to DicomLock. This is the core CDR-efficacy claim.
- **Fidelity**: disarmed pixels compared bit-exact against the original.
- **False positives**: benign files wrongly blocked.
- **Differentiation**: files DicomLock blocks that the other toolkits parse without complaint.

## Corpus

The full pipeline (detection, target matrix, CDR, neutralization, fidelity) runs over the inert
fixtures in [`../samples/tampered/`](../samples/tampered) plus the benign files in
[`../samples/`](../samples), labeled by attack class in [`corpus.py`](corpus.py). Regenerate or extend
the attack fixtures with [`../make_tampered_corpus.py`](../make_tampered_corpus.py); new files are
picked up automatically as long as the filename matches a class rule.

In addition, the false-positive metric is run at clinical scale over the 575 real TCIA CTs in
`../data/tcia_ct/` (scan-only, since benign files do not need the crash matrix or CDR). That set lives
under `data/` (gitignored), so it is present locally but absent on a fresh clone; pass `--skip-scale`
to omit it, and the metric falls back to the curated benign samples.

## Adversarial generator and pinned codec

- [`generate.py`](generate.py) (`python -m bench.generate`) writes a large labeled corpus of inert
  malformed files designed to *break* the tool: polyglot signature/offset variants, a preamble
  entropy sweep, length/nesting/dimension boundary probes, payload-under-known-vendor, and benign
  edge cases. The report's "Failures hunted" section lists scanner misses, CDR escapes, and fidelity
  breaks. This pass already found and fixed a real gap (the polyglot signature list missed WASM, DEX,
  RAR, 7-Zip, and Lua).
- [`pinned.py`](pinned.py) (`python -m bench.pinned`) runs J2K pixel data through a pinned
  OpenJPEG 2.3.0 + AddressSanitizer build (the [`../_attack_test/aim3/`](../_attack_test/aim3) Docker
  image) and measures whether CDR neutralizes what the real vulnerable decoder chokes on. Benign J2K
  decodes clean; `--demo FILE.dcm` shows raw crash -> CDR -> re-decode. The known malicious case
  faults the decoder (ASan) raw and is quarantined by CDR.
- [`fidelity.py`](fidelity.py) (`python -m bench.fidelity`) runs the actual CDR rebuild across a
  diverse benign corpus (pydicom + pylibjpeg test data spanning many modalities and every common
  transfer syntax, plus the 580 real TCIA CTs) and reports the bit-exact rate. For native/lossless
  sources a transcode must be bit-exact vs the acquisition; any miss is a fidelity break. Latest run:
  **623/623 native+lossless bit-exact, 20/20 lossy preserved-as-decoded, 0 breaks, 13 transfer
  syntaxes**. `--skip-scale` omits the CTs; `--limit N` caps for a quick pass.

## Scaling further

- Point the corpus at a larger generated set, and add more pinned-vulnerable targets, to characterize
  the attack surface and CDR efficacy at greater breadth.

## Layout

| File | Role |
|------|------|
| `corpus.py` | labeled inputs (curated, generated, real-CT scale set) |
| `targets.py` | sandboxed parser/codec matrix + DoS pre-identification |
| `evaluate.py` | per-file detection, CDR, neutralization re-test, fidelity |
| `report.py` | aggregate metrics, failures hunted, render markdown |
| `generate.py` | adversarial structural-mutation corpus generator |
| `pinned.py` | pinned OpenJPEG 2.3.0+ASan efficacy harness (Docker) |
| `fidelity.py` | CDR bit-exact fidelity at scale over a diverse benign corpus |
| `__main__.py` | CLI |
