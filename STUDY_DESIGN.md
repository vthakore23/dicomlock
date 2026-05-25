# Study Design — Content Disarm & Reconstruction as a Pre-Parse Defense for DICOM

**Working title:** *Neutralizing the medical-imaging file attack surface: a fuzzing and
CVE-reproduction evaluation of Content Disarm & Reconstruction (CDR) for DICOM.*

**Status:** protocol / design, with an **initial Aim-3 execution** landed. A runnable, hermetic
harness (`_attack_test/aim3/`) builds a real pinned-vulnerable **OpenJPEG v2.3.0 + AddressSanitizer**
target plus a coverage-guided **AFL++** setup, and runs the paired raw-vs-CDR-vs-POST experiment.
First result: a fuzzer-found malformed JPEG2000 drives the pinned decoder to a fault; CDR neutralizes
the malicious DICOM carrier (quarantine) and disarms a clean image bit-exact (`aim3/results/`). This
is the publishable asset behind DicomLock — it converts the tool into evidence. It is written so a
solo technical author can execute it on public data with no PHI, no IRB, and no partnerships that
aren't already available.

---

## 1. Motivation and the "why now"

AI vulnerability discovery (Anthropic Project Glasswing / Claude Mythos, 2026) finds memory-safety
bugs faster than vendors patch them; >99% of one model's findings remained unpatched, and hospitals
are the slowest patchers (FDA recertification friction, legacy/embedded devices). The DICOM **file**
is a direct attack surface: a 128-byte preamble that can carry an executable (CVE-2019-11687,
ELFDICOM), attacker-controlled length/nesting fields (parser DoS), and pixel data that decodes
through libjpeg / OpenJPEG / CharLS / OpenJPH / FFmpeg-class codecs with long CVE histories.

The defensive thesis under test: **you cannot win the patch race, so neutralize the file at the
data layer before it reaches the vulnerable parser/codec.** CDR rebuilds a clean canonical file and
therefore should neutralize *unknown* bugs (it does not depend on knowing the CVE). This study tests
whether that thesis holds empirically, against both fuzzer-discovered crashers and real published
CVEs, while preserving diagnostic fidelity.

**Regulatory hook (FDA 524B).** Premarket cybersecurity is enforced for medical devices (final
guidance Sept 2023; Select Updates finalized Jun 2025; SBOM + refuse-to-accept). PACS/modality
makers must demonstrate input-handling robustness. A fuzzed-and-hardened DICOM parse+CDR library,
plus a "CDR vs. real CVEs" result, is directly licensable/contributable to that obligation — and
publishable.

---

## 2. Research questions and hypotheses

- **RQ1 (attack surface).** How many *unique* crash/hang/OOM defects can structure-aware fuzzing
  surface across widely deployed DICOM parsers and the codecs DICOM routes into, using bounded
  effort on commodity hardware?
- **RQ2 (CDR efficacy — the core claim).** For inputs that crash a parser/codec (fuzzer-found
  **and** real-CVE triggers), does routing the input through CDR first eliminate the crash?
  - **H1:** CDR neutralizes ≥ the overwhelming majority of file-parse/codec crashers, because it
    rebuilds from a validated canonical form rather than passing the hostile bytes through.
- **RQ3 (fidelity).** Does CDR preserve diagnostic content?
  - **H2:** On native/lossless inputs, CDR output is **bit-exact** (decoded pixel array identical).
- **RQ4 (specificity).** Does the *scanner* maintain a near-zero false-positive rate on real
  clinical images while catching the attack corpus?
  - **H3:** FP rate < 1% on real CTs (current measured: 0/575); detection 100% on modeled classes.
- **RQ5 (scope boundary — honesty).** Which classes does CDR **not** address (e.g. network/auth
  bugs such as Orthanc CVE-2025-0896), making the contribution precise rather than overstated?

---

## 3. Specific aims

### Aim 1 — Characterize the DICOM parse/decode attack surface by fuzzing
Build coverage-guided and structure-aware fuzzing harnesses for:
- **Parsers:** pydicom (Python), GDCM (C++), dcmtk (C++, via `dcmdump`/`dcm2img`), and optionally
  dcm4che (Java) — the toolkits real imaging/AI pipelines are built on.
- **Codecs (the deeper surface):** OpenJPEG, libjpeg/libjpeg-turbo, CharLS, OpenJPH, and an
  FFmpeg-class decoder for the video transfer syntaxes — fuzzed both standalone and *through* the
  DICOM encapsulation path so findings are reachable from a real file.

Record crashes, hangs (DoS), and OOM; de-duplicate by stack hash into unique defect buckets.

### Aim 2 — Reproduce real, published CVEs as inert triggers
Pin known-vulnerable versions and construct **inert** DICOM carriers that reach each bug, drawn from
file-parse/codec memory-safety classes (NOT network/auth):
- Codec memory safety from the project's auditable map
  ([`scanner/data/dicom_codec_cve.json`](scanner/data/dicom_codec_cve.json)): e.g. OpenJPEG
  CVE-2020-27814 / CVE-2018-5785, libjpeg-turbo CVE-2018-19664 / CVE-2018-20330, zlib
  CVE-2022-37434, FFmpeg-class CVE-2016-10190.
- DICOM-application parse bugs in scope for file CDR: e.g. MicroDicom viewer RCE CVE-2025-5943
  (crafted-file out-of-bounds write); GDCM advisories (CISA ICS-medical, 2025).
- **Explicitly out of scope** (Aim addresses RQ5): Orthanc auth-bypass CVE-2025-0896 — a server
  authentication flaw, not a file-parse bug; CDR cannot and should not claim to fix it.

### Aim 3 — Evaluate CDR as a pre-parse mitigation
The core experiment, run for every trigger from Aims 1–2:
1. Feed the **raw** trigger to the target parser/codec → record outcome (crash/hang/OOM/clean).
2. Feed the trigger through **DicomLock CDR** (`disarm_or_quarantine`) → obtain a clean file **or** a
   quarantine verdict.
3. Feed the **disarmed** output to the same target → record outcome.
4. **Success** = the target no longer crashes (either the input was disarmed to a benign file that
   parses cleanly, or it was quarantined and never reached the parser).
5. For disarmed (non-quarantined) cases, verify **clinical fidelity**: decoded pixel array bit-exact
   vs. the original's intended image where an original image exists.

---

## 4. Methods

**Corpus / seeds.** Real clinical images: TCIA CT (575 already on disk) + a few public MR/US/video
DICOM for codec diversity. Seeds for the structure-aware fuzzer: the existing inert attack corpus
(`samples/tampered/`, 20 fixtures) plus valid files mutated at the element/length/VR/sequence level.

**Fuzzers.** Coverage-guided (AFL++ / libFuzzer) for the C/C++ codecs and GDCM/dcmtk via
persistent-mode harnesses; structure-aware mutation (e.g. a DICOM grammar for boofuzz or a custom
pydicom-based mutator) so mutations stay reachable past the File Meta group. Budget: a fixed,
reported CPU-hour cap per target on commodity hardware (reproducibility over record-setting).

**CDR under test.** `scanner.disarm.disarm` + `scanner.pipeline.disarm_or_quarantine` (which
re-scans the disarmed output and quarantines residual danger). Pin the DicomLock commit.

**Environment.** Containerized targets at pinned vulnerable versions; CPU-time + memory rlimits and
no network (matches the deployment recommendation in [THREAT_MODEL.md](THREAT_MODEL.md)). All builds,
seeds, and harnesses released for reproducibility.

### Metrics
- Unique defect buckets per target (Aim 1).
- **Neutralization rate** = fraction of crashers that no longer crash after CDR (Aim 3, primary).
- **Bit-exact fidelity rate** on native/lossless disarmed outputs (H2).
- **Quarantine rate** and reasons (un-decodable / bomb / failed re-scan).
- Scanner **FP rate** on real CTs and **detection rate** on the corpus (H3).
- Throughput (files/sec) and per-file latency for deployability.

### Analysis
Primary: neutralization rate with a binomial CI; McNemar's test on paired raw-vs-disarmed crash
outcomes. Report per-target and pooled. Pre-register the CPU budget and version pins so the result
is a fixed, citable artifact.

---

## 5. Expected contributions

1. An open, reproducible **measurement** of the DICOM file parse/decode attack surface across the
   toolkits hospitals actually run.
2. The first **open-source, auditable** demonstration that CDR neutralizes both fuzzer-found and
   real-CVE file/codec triggers **while preserving images bit-exact** — evidence for the
   "neutralize, don't patch-race" thesis.
3. A precise **scope statement** (what CDR does and does not cover), strengthening credibility.
4. A reusable **fuzzing + CDR harness** and corpus that PACS/modality vendors can run against
   FDA-524B input-robustness expectations.

---

## 6. Threats to validity (honest)

- **Construct:** a crash in a pinned old version ≠ exploitability today; we measure crash
  neutralization, not end-to-end exploit prevention. State this plainly.
- **External:** fuzzing under a fixed budget under-counts the true surface; results are a lower
  bound. Bit-exact applies to native/lossless; lossy/proprietary-only inputs are quarantined, not
  recovered.
- **Internal:** stack-hash de-duplication can over/under-merge buckets; report the method.
- **Prior art:** commercial CDR (OPSWAT, Votiro) and academic transcoding (ICDR/ImSan) exist —
  novelty is openness, auditability, the paired CVE-reproduction methodology, and PACS-depth, not
  the concept of CDR.

---

## 7. Ethics and responsible disclosure

- All shipped artifacts are **inert** (magic bytes / inert headers + zero padding) — no working
  malware, consistent with [SECURITY.md](SECURITY.md).
- Any *new* zero-day surfaced by fuzzing goes through coordinated disclosure to the maintainer
  before publication.
- Public, de-identified imaging only → no PHI, no IRB required. Re-confirm dataset licenses (TCIA).

---

## 8. Milestones (indicative, solo cadence)

1. Harnesses + pinned vulnerable targets containerized; seed corpus assembled.
2. Aim 1 fuzzing run to the budget cap; defect buckets triaged.
3. Aim 2 CVE triggers reproduced (inert) and confirmed against pinned versions.
4. Aim 3 paired raw-vs-CDR evaluation + fidelity verification; stats.
5. Write-up + artifact release.

**Target venues:** *npj Digital Medicine* or *JAMIA* (clinical-informatics framing); security
venues *USENIX WOOT* / *IEEE S&P workshops* (methodology). A preprint + released artifact lands
first to establish the result and drive DicomLock credibility.

---

## 9. Reproducibility checklist

- [ ] Pinned target versions + Dockerfiles published.
- [ ] Fuzzing harnesses + grammar/mutators released.
- [ ] Seed corpus + every inert trigger released.
- [ ] DicomLock commit hash recorded.
- [ ] CPU budget, hardware, and rlimits reported.
- [ ] Raw outcome logs + analysis scripts released.

---

## 10. Preliminary results (reproduced 2026-05-25, DicomLock v0.7.0)

These establish false-positive discipline, detection, and CDR neutralization on a curated corpus
plus one pinned-vulnerable target. The full fuzzing campaign (Aim 1 at scale, memory-corruption
class, multiple pinned targets) remains future work; the crashes reproduced so far are
DoS/allocation-class, not memory-corruption.

The benchmark engine reproduces the per-class detection, neutralization, fidelity, and
false-positive numbers in one command: `python -m bench` (see `bench/README.md`). Latest run:
detection 20/20, false positives 0/590 (15 curated samples + 575 real TCIA CTs, scan-only),
neutralization 20/20, fidelity 23/23 bit-exact, and 9 of the 14 blocked files are silently accepted
by all three reference toolkits (pydicom, GDCM, dcmtk).

| Result | Number | Harness |
|--------|--------|---------|
| False positives, 575 real clinical CTs | **0 / 575** (0 parse errors) | `validate_scale.py` |
| False positives, mixed-compression corpus (103 files, 12 transfer syntaxes) | **0 on conformant files** (8/103 blocked, every one genuinely non-conformant: no Part-10 header, truncated, or missing image dimensions) | `fp_mixed_corpus.py` |
| Detection on the tampered corpus | **20 / 20** flagged by the expected check; **0 FP** on the 15 paired clean files | `validate_phase1.py` |
| Differentiation | pydicom, GDCM, and dcmtk `dcmdump` accept the weaponized files (or crash on the bomb without flagging it); DicomLock raises a verdict on every one | `compare_baseline.py` |
| CDR, paired raw-vs-CDR | **4 / 4** DoS-bomb inputs neutralized (pre-identified and quarantined, never executed raw); 9 polyglot/payload/deflate files disarmed **bit-exact**; un-decodable files quarantined | `cdr_vs_parsers.py` |
| Aim 3 vs a pinned-vulnerable codec | a fuzzer-found malformed JPEG 2000 OOM-kills **OpenJPEG 2.3.0 + ASan**; CDR neutralizes the DICOM carrier (sandboxed quarantine) and disarms a clean image **bit-exact** | `aim3/` (Docker) |
| Re-identification-risk score | ranks clean = 0/MINIMAL, residual-PHI = 45/MODERATE, dirty = 100/HIGH | `test_reid_score.py` |

The four mixed-compression false positives found while building this table (explicit/implicit
VR-mismatch length-walk desync; 1-bit bit-packing; YBR_FULL_422 subsampling; legal trailing
padding) were all fixed before the 0-on-conformant result above; detection held at 20/20 and the
575-CT scale stayed at 0 FP after the fixes.
