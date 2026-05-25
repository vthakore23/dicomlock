# DicomLock Technical Architecture (Security / CDR)

> The build plan. Each session picks a phase/module and implements it. Check items off.
> **Product = scan + DISARM DICOM files before they reach vulnerable PACS/viewer software.**
> See `../CLAUDE.md` for the "why now" (Mythos / Project Glasswing), the DICOM file-structure
> quick-reference, and the crypto framing. This doc is the *how*.

---

## System Overview

```
        DICOM file in  (scanner / outside facility / patient CD / upload / API)
                                  │
                       ┌──────────▼──────────┐
                       │   Sandboxed Ingest  │  raw bytes + SHA-256, bounded parse,
                       │  (resource limits)  │  no network. NB: pydicom force=True
                       └──────────┬──────────┘  parses hostile input (risk surface).
                                  │
        ┌─────────────────────────┼─────────────────────────┐
        │                 SECURITY SCAN MODULES              │
        │  1 File Security   polyglot, private-tag payload,  │
        │                    length-amplification,           │
        │                    sequence-depth, VR validation   │
        │  2 Codec Exposure  TransferSyntax → decoder → CVEs │
        │  3 Crypto Posture  cleartext? TLS? Encrypted Attrs │
        │  4 Metadata        integrity (existing)            │
        │  (parked)          De-ID auditor, deepfake classifier │
        └─────────────────────────┬─────────────────────────┘
                                  │
                       ┌──────────▼──────────┐
                       │   Report + Score    │  findings, severity, JSON / PDF
                       └──────────┬──────────┘
                                  │
                       ┌──────────▼──────────┐
                       │   CDR / DISARM      │  rebuild a clean canonical DICOM
                       │ (the differentiator)│  + prove clinical equivalence
                       └──────────┬──────────┘
                                  │
                    ┌─────────────┴─────────────┐
              clean file → PACS         dangerous → quarantine + report
```

**Key design property of CDR**: it neutralizes *unknown* attacks because it rebuilds from a
validated canonical form rather than detecting specific exploits. Against a Mythos-class
bug-discovery adversary this matters, because you don't need to know the CVE to neutralize it.

---

## Project Structure (target)

```
dicomlock/
├── ARCHITECTURE.md          ← this file
├── scan.py                  ← CLI (BUILT, v0.4.0)
├── server.py                ← FastAPI web server (BUILT)
├── _attack_test/            ← attack-surface proof + inert fixtures (BUILT)
├── scanner/
│   ├── findings.py          ← Finding class + severity (BUILT)
│   ├── ingest.py            ← read/hash/parse; ADD sandbox/resource limits
│   ├── file_security.py     ← Module 1 (EXTEND: 4 new checks)
│   ├── codec_cve.py         ← Module 2 (NEW)
│   ├── crypto_posture.py    ← Module 3 (NEW)
│   ├── metadata.py          ← Module 4 (BUILT)
│   ├── disarm.py            ← Module 5 / CDR engine (NEW, differentiator)
│   ├── deid_auditor.py      ← parked (BUILT; future privacy pillar)
│   ├── classify.py          ← parked (experimental deepfake RF)
│   ├── pixel_analysis.py / pixel_advanced.py / calibration.py  ← legacy
│   └── report.py            ← report gen JSON/PDF (NEW, later)
├── data/
│   ├── dicom_codec_cve.json ← decoder → known CVEs (NEW)
│   ├── vendor_private_tags.json ← private-tag allow/deny for CDR (NEW)
│   └── tcia_ct/             ← 580 real CT for FP validation (HAVE)
├── samples/
│   ├── *.dcm                ← 15 clean test files (HAVE)
│   └── tampered/            ← attack corpus (NEW; promote from _attack_test/)
└── tests/                   ← unit + validation (NEW)
```

---

## Module Specifications

### Module 1: File Security (`file_security.py`)  *EXTEND*

```python
def check_preamble(filepath) -> [Finding]            # BUILT: polyglot signatures
    # EXTEND: add Mach-O/Java/more sigs; add Shannon-entropy flag on the 128-byte preamble
    #         (a high-entropy "should-be-zero" preamble is suspicious even without a known sig)

def check_private_tag_payloads(ds) -> [Finding]      # NEW
    # Enumerate odd-group (private) tags; scan values for PE/ELF/Mach-O/script signatures;
    # flag any private tag carrying binary > ~1 KB. Private tags are arbitrary-binary smuggling space.

def check_length_amplification(filepath) -> [Finding]  # NEW: headline parser-DoS defense
    # Walk elements at the byte level; for each, compare declared length to bytes remaining in file.
    # Flag declared_length >> remaining (ratio threshold). This is the 140B→4GB / GDCM CVE-2026-3650 class.
    # Logic already prototyped in _attack_test/prove_attack_surface.py (demo 3).

def check_sequence_depth(ds) -> [Finding]            # NEW
    # Recursively walk SQ elements; flag nesting depth > ~10 (normal 3 to 5). Nesting bombs exhaust memory.

def check_vr_validation(ds) -> [Finding]             # NEW
    # For standard tags, compare declared VR to the DICOM dictionary. Mismatches = hand-crafted/malicious.
```

### Module 2: Codec CVE Exposure (`codec_cve.py`)  *NEW*

```python
def check_codec_cve_exposure(ds) -> [Finding]
    # 1. Read TransferSyntaxUID -> decoder library (table in CLAUDE.md file-structure ref):
    #    native | RLE | libjpeg | OpenJPEG | CharLS | FFmpeg-class (MPEG2/H.264/HEVC).
    # 2. If encapsulated, cross-reference data/dicom_codec_cve.json (decoder -> [CVE, CVSS, desc]).
    # 3. Report: codec invoked, encapsulated?, list of known CVEs that decoder has had.
    # IMPORTANT framing: this reports EXPOSURE (this file routes through a CVE-bearing decoder),
    #   NOT a claim that this file exploits a CVE. Honesty preserves credibility.
```
`data/dicom_codec_cve.json`: seed from NVD + CISA ICS-medical advisories (OpenJPEG, libjpeg-turbo,
CharLS, FFmpeg, GDCM, dcm4che). Keep dated; this is a maintained signature file.

### Module 3: Crypto Posture (`crypto_posture.py`)  *NEW*

```python
def check_crypto_posture(ds, context=None) -> [Finding]
    # - Is the object cleartext? (the common case). Transport TLS is mostly invisible from a file
    #   alone, so report what's knowable + prompt for transport context if integrated inline.
    # - Detect DICOM Encrypted Attributes Sequence (0400,0500) usage + scheme (CMS/AES).
    # - Detect DICOM digital signatures (PS3.15) presence (almost always absent).
    # - Flag point-of-use exposure: pixel data must be decrypted to render -> attack surface at decode.
    # Report "no encryption" vs "encryption present but stack-exposed". (Mythos doesn't break the
    #   cipher; see CLAUDE.md. The quantum harvest-now-decrypt-later risk is separate.)
```

### Module 4: Metadata Integrity (`metadata.py`)  *BUILT*. Keep.

### Module 5: CDR / Disarm (`disarm.py`)  *NEW, the differentiator*

```python
def disarm(filepath, policy=DEFAULT) -> DisarmResult
    # Rebuild a clean, clinically-identical DICOM from a validated parse:
    #   1. Zero the 128-byte preamble.
    #   2. Validate + bound every element length; drop/repair malformed elements.
    #   3. Quarantine private tags (configurable allow/deny via vendor_private_tags.json).
    #   4. Re-emit pixel data through ONE hardened path:
    #        - native/lossless: pass through validated, OR decode+re-encode to a canonical native TS
    #        - lossy/encapsulated: documented policy (decode+re-encode is lossy → flag, or pass-through)
    #   5. Strip non-essential/risky elements.
    # Returns: clean .dcm + a manifest of every change made.

# CRITICAL: prove clinical equivalence (the credibility linchpin):
#   - native/lossless: pixel-array hash MUST be bit-exact pre/post disarm.
#   - lossy: explicit, documented policy; visual + metric diff; never silently degrade diagnostics.
```

### Parked modules
- **`deid_auditor.py`**: BUILT; keep as the future "privacy pillar" (re-identification scoring,
  burned-in PHI OCR, residual-tag PHI). Revive if the privacy wedge is pursued (needs head/brain data).
- **`classify.py`** (deepfake RF): experimental only (52% FP; real datasets unreleased).
- **PRNU fingerprinting**, **AI robustness testing**: research-grade, later.

---

## Sandboxing & Tool Safety

The scanner parses *untrusted, hostile* files, so the tool must not become the victim:
- Run ingest/parse with **memory + CPU-time limits** (e.g., `resource` rlimits) and **no network**.
- Prefer subprocess/container isolation for the parse step.
- Treat `pydicom.dcmread(force=True)` as parsing attacker input; bound it. Never auto-execute anything.

---

## Web Interface (`server.py`)  *BUILT, extend*

Endpoints: `POST /api/scan` (BUILT), add `POST /api/disarm` (returns clean file + manifest),
`GET /api/health`. Flow: receive upload → temp dir → sandboxed scan → report → optional disarm →
return → **delete temp immediately (never persist PHI)**. Frontend: drag-drop, color-coded
findings, "Download disarmed file." Reuse the dark/cyan-purple design language.

---

## Testing Strategy

**Tampered corpus generator** (`tests/` → writes `samples/tampered/`): polyglot (PE/ELF/Mach-O),
length-bomb, deep-nesting, oversized-element, VR-mismatch, private-tag-payload, codec-CVE carrier.
Promote the inert artifacts in `_attack_test/` as the first fixtures.

**Unit tests**: one per check (clean → pass; each attack → correct severity).

**Validation**:
- FP rate: run all security checks on 580 real TCIA CTs → **target <1%**.
- Detection: run on the tampered corpus → **target 100%** on known classes.
- CDR equivalence: disarm real files → bit-exact pixel hash (native/lossless) + opens in a viewer.

---

## Success Targets

| Metric | Target | How measured |
|--------|--------|--------------|
| Scan time (single file) | < 2 s | time full pipeline on CT/MR |
| Polyglot detection | 100% | PE/ELF/Mach-O/ZIP/PDF preambles |
| Length-amp / depth detection | 100% | on tampered corpus |
| False-positive rate (clean files) | < 1% | 580 real TCIA CTs |
| Codec-CVE mapping | correct decoder + CVE list | vs NVD/CISA |
| CDR clinical equivalence | bit-exact (native/lossless) | pixel-array hash pre/post |
| No PHI persisted | always | temp deleted post-scan |

---

## Build Order (mirrors CLAUDE.md phases)

- **Phase 1**: Module 1 new checks (`length_amplification`, `sequence_depth`, `vr_validation`,
  `private_tag_payloads`) + Module 2 (`codec_cve`) + tampered corpus.
- **Phase 2**: Module 5 (`disarm.py`) + clinical-equivalence proofs + sandboxed ingest. (Module 3
  crypto posture can land here or in Phase 1.)
- **Phase 3**: full validation (FP rate, detection, CDR equivalence).
- **Phase 4**: open-source packaging (`report.py`, README, LICENSE Apache-2.0, `pip install`).
- **Phase 5**: demand validation (non-coding).
