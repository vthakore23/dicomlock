# DicomLock

**Open-source, self-hosted security for DICOM medical-image files — scan for weaponization, then disarm.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

DicomLock inspects every DICOM file for the ways it can be weaponized — polyglot malware,
parser-exploit constructions, and routing through vulnerable image/video codecs — and then
**disarms** it: rebuilding a clean, clinically-identical copy before the file ever reaches a
PACS, viewer, or AI model. It runs **self-hosted**; no patient data leaves your network.

This is **Content Disarm & Reconstruction (CDR) for DICOM**, built open-source and auditable.

> A medical image is not a picture — it's a parser's input. Hospital software must parse and
> decode all of it, and that step is the attack surface.

---

## Why this exists

AI now finds software vulnerabilities faster than hospitals can patch them. Anthropic's
**Project Glasswing / Claude Mythos** (2026) showed a frontier model autonomously finding *and
exploiting* thousands of high-severity bugs — including a 16-year-old FFmpeg bug fuzzers missed —
with **>99% still unpatched** and adversary parity projected within 6–24 months. The bottleneck
shifted from *finding* bugs to *patching* them, and hospitals are the slowest patchers on earth
(FDA recertification friction, legacy and embedded devices).

The DICOM file itself is the attack surface:

- **Polyglot** — the 128-byte preamble can carry an executable header, so one file is a valid
  scan *and* valid malware (CVE-2019-11687; **ELFDICOM** extended it to Linux medical devices).
  Antivirus deliberately skips medical imagery.
- **Parser abuse** — attacker-controlled length fields and deep nesting cause DoS/overflow
  (GDCM class; a 140-byte file can demand ~4 GB — a 30,000,000× amplification we reproduce).
- **Vulnerable codecs** — encapsulated pixel/video data decodes through libjpeg / OpenJPEG /
  CharLS / **FFmpeg-class** libraries with long CVE histories, deep inside the PACS/viewer.

Live DICOM CVEs make this concrete: Orthanc auth-bypass **CVE-2025-0896** (CVSS 9.8),
MicroDicom RCE **CVE-2025-5943**, GDCM advisories (CISA, 2025), and ~3,627 internet-exposed
DICOM servers / ~1.19 billion images (Rapid7, 2025).

> **On cryptography (read this):** Mythos does **not** break ciphers (AES/RSA). It finds the
> *implementation and deployment* flaws around encryption (key-leak memory bugs, auth bypass,
> point-of-use decryption) and exploits that most DICOM is **cleartext** anyway. The genuine
> "crypto math breaks" risk is quantum harvest-now-decrypt-later on long-lived PHI — a separate
> threat. DicomLock makes no claim to break encryption.

---

## What it does

1. **Scan** — deterministic, rule-based (not ML) checks on the file:
   polyglot/preamble-entropy, length-amplification (parser DoS), sequence-depth (nesting bomb),
   pixel-dimension/decompression bomb, private-tag payloads, codec-CVE exposure, metadata integrity.
2. **Disarm** — for dangerous-but-recoverable files: zero the preamble, **transcode** compressed
   pixels to native (off libjpeg/OpenJPEG/CharLS/FFmpeg-class) keeping the image **bit-exact**,
   and filter private tags against a vendor allowlist (keep recognized, strip unknown + exe-payloads).
3. **Quarantine** — the un-fixable (length bombs, un-decodable files, or anything that fails a
   re-scan of the disarmed output). DicomLock never emits a still-dangerous file.

**The key property of CDR:** it neutralizes *unknown* attacks because it rebuilds from a validated
canonical form rather than detecting a specific exploit. That is the only defense that survives a
Mythos-class, infinite-bug-discovery adversary — you don't need to know the CVE.

---

## Honest positioning

Commercial DICOM CDR **already exists** — OPSWAT MetaDefender Deep CDR added DICOM (June 2024);
Votiro (Menlo) markets it too; academic prior art (ICDR/ImSan) transcodes to disarm image
polyglots. **"Nobody does this" is not the pitch.**

DicomLock's lane is **open-source, self-hosted, auditable, and PACS-depth**: bit-exact pixel
transcoding off the codec, vendor-allowlist private-tag filtering, parser-bomb rejection, and
disarm-then-re-scan verification — all inspectable in source, running in-hospital so no PHI
leaves the building, and free for research and academic use. The realistic first adopters are
research-imaging / data-engineering teams at academic medical centers that already run ingestion
and de-identification pipelines on untrusted external DICOM.

DicomLock is a quality/security/sanitization tool — **not a medical device** (no diagnostic claim,
no FDA clearance). See [THREAT_MODEL.md](THREAT_MODEL.md) for exactly what it does and does not defend.

---

## Install

```bash
# From source (recommended while pre-release)
git clone https://github.com/vthakore23/dicomlock.git
cd dicomlock
pip install -e .

# Core install includes the CDR decoder backends (gdcm + pylibjpeg) so disarm works out of the box.
# Optional extras:
pip install -e ".[server]"   # web UI + REST API
pip install -e ".[full]"     # parked/experimental modules (--deid PHI audit, legacy forensics)
```

Requires Python 3.10+.

---

## Usage

### CLI

```bash
dicomlock path/to/file.dcm                 # scan one file
dicomlock path/to/folder/                  # scan every .dcm in a folder
dicomlock path/to/folder/ --disarm         # scan + disarm/quarantine each file
dicomlock path/to/file.dcm --deid          # also run the PHI / de-identification audit
```

From a source checkout without installing: `python scan.py <file|dir> [--disarm] [--deid]`.

### Python library

```python
from scanner.pipeline import run_security_scan, disarm_or_quarantine, is_dangerous

report = run_security_scan("file.dcm")
if is_dangerous(report):
    result = disarm_or_quarantine("file.dcm")   # -> {"action": "disarmed"|"quarantined", ...}
```

### Web UI + REST API

```bash
python server.py        # http://localhost:8899
```

- `POST /api/scan` (`?deid=true`) — returns the JSON findings report.
- `POST /api/disarm` — returns the clean rebuilt file, or a quarantine verdict.
- `GET /api/health`.

Uploads are scanned in a temp dir and deleted immediately — **PHI is never persisted.**

---

## What it checks

| Check | Catches | Severity |
|-------|---------|----------|
| `check_preamble` | polyglot signatures (PE/ELF/Mach-O/ZIP/PDF/gzip/shell) + high-entropy preamble | critical / warn |
| `check_length_amplification` | element declaring more bytes than the file holds (parser DoS) | critical |
| `check_sequence_depth` | sequence-nesting bombs | fail |
| `check_pixel_dimension_bomb` | absurd declared image buffer + decompression bombs | critical |
| `check_private_tag_payloads` | executables / opaque high-entropy blobs in private tags | critical / warn |
| `check_codec_cve_exposure` | TransferSyntax → decoder → known-CVE exposure; JPIP SSRF references | warn |
| `run_metadata_checks` | metadata integrity | info / warn |

Codec exposure is reported **honestly as exposure, never as a proven exploit** — each finding links
the decoder's CVEs to NVD for audit. The decoder→CVE map lives in
[`scanner/data/dicom_codec_cve.json`](scanner/data/dicom_codec_cve.json) (a maintained seed —
verify against NVD/CISA).

---

## Validated results

Reproducible with the scripts in [`_attack_test/`](_attack_test/):

- **False positives:** **0 across 575 real clinical CT files** (TCIA) — `validate_scale.py`.
- **Detection:** **20 / 20** crafted attack/exposure fixtures flagged (14 blocked outright,
  6 flagged as codec/SSRF exposure) — `validate_phase1.py`.
- **Differentiation:** pydicom, GDCM, and dcmtk `dcmdump` all **silently accept** the weaponized
  files (or crash on the bomb without flagging it); DicomLock flags every one — `compare_baseline.py`.
- **CDR is bit-exact:** JPEG2000-lossless, JPEG-LS-lossless, Deflated/zlib, and a JPEG2000+ELF
  polyglot worst case all transcode to native with bit-exact pixels and codec exposure removed —
  `disarm_compressed.py`. Un-decodable inputs fail-safe to quarantine.

```bash
python make_tampered_corpus.py            # regenerate the inert attack corpus
python _attack_test/validate_phase1.py    # 0 FP on clean samples + detection on the corpus
python _attack_test/validate_scale.py     # FP rate across all 575 real CTs
python _attack_test/compare_baseline.py   # DicomLock vs pydicom / GDCM / dcmtk
python _attack_test/disarm_compressed.py  # bit-exact transcode proofs
```

The attack fixtures are **inert** — polyglots carry only magic bytes; the payload tags carry an
executable header plus zero padding. No working malware ships in this repo.

---

## Documentation

- [THREAT_MODEL.md](THREAT_MODEL.md) — attacks defended, explicit non-claims, residual risk.
- [ARCHITECTURE.md](ARCHITECTURE.md) — module specs and build plan.
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute (CVE-map updates, vendor allowlist, codecs).
- [SECURITY.md](SECURITY.md) — vulnerability disclosure.

---

## Disclaimer

DicomLock is provided "as is" under the Apache-2.0 License, **without warranty of any kind**. It is
a security/sanitization tool, **not a medical device**, and makes no diagnostic claim. Validate
disarmed files in your own environment before clinical use, and run it on de-identified data where
possible. You are responsible for compliance with HIPAA and all applicable regulations.

## License

[Apache-2.0](LICENSE) © 2026 Vijay Thakore. Open-sourcing forecloses a patent on the CDR method —
that openness and auditability is the point.
