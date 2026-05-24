# DicomLock — Threat Model

This document states precisely what DicomLock defends against, what it does **not** claim, and the
residual risk that remains. Credibility depends on this honesty: DicomLock reports *exposure*, not
proven exploits, and it is a sanitization tool, not a medical device.

---

## Assets being protected

1. **The software that parses the file** — the PACS, viewer, AI ingestion pipeline, de-id pipeline,
   and DICOM toolkits (pydicom, GDCM, dcmtk, dcm4che) and the image/video codecs they invoke
   (libjpeg, OpenJPEG, CharLS, OpenJPH, FFmpeg-class). These are slow-to-patch and run deep inside
   hospital networks.
2. **Patient data confidentiality** — PHI in standard and private tags; the requirement that no
   data leaves the building during scanning/disarm.
3. **Clinical fidelity** — the diagnostic content of the image must survive disarm unchanged.

## Trust boundary

DICOM enters from an **untrusted source**: an outside facility, a patient CD/USB, an external
upload, an API, or a federated research transfer. DicomLock sits at that boundary and is itself a
parser of hostile input — so the tool must not become the victim (see "Tool safety").

---

## Attacker model

A capable adversary who can craft a DICOM file (or modify a legitimate one) and get it ingested by
a hospital/research system. In the **Mythos era** this adversary can discover novel memory-safety
bugs in DICOM toolkits and codecs faster than vendors patch them, so the defense **cannot** rely on
knowing the specific CVE in advance. Out of scope: an attacker with code execution on the host
already, or who controls the PACS itself.

---

## Threats defended, and how

| # | Threat | DICOM mechanism | DicomLock defense |
|---|--------|-----------------|-------------------|
| T1 | **Polyglot malware** | executable/archive header in the 128-byte preamble (CVE-2019-11687, ELFDICOM) | `check_preamble` flags 7 signature classes + a preamble-entropy heuristic; CDR **zeroes the preamble** |
| T2 | **Parser length bomb (DoS)** | element declares ≫ remaining bytes (e.g. 140 B → ~4 GB) | `check_length_amplification` byte-walks pre-parse; **quarantine** (un-disarmable) |
| T3 | **Sequence-nesting bomb** | deeply nested SQ exhausts memory/stack | `check_sequence_depth` rejects depth beyond a safe limit |
| T4 | **Allocation / decompression bomb** | header declares a multi-GiB frame, or a tiny encapsulated payload claims to decode to GiB | `check_pixel_dimension_bomb` (header-only, never decodes); **quarantine** |
| T5 | **Smuggled payload in private tags** | odd-group tags hold arbitrary binary (PHI leak + payload space) | `check_private_tag_payloads`; CDR strips via **default-deny vendor allowlist** + exe-signature override |
| T6 | **Vulnerable-codec routing** | TransferSyntax forces decode through libjpeg/OpenJPEG/CharLS/OpenJPH/FFmpeg-class | `check_codec_cve_exposure` reports the decoder + its CVE history (NVD-linked); CDR **transcodes off the codec to native** |
| T7 | **JPIP external-reference (SSRF-class)** | `.94/.95` point pixel data at a remote URL the parser fetches | `check_codec_cve_exposure` flags the external fetch; CDR resolves/strips rather than fetching |
| T8 | **Deflate-wrapped dataset** | `1.2.840.10008.1.2.1.99` routes the *whole* dataset through zlib inflate | flagged as zlib exposure; CDR transcodes off the deflate path (length-check correctly skips compressed bodies rather than false-positiving) |

**Disarm is verified, not assumed:** every disarmed file is **re-scanned**, and anything still
carrying a fail/critical finding is quarantined instead of emitted. Image equivalence is checked
bit-exact (decoded pixel array pre/post) on native/lossless transcodes.

---

## What DicomLock does NOT claim

- **It does not break or weaken encryption.** Mythos finds implementation/deployment flaws *around*
  ciphers; it does not break AES/RSA, and neither does this tool.
- **Codec exposure is exposure, not exploitation.** A `codec_cve` finding means the file routes
  through a CVE-bearing decoder — *not* that the file exploits a CVE. The bundled CVE map is a
  **seed**; verify against NVD/CISA.
- **It is not antivirus and not a network/device monitor.** It inspects the *file*; it does not
  watch traffic or endpoints (that is the Claroty/Cylera/Asimily/Forescout lane).
- **It is not a medical device.** No diagnostic claim; no FDA clearance; not a substitute for
  patching vulnerable software.
- **It is not novel in concept.** Commercial DICOM CDR (OPSWAT, Votiro) and academic transcoding
  (ICDR/ImSan) predate it. Its contribution is being open, self-hosted, auditable, and PACS-depth.

---

## Residual risk (honest limitations)

- **Lossy-compressed pixel data:** transcoding decodes once and stores uncompressed (no *new* loss),
  but a file that is *only* available as un-decodable lossy/proprietary data is quarantined, not
  recovered.
- **In-the-wild evidence:** the threat is demonstrated via PoCs and CVEs, **not** documented as a
  weaponized DICOM *file* used in an attack. Urgency is anticipatory.
- **Compressed-body length bombs:** a length bomb hidden *inside* a deflated stream can't be checked
  at the byte level without inflating (the very codec path we distrust); pydicom inflates on read,
  so deployments handling deflate should treat it as elevated exposure.
- **Seed data files:** `dicom_codec_cve.json` and `vendor_private_tags.json` are maintained seeds.
  An incomplete allowlist only *over-strips* (safe); an out-of-date CVE list under-reports.
- **Detection checks are deterministic rules** with thresholds tuned ~300–1000× above the largest
  real clinical image measured (3.1 MiB across 575 CTs). Novel structural attacks outside the
  modeled classes may pass the *scanner* — which is exactly why CDR rebuilds from a canonical form
  rather than relying on detection alone.

---

## Tool safety (the parser must not become the victim)

DicomLock parses hostile input, so:

- Allocation/length/decompression bombs are rejected **before** any pixel decode — the disarm step
  refuses them up front so a crafted file cannot DoS the tool itself.
- Bomb checks are **header/byte-level only**; they never allocate or decode the declared buffer.
- Recommended deployment: run ingest/parse under memory + CPU-time limits with **no network**, and
  prefer subprocess/container isolation (see [ARCHITECTURE.md](ARCHITECTURE.md), "Sandboxing").
