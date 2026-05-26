# DicomLock

Open-source, self-hosted security for DICOM medical-image files. It scans a file for the ways it can be weaponized, then disarms it by rebuilding a clean, clinically identical copy.

[![PyPI](https://img.shields.io/pypi/v/dicomlock.svg)](https://pypi.org/project/dicomlock/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

A DICOM file is not just a picture. It is input for a parser, and hospital software has to read and decode all of it before anyone sees an image. That step is the attack surface. DicomLock checks the file for polyglot malware, parser-exploit constructions, and pixel data that routes through vulnerable image or video codecs, then rebuilds a clean version before the file reaches a PACS, viewer, or model. It runs inside your network, so no patient data leaves the building.

This is Content Disarm and Reconstruction (CDR) for DICOM, built to be open and auditable.

## Install

```bash
pip install dicomlock
```

The core install pulls in the decoder backends (gdcm and pylibjpeg) so disarm works out of the box. Two optional extras:

```bash
pip install "dicomlock[server]"   # web UI and REST API
pip install "dicomlock[full]"     # PHI / de-identification audit and legacy forensics
```

Python 3.10 or newer.

## Usage

```bash
dicomlock file.dcm                 # scan one file
dicomlock folder/                  # scan every .dcm in a folder, print an aggregate summary
dicomlock folder/ --disarm         # scan, then disarm or quarantine each file
dicomlock file.dcm --deid          # add the PHI / de-identification audit
```

Directory scans print an aggregate summary at the end: files scanned, elapsed time and throughput, verdict distribution (CLEAN / CAUTION / FAIL / CRITICAL), disarm actions if `--disarm` was set, finding categories that fired, and the paths of every file flagged dangerous so you can drill in.

As a library:

```python
from scanner.pipeline import run_security_scan, disarm_or_quarantine, is_dangerous

report = run_security_scan("file.dcm")
if is_dangerous(report):
    result = disarm_or_quarantine("file.dcm")   # {"action": "disarmed" | "quarantined", ...}
```

Web UI and API:

```bash
python server.py    # http://localhost:8899
```

Uploads are scanned in a temp directory and deleted right after, so PHI is never persisted.

Docker:

```bash
docker build -t dicomlock .
docker run --rm -p 8899:8899 dicomlock                             # API + web UI at http://localhost:8899
docker run --rm -v "$PWD/data:/data" --entrypoint dicomlock \
    dicomlock /data --disarm                                       # CLI on a mounted host directory
```

The image is about 425 MiB, runs as a non-root user, and exposes only port 8899. Default command is the API; override `--entrypoint dicomlock` to use the CLI on a mounted host directory.

## How it works

1. **Scan.** Deterministic, rule-based checks, no ML: preamble and polyglot signatures, length amplification, sequence-nesting depth, pixel-dimension and decompression bombs, private-tag payloads, codec-CVE exposure, and metadata integrity.
2. **Disarm.** For files that are dangerous but recoverable, it zeroes the preamble, transcodes compressed pixels to native off the vulnerable codec (in a sandboxed subprocess), and filters private tags against a vendor allowlist. Lossless sources come out bit-exact. Lossy sources are decoded once with no new compression.
3. **Quarantine.** Anything it cannot safely rebuild, such as length bombs and files no backend can decode, is held back. It re-scans its own output, so it never emits a file that still fails a check.

The point of CDR is that it rebuilds from a validated canonical form instead of matching a known signature, so it neutralizes attacks it has never seen. That is the defense that holds up when vulnerabilities turn up faster than anyone can patch them, which is the situation for the systems a patch cycle reaches slowly: legacy and embedded medical devices, and software locked behind FDA recertification.

## Why this is a real problem

The 128-byte preamble can hold an executable header, so one file can be a valid scan and working malware at the same time (CVE-2019-11687, extended to Linux devices by ELFDICOM). Attacker-controlled length fields turn a 140-byte file into a multi-gigabyte allocation request. Encapsulated pixel and video data decodes through libjpeg, OpenJPEG, CharLS, and FFmpeg-class libraries that carry long CVE histories. Live examples in clinical software include the Orthanc auth bypass (CVE-2025-0896, CVSS 9.8) and MicroDicom remote code execution (CVE-2025-5943).

DicomLock works on the file. It does not break or weaken encryption and makes no claim to.

## Results

Reproducible with `python -m bench` and the scripts in [`_attack_test/`](_attack_test/). The real-clinical-data figures use public TCIA images, which are not shipped in this repo:

- Zero false positives across 945 real clinical files in three modalities and three body regions (575 chest CT, 100 abdomen CT, 120 brain MR, 150 chest radiographs), and zero on a separate mixed-compression corpus of 12 transfer syntaxes.
- 80 of 80 crafted attack files flagged by the expected check.
- pydicom, GDCM, and dcmtk accept the weaponized files without complaint; DicomLock flags every one.
- Disarmed pixels are bit-exact on native and lossless sources, checked against two independent decoders (GDCM and pylibjpeg).
- The codec decode is sandboxed, so a crashing or hanging decoder is contained and the file is quarantined, not the tool.

The attack fixtures in this repo are inert. Polyglots carry only magic bytes, and payload tags carry a header plus zero padding. No working malware ships here.

## Where it fits

Commercial DICOM CDR already exists (OPSWAT, Votiro), and there is academic prior art, so "nobody does this" is not the pitch. DicomLock's reason to exist is that it is open, self-hosted, auditable, and PACS-depth. The transcoding, the vendor allowlist, and the parser-bomb rejection are all readable in source and run inside your network. The natural first users are research-imaging and data-engineering teams that already ingest untrusted external DICOM.

It is a security and sanitization tool, not a medical device. It carries no diagnostic claim and no FDA clearance. See [THREAT_MODEL.md](THREAT_MODEL.md) for what it does and does not defend.

## Documentation

- [THREAT_MODEL.md](THREAT_MODEL.md), attacks defended and explicit non-claims
- [ARCHITECTURE.md](ARCHITECTURE.md), module specs
- [CONTRIBUTING.md](CONTRIBUTING.md), how to help with the CVE map, vendor allowlist, and codecs
- [SECURITY.md](SECURITY.md), vulnerability disclosure

## License

[Apache-2.0](LICENSE), © 2026 Vijay Thakore. Provided as is, without warranty. DicomLock is a sanitization tool, not a medical device, and makes no diagnostic claim. Validate disarmed files in your own environment before any clinical use, and run on de-identified data where you can.
