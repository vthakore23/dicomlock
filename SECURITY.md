# Security Policy

DicomLock is a security tool that parses hostile input, so its own robustness matters.

## Reporting a vulnerability

**Do not open a public GitHub issue for a vulnerability in DicomLock itself.**

Please report privately via one of:

- GitHub's [private vulnerability reporting](https://github.com/vthakore23/dicomlock/security/advisories/new)
  (Security → Report a vulnerability), or
- email **hello@dicomlock.com**.

Include: affected version/commit, a description, and an **inert** reproducer (a crafted DICOM that
demonstrates the issue without carrying working malware). We aim to acknowledge within a few days
and to coordinate a fix and disclosure timeline with you.

## In scope

- A crafted DICOM that **crashes, hangs, or exhausts resources** in the scanner/disarm path
  (the tool becoming the victim).
- A file that **passes disarm but remains dangerous** (the re-scan verification failing to catch
  residual danger) — this is the most serious class.
- A disarm that **silently alters diagnostic pixels** on a native/lossless input (loss of clinical
  fidelity).

## Out of scope

- CVEs in upstream decoders/toolkits (libjpeg, OpenJPEG, CharLS, OpenJPH, FFmpeg, pydicom, GDCM) —
  report those upstream. DicomLock *reports exposure* to these; it does not own their fixes.
- The bundled `dicom_codec_cve.json` being out of date — open a normal PR to refresh it.
- Findings labeled "exposure" (e.g. `codec_cve` warnings) behaving as documented — exposure is not
  a claim of exploitability.

## Handling test artifacts

The attack corpus in `samples/tampered/` and `_attack_test/` is **inert by design** (magic bytes /
inert headers + zero padding). Never submit or commit working malware, even in a report.
