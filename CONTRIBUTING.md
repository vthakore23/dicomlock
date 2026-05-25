# Contributing to DicomLock

Thanks for helping harden medical imaging. DicomLock is Apache-2.0 and welcomes contributions,
especially from imaging-informatics engineers, security researchers, and PACS/vendor teams.

## Ground rules

- **Inert fixtures only.** Never commit working malware. Attack fixtures carry magic bytes / inert
  headers + zero padding, exactly like [`make_tampered_corpus.py`](make_tampered_corpus.py).
- **Honesty over hype.** Checks report *exposure*, not proven exploits. Keep severities truthful
  (codec routing is `warn`, not `critical`). Don't claim DicomLock breaks encryption. It doesn't.
- **No regressions on the two headline metrics:** 0 false positives on the 575 real CTs, and 100%
  detection on the attack corpus. CI of your change should reproduce both.

## Dev setup

```bash
git clone https://github.com/vthakore23/dicomlock.git
cd dicomlock
pip install -e ".[server,full]"
python make_tampered_corpus.py          # generate the inert corpus
python _attack_test/validate_phase1.py  # must show 0 FP + all fixtures detected
```

## Before you open a PR

Run the full proof suite and confirm it stays green:

```bash
python _attack_test/validate_phase1.py    # 0 FP on clean samples + detection on the corpus
python _attack_test/validate_scale.py     # 0 FP across all 575 real CTs
python _attack_test/compare_baseline.py   # still beats pydicom / GDCM / dcmtk
python _attack_test/disarm_compressed.py  # CDR still bit-exact
python _attack_test/test_allowlist.py     # private-tag allowlist behavior
```

If you add or change a check, add a matching fixture to `make_tampered_corpus.py` **and** an entry
to the `expected` map in `_attack_test/validate_phase1.py` so the regression suite covers it.

## High-value contribution areas

- **Codec-CVE map** ([`scanner/data/dicom_codec_cve.json`](scanner/data/dicom_codec_cve.json)):
  refresh against NVD/CISA; every CVE id must be auditable at the NVD url in `_meta`.
- **Vendor private-tag allowlist**
  ([`scanner/data/vendor_private_tags.json`](scanner/data/vendor_private_tags.json)): expand from
  real GE/Siemens/Philips/Canon/Hologic private dictionaries. Default-deny: an incomplete list only
  over-strips (safe), so accuracy matters more than completeness.
- **Decoder coverage**: broaden transcode paths in [`scanner/disarm.py`](scanner/disarm.py) and
  the TransferSyntax-to-decoder map in [`scanner/codec_cve.py`](scanner/codec_cve.py).
- **New attack classes**: bring a real, demonstrable construction (with a citation/CVE class) plus
  an inert fixture and a check.

## Style

- Deterministic, rule-based checks (no ML in the default scan path).
- Each check returns `list[Finding]` with an honest severity and an actionable `details` string.
- Keep dependencies lean; the core install must keep scan **and** disarm working out of the box.

## Licensing & sign-off

By contributing you agree your work is licensed under Apache-2.0. Sign off your commits (DCO):

```bash
git commit -s -m "..."
```

## Reporting security issues

Don't open a public issue for a vulnerability in DicomLock itself. See [SECURITY.md](SECURITY.md).
