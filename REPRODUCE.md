# Reproducing the DicomLock results

This file reproduces the numbers reported in the README and the preprint. The benchmark engine in
[`bench/`](bench/) is the single source of those numbers. It imports the shipped `scanner` package,
runs a labeled corpus through both a matrix of real DICOM toolkits and through DicomLock's CDR, and
prints the metrics with confidence intervals.

## Setup

```bash
git clone https://github.com/vthakore23/dicomlock
cd dicomlock
pip install -e .            # installs scanner + decoder backends (gdcm, pylibjpeg)
```

The benchmark's parser matrix also calls `dcmtk` (`dcmdump`). Without it, the other two toolkits
(pydicom and GDCM) still run and the report notes dcmtk as unavailable. On conda:
`conda install -c conda-forge dcmtk --solver=libmamba`.

Environment used for the published run: Python 3.12, pydicom 3.0.1, numpy, python-gdcm, pylibjpeg
(+openjpeg, +libjpeg), Pillow, dcmtk. Numbers last reproduced 2026-05-25.

## One command

```bash
python -m bench
```

This writes `bench/results.json` and prints detection, false positives, neutralization, fidelity,
differentiation, a by-attack-class table, and the statistical section (Wilson intervals, the
rule-of-three false-positive bound, and the McNemar comparison against the toolkit matrix). On a clean
clone it runs the inert corpus that ships in the repo; it also generates the adversarial corpus on
first run.

## What each command reproduces

| Result | Command |
|--------|---------|
| Detection 80/80, neutralization 80/80, false positives on the curated set, differentiation, McNemar | `python -m bench` |
| CDR bit-exact fidelity at scale (623/623 native and lossless across 13 transfer syntaxes) | `python -m bench.fidelity` |
| Diverse-modality false positives and fidelity (0 FP, 370/370 bit-exact on MR, XR, and abdomen CT) | `python -m bench.diverse_check` |
| Residual re-identification risk across public "de-identified" datasets | `python -m bench.reid_audit` |
| Re-identification score vs a standard tag anonymizer (dicognito) | `python -m bench.reid_vs_anonymizer` |
| The adversarial corpus that tries to break the tool (inert, labeled) | `python -m bench.generate` |
| Pinned vulnerable codec (OpenJPEG 2.3.0 + ASan), optional | `python -m bench.pinned --demo FILE.dcm` |

## Real clinical data (not shipped here)

This repo contains no patient data. The real-clinical-data figures (0 false positives across 945 real
files in three modalities and three body regions, and the bit-exact rebuilds at scale) are measured
on public collections from The Cancer Imaging Archive, which you fetch yourself. The bundled
[`download_tcia.py`](download_tcia.py) pulls one inert slice per series over the public NBIA API:

```bash
python download_tcia.py --ct 500 --xr 150                                                # chest CT and chest radiography
python download_tcia.py --collection UPENN-GBM --modality MR --count 120                 # brain MR
python download_tcia.py --collection TCGA-KIRC --modality CT --count 100 --output-name tcia_ct_abdomen  # abdomen CT
```

Files land in `data/tcia_ct/`, `data/tcia_xr/`, `data/tcia_mr/`, and `data/tcia_ct_abdomen/` (all
gitignored). Then:

```bash
python -m bench                                                              # the false-positive scale pass picks up data/tcia_ct automatically
python -m bench.fidelity                                                     # bit-exact rebuilds across the CTs and bundled diverse test data
python -m bench.diverse_check --dir data/tcia_ct_abdomen                     # false positives + fidelity over the diverse modalities you pulled
python -m bench.reid_audit --dir data/tcia_ct_abdomen --label "CT (abdomen, TCGA-KIRC)"  # residual re-identification risk
```

Counts vary slightly run to run because TCIA series selection is sampled, so treat the published
totals as the result on the specific pull described in the preprint, not an exact re-draw.

## Pinned vulnerable codec (optional, needs Docker)

The codec-neutralization result uses a pinned, instrumented decoder built in Docker. See
[`_attack_test/aim3/`](_attack_test/aim3/). The image builds OpenJPEG 2.3.0 with AddressSanitizer; the
harness feeds a JPEG 2000 stream to it raw, then through CDR, and records the difference. This step is
optional and is skipped gracefully if the image is absent.

## What reproduces from a clean clone, and what does not

- Inert corpus, detection, neutralization, fidelity on bundled data, differentiation, and the full
  statistical report: yes, with `python -m bench` alone.
- The real-clinical false-positive and fidelity figures: you supply the public TCIA data first (no PHI
  is shipped).
- The pinned-codec result: you build the Docker image first.

All shipped attack fixtures are inert. Polyglots carry only magic bytes, and payload tags carry a
header followed by zero padding. No working malware is in this repository.
