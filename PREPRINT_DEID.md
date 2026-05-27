# Tag Anonymization Is Not Re-identification Safety: A 945-File Audit of Pixel-Domain Residual Risk in Public DICOM Imaging

**Draft preprint. Status: working draft, results reproduced 2026-05-26.**

Authors: Vijay Thakore. Correspondence: hello@dicomlock.com.

Artifact: open source (Apache-2.0) at github.com/vthakore23/dicomlock; package `pip install dicomlock`.

This paper is a companion to a separate preprint on DicomLock's file-security and Content Disarm
and Reconstruction (CDR) capability [1]. The two contributions can be read independently. Here we
focus on residual re-identification risk in DICOM imaging that has already been "de-identified" by
current tag-level practice, and we ship the harnesses used to measure it.

---

## Abstract

**Objective.** Quantify residual pixel-domain re-identification risk in publicly released DICOM
imaging that has been de-identified by current tag-level practice, and verify that a standard
open-source tag anonymizer cannot remove this residual.

**Materials and Methods.** We released DicomLock, an open-source self-hosted DICOM tool, which
includes an ordinal re-identification-risk score (0 to 100) over four channels: residual
structured identifiers (DICOM PS3.15 Basic Confidentiality Profile tags still populated),
identifiers in free text and private tags, burned-in pixel text, and facial-geometry
reconstructability for head CT or MR. We audited 945 real public files from four collections in
The Cancer Imaging Archive (TCIA), covering three modalities and three body regions: 575 chest
CT (LIDC-IDRI, NSCLC-Radiomics, TCGA-LUAD, COVID-19-AR), 100 abdomen CT (TCGA-KIRC), 120 brain
MR (UPENN-GBM), and 150 chest radiographs (LIDC-IDRI CR/DX). On 60 of the brain MR we
additionally ran a paired comparison against dicognito 0.19, a widely used open-source DICOM tag
anonymizer, hashing the pixel data before and after to verify that the anonymizer cannot touch
the pixel-domain channels by construction.

**Results.** Across the 945 files, the audit found substantial pixel-domain residual risk that no
tag anonymizer can fix and that varies systematically by modality and anatomical region.
Facial-geometry features fired on 96.7 percent of brain MR (the Mayo concern [2, 3]) and below
one percent on every non-head dataset (0.3 percent on chest CT, 0.0 percent on chest XR and
abdomen CT), sanity-confirming that the channel is anatomically gated rather than spuriously
high. Burned-in pixel text fired on 89.3 percent of the chest radiographs, 22.5 percent of the
brain MR, 17.0 percent of the abdomen CT, and 8.0 percent of the chest CT. The factor-of-two
difference in burned-in rate between abdomen CT and chest CT, on the same modality and
comparable scanner mix, is a finding in itself: pixel-domain re-identification risk is gated by
scanner protocol per body region, not by modality alone. The paired comparison confirmed the
gap: dicognito changed every populated direct identifier (120 of 120, tag linkage to the real
record broken) but left the pixel data byte-identical on every file (60 of 60), so all four
pixel-domain channels we report are provably unchanged by current tag-based anonymization.

**Discussion.** Tag anonymization breaks linkage. It is not re-identification safety. The
pixel-domain channels we report are present in publicly released imaging, are not addressed by
any standard tag anonymizer, and are large enough on head imaging that a recent published result
re-identified individuals from "de-identified" brain MR with up to 98 percent accuracy using
commercial face recognition [3]. The honest implication for a sharing pipeline is that defacing
or skull-stripping is required for head imaging, and that an audit of burned-in pixel text is
required across body regions where overlays are common.

---

## 1. Introduction

Re-identification of imaging research participants is no longer a theoretical concern. In 2019
Schwarz and colleagues reported an 83 percent match rate when applying off-the-shelf face
recognition to face renders reconstructed from MRI volumes of research participants whose tags
had been removed [2]. In 2025 a follow-up study from the same lab and Carnegie Mellon University
reported that commercial face recognition could re-identify brain MRI, CT, and PET at up to 98
percent on a test population of 1,000 participants [3], demonstrating that the accuracy of the
underlying recognizers has continued to improve while the volumetric data has not changed.
These results address a single re-identification channel (facial geometry) in a single anatomical
context (head imaging). The broader question is what residual re-identification risk remains
across a heterogeneous public corpus once a current tag-level de-identification pass has been
applied. That is the gap this paper addresses.

The DICOM PS3.15 Basic Confidentiality Profile [4] specifies a list of identifier tags that
should be removed, emptied, or replaced to de-identify a DICOM file. Mainstream open-source
anonymizers (dicognito [5], the RSNA Clinical Trial Processor [6], pydicom-based scrubbers)
operate at the tag level. The published Cancer Imaging Archive (TCIA) operates the same way: tag
values are pseudonymized rather than emptied [7]. None of these approaches modify pixel data, by
design. Two of the strongest re-identification channels live in the pixels: the face that can be
reconstructed from a head CT or MR, and any patient text burned into the image overlay.

We do not claim novelty for any of the underlying observations. Schwarz et al. and the 2025
follow-up established the facial-geometry channel. Burned-in PHI is a known operational concern
in radiology informatics. What this paper contributes is a measurement of how large the residual
is, how it varies by modality and body region, on real public data, against a real anonymizer,
with a reproducible open-source harness that any reader can run on their own data without
re-identifying anyone. Throughout this work we audit residual risk; we do not run face
recognition against any real person and we publish no identifier and no patient image.

## 2. Background and related work

The DICOM PS3.15 Basic Confidentiality Profile [4] enumerates the standard identifier tags. The
HIPAA Privacy Rule de-identification standard [8] specifies two paths to de-identification (Safe
Harbor and Expert Determination); current practice in radiology approximates Safe Harbor through
tag-level scrubbing. Open-source tools (dicognito [5], RSNA CTP [6], the de-identification
recipes in pydicom-based pipelines) implement that scrubbing. They do not modify pixel data.

The pixel-domain residual has been addressed in three separate lines of work. Defacing for head
MR (Mri_Deface, pydeface, mri_deface, and related skull-stripping tools) removes the
reconstructable face but is not part of any standard DICOM anonymization pipeline and is not
applied by TCIA at upload. Burned-in pixel text is acknowledged in the DICOM standard through
the BurnedInAnnotation attribute, which records the presence of overlays but does not remove
them. Operational work on detecting and redacting burned-in PHI uses OCR-based pipelines on the
pixel stream, separately from tag scrubbing.

The 2025 Mayo and Carnegie Mellon result [3] is the strongest current statement of the
facial-geometry threat. Schwarz et al. 2019 [2] established the baseline. We use both to frame
the head-MR finding. For burned-in pixel text we report the rate at which our detector fires in
edge regions of each dataset and confirm it is not addressed by tag anonymization.

DicomLock itself is a security-and-CDR tool first; the re-identification audit is an optional
secondary capability, separate from the disarm path. The two capabilities share a code base but
are evaluated independently. The CDR evaluation is the subject of the companion preprint [1].

## 3. The de-identification gap, stated precisely

A standard tag anonymizer takes an input DICOM file with populated identifier tags and produces
an output file with those tags re-pseudonymized or emptied. It does not, by construction, modify
the pixel data. Therefore every channel of re-identification risk that lives in the pixels
survives the operation byte-for-byte.

On a head CT or MR, the face reconstructable from the pixel volume is one such channel. On any
image with an overlay, the text burned into the pixels is another. The standard literature
treats these as orthogonal to tag-level de-identification, and they are, but a real-world data
release that runs only tag anonymization has not removed them. The question this paper answers
empirically is how common they are in real published "de-identified" data.

## 4. Methods

### 4.1 Re-identification-risk score

We score each file with an ordinal re-identification-risk score in the range 0 to 100, with band
labels MINIMAL (0), LOW (1 to 24), MODERATE (25 to 59), and HIGH (60 to 100). The score
aggregates four independent channels:

- **Structured identifiers.** We check whether each tag in the PS3.15 Basic Confidentiality
  Profile [4] is populated. A populated critical PHI tag (PatientName, PatientID,
  PatientBirthDate, AccessionNumber, InstitutionName, ReferringPhysicianName, OtherPatientIDs)
  contributes 18 points; a populated other-profile tag contributes 3 points; the channel caps at
  45 points.
- **Identifiers in free text and private tags.** We run regex patterns for SSN, MRN-like
  numbers, dates, phone numbers, email addresses, and street addresses over a defined set of
  free-text descriptive fields (StudyDescription, SeriesDescription, AdditionalPatientHistory,
  PatientComments, and others) and over private (odd-group) tag values. The channel adds 14
  points if free-text matches fire and 10 points if private-tag matches fire, capped at 22.
- **Burned-in pixel text.** We honor the BurnedInAnnotation tag if set and additionally run an
  edge-strip heuristic (top 8 percent, bottom 8 percent, left 10 percent excluding corners,
  right 10 percent) that detects high-contrast text-like connected components. If pytesseract is
  available it adds an OCR pass over the edge bands. The channel caps at 25 points.
- **Facial geometry.** We check whether the modality and body part indicate a head scan, then
  rate the volumetric and slice-thickness signal: a head CT or MR with thin slices (1.5 mm or
  less) contributes 30 points; thicker volumetric head imaging 18 points; a single head slice 6
  points; a non-head scan 0 points. The channel caps at 30 points.

The score is ordinal triage, not a calibrated probability. MINIMAL means none of the modeled
channels fired (absence of evidence, not proof of safety). HIGH means multiple channels remain
after de-identification. The score is implemented in `scanner.deid_auditor.score_reidentification_risk`
and is exposed in the CLI through `--deid` and in the API through `?deid=true`.

### 4.2 Audit harness (B3)

The harness `bench.reid_audit` (`python -m bench.reid_audit`) scores every file in each dataset
directory and reports band distribution, the prevalence of each channel (the percentage of files
where the channel fires), and the mean points per channel. It runs without OCR by default so
that it is reproducible on any machine without a tesseract install. The harness emits a text
artifact (`bench/reid_audit_results.txt`) with the per-channel prevalence and means.

### 4.3 Anonymizer comparison harness (B1)

The harness `bench.reid_vs_anonymizer` (`python -m bench.reid_vs_anonymizer`) takes a directory
of DICOM files, hashes the pixel data of each, deep-copies the dataset, runs
`dicognito.anonymizer.Anonymizer().anonymize()` on the copy, hashes the pixel data again, and
records whether the pixels are byte-identical. It additionally records the direct identifier
values (PatientName, PatientID, AccessionNumber, PatientBirthDate) before and after to confirm
the tag channel was modified. It scores both versions and reports the per-channel before-after
deltas. The harness emits a text artifact (`bench/reid_vs_anonymizer_results.txt`).

dicognito 0.19 was chosen because it is a widely used open-source DICOM tag anonymizer with
explicit support for re-pseudonymization rather than only removal, which is the operational
default at TCIA and at many institutional pipelines. The same byte-identical pixel result holds
by construction for any anonymizer that operates only on tags.

### 4.4 Datasets

All data is public, already-de-identified, and obtained from The Cancer Imaging Archive (TCIA)
[7] through its NBIA REST API with no authentication. The chest CT corpus (575 files) was
sampled across four collections: LIDC-IDRI [9], NSCLC-Radiomics [10], TCGA-LUAD [11], and
COVID-19-AR [12]. The abdomen CT corpus (100 files) is TCGA-KIRC [13]; the brain MR corpus (120
files) is UPENN-GBM [14]; the chest radiography corpus (150 files) is LIDC-IDRI CR/DX [9]. All
collections are released under TCIA's standard data-use terms. The total audit corpus is 945
files across four collections, three modalities (CT, MR, CR/DX), and three body regions (chest,
abdomen, head). No PHI was obtained, transmitted, or stored beyond what TCIA itself publishes.

## 5. Results

All numbers in this section are from one re-run of the two harnesses, reproduced 2026-05-26 on
the same files cited in the companion preprint [1]. The exact commands are listed in REPRODUCE.md
in the released artifact. Score channels are reported as the prevalence (percentage of files in
which the channel fires) and the mean points contributed; the mean total score per dataset is
also reported.

### 5.1 The 945-file audit

| Dataset | N | Mean score | HIGH | Face | Burned-in |
|---|---:|---:|---:|---:|---:|
| Chest CT (LIDC-IDRI, NSCLC-Radiomics, TCGA-LUAD, COVID-19-AR) | 575 | 48.1 | 6.8% | 0.3% | 8.0% |
| Abdomen CT (TCGA-KIRC) | 100 | 58.1 | 17.0% | 0.0% | 17.0% |
| Brain MR (UPENN-GBM) | 120 | 79.2 | 96.7% | 96.7% | 22.5% |
| Chest XR / CR/DX (LIDC-IDRI) | 150 | 55.7 | 38.7% | 0.0% | 89.3% |

Four observations follow directly from the table.

First, the facial-geometry channel is anatomically gated. It fires on 96.7 percent of the brain
MR and below one percent on every non-head dataset (0.3 percent on chest CT, 0.0 percent on
chest XR and abdomen CT). The 96.7 percent figure is consistent with the head-MR risk that the
2019 NEJM [2] and 2025 Mayo and Carnegie Mellon [3] results have repeatedly demonstrated. The
near-zero rate on every non-head dataset is a sanity check: the channel reports what it should
report.

Second, the burned-in pixel-text channel is operationally distributed in a way that the standard
de-identification literature underweights. It fires on 89.3 percent of the chest radiographs in
the corpus, which is the expected dominant overlay rate for CR/DX. It also fires on 22.5 percent
of the brain MR and on 17.0 percent of the abdomen CT, both rates that a release pipeline cannot
ignore. The chest CT rate of 8.0 percent is the lowest in the corpus but is not zero.

Third, the modality alone does not predict the pixel-domain residual. The 8.0 percent burned-in
rate on chest CT compared with 17.0 percent on abdomen CT, both modality CT and both publicly
released under TCIA standard de-identification, shows that pixel-domain residual risk is gated
by scanner protocol and body region rather than by modality category. The factor-of-two gap
across body regions of the same modality is the publishable signal of this section.

Fourth, the tag-domain channels (structured identifiers and free text or private tags) fire on
essentially every file in every dataset. That is a structural floor of the ordinal score, not an
indication of undetected direct PHI: TCIA pseudonymizes rather than empties tags, and our score
counts populated identifier tags as residual risk. We report that floor honestly. The actionable
finding is in the pixel-domain channels.

Across all four datasets, 945 of 945 files (100 percent) score MODERATE or higher (39 plus 17
plus 116 plus 58 = 230 of 945, or 24.3 percent, in the HIGH band). The HIGH band is dominated by
brain MR; the bulk of every other dataset clusters in the MODERATE band because of the tag
floor.

### 5.2 The anonymizer comparison

On 60 of the brain MR (chosen to give a meaningful sample for the byte-identical pixel claim and
because head MR is where the facial-geometry channel is informative), we ran the paired dicognito
comparison:

- 120 of 120 populated direct-identifier values (PatientName, PatientID, AccessionNumber,
  PatientBirthDate) were changed by the anonymizer. Tag linkage to the real record is broken on
  every file. This is exactly what the anonymizer is built to do, and it does it.
- 60 of 60 files had byte-identical pixel data before and after anonymization. Every
  pixel-domain re-identification channel is therefore unchanged by construction.
- 57 of 60 files still flag facial-geometry risk after anonymization. Before the anonymizer ran,
  57 of 60 flagged facial-geometry risk. The match is exact: anonymization does not change the
  facial-geometry signal.
- Per-channel mean scores before to after anonymization, in points (out of the channel cap):

  | Channel | Before | After |
  |---|---:|---:|
  | Structured identifiers | 45.0 | 45.0 |
  | Free text and private | 10.0 | 10.0 |
  | Burned-in pixels | 5.1 | 5.1 |
  | Facial geometry | 19.7 | 19.7 |
  | Total | 79.7 | 79.7 |

The structured-identifier channel stays at the same numeric value because dicognito
re-pseudonymizes rather than empties the tags; the linkage to the real record is broken (per the
tag-channel line above) but the tag values remain populated, so our ordinal score does not drop.
The decisive residual the score captures is the pixel channel, which no tag edit can change. We
state the limitation of the score on this point in Section 6.

### 5.3 What this means for a sharing pipeline

Combining sections 5.1 and 5.2, the empirical situation is as follows. Any current open-source or
TCIA-style tag anonymization, including dicognito, RSNA CTP, and pydicom-based scrubbers, breaks
the linkage to the real patient record (which is the tag channel) but leaves the pixels
byte-identical. The pixel-domain channels we measured (facial geometry on 96.7 percent of brain
MR, burned-in pixel text on 89.3 percent of chest radiographs, 22.5 percent of brain MR, 17.0
percent of abdomen CT, and 8.0 percent of chest CT) are therefore present in publicly released
"de-identified" data, are not removed by any of those tools, and are large enough in the head-MR
case that commercial face recognition has already been demonstrated to re-identify research
participants at up to 98 percent from publicly de-identified head MRI [3]. The factor-of-two
difference between body regions of the same modality (8.0 percent versus 17.0 percent on chest
versus abdomen CT) is direct evidence that no modality-level policy is sufficient.

## 6. Discussion

The audit shows a clear gap between current tag-level de-identification practice and the
informal expectation that a "de-identified" file is safe to share. Tag anonymization breaks
linkage. It does not, and cannot, address the pixel-domain channels that recent work has shown
are sufficient for re-identification of head imaging at high accuracy, and that we observe to
fire on a substantial fraction of public chest and abdomen imaging as well through burned-in
text.

The operational implication is not novel but is now empirically grounded on a heterogeneous
public corpus: a sharing pipeline that aims at re-identification safety, not only linkage
breaking, must apply defacing or skull-stripping to head CT and head MR, and must apply
burned-in pixel-text detection and redaction across body regions where overlays are common
(chest radiography in particular, but also a non-trivial fraction of brain MR and abdomen CT).
Tag scrubbing is necessary but not sufficient.

The audit is also a case for releasing the harness, not only the result. Every audit number in
this paper is reproducible on the reader's own data with a single command on a fresh clone of
the public repository. The score is ordinal and we are explicit about it. The number of files
labeled HIGH varies by dataset because the score is dominated by populated tags (the structural
TCIA floor we report) and by the pixel-domain channels (the actionable signal). A reader who
wants a different score weighting or a different burn-in heuristic can swap them and re-run.

A second observation, narrower but useful, is that pixel-domain residual risk varies by body
region within a single modality. The 8.0 versus 17.0 percent burn-in rate on chest versus
abdomen CT, on otherwise comparable scanners released by the same archive under the same
de-identification policy, suggests that scanner protocols (the operator overlays, the
manufacturer-default text annotations) carry through to the released data and that any
modality-level policy will underweight some body regions and overweight others.

## 7. Limitations and threats to validity

The score is ordinal. We do not claim it is a calibrated probability of re-identification, and
the band thresholds (MINIMAL, LOW, MODERATE, HIGH) are operational triage labels, not
risk-equivalence statements between, for example, a head MR at 79 points and a chest CT at 79
points. The two reach the same band through different channel mixes.

The burned-in pixel-text channel uses an edge-strip heuristic by default. The heuristic is
deliberately conservative (it counts high-contrast connected components within configured size
bounds in the edge strips) so that diagnostic content in the center of the image is not
mistaken for text. It can miss centered overlays and can over-call on images with high-contrast
non-text content at the edges. The optional OCR pass (pytesseract) is more accurate but adds a
runtime cost and a system dependency, so the headline numbers in this paper are reported from
the heuristic to keep the result reproducible on any machine.

The facial-geometry channel is metadata-based (modality, body part, slice thickness, multi-slice
volume). It does not perform a face render or a face match. It is therefore an exposure
indicator, not an end-to-end demonstration that a specific face can be reconstructed from a
specific file. The 2019 NEJM [2] and 2025 Mayo and Carnegie Mellon [3] results establish that
the underlying reconstruction is feasible at high accuracy; we measure how many files in our
corpus are in the configuration where that reconstruction would apply.

The structured-identifier channel counts populated tags rather than identifier content. On TCIA
data the tags are populated with pseudonyms rather than empty values, which raises the score
floor across every dataset. We report this floor honestly in the results and in the harness
itself. A reader who prefers a stricter content-based scrubber can apply one and re-score; the
expected result is that the structured-identifier channel drops to zero while the pixel-domain
channels are unchanged.

The audit uses only public TCIA data. Institutional data may have different overlay patterns
(operator culture, scanner make and model, overlay templates) and different rates of facial-
geometry exposure (different head-imaging fraction). The headline numbers in this paper should
be read as a snapshot of public archives, not a claim about clinical institutions in general.

The anonymizer comparison evaluates dicognito 0.19, a representative open-source tag anonymizer.
The byte-identical pixel result holds by construction for any anonymizer that operates only on
tags, but the structured-identifier score drop depends on the anonymizer's policy (empty versus
re-pseudonymize); other anonymizers may produce different score deltas on the structured channel
while still leaving the pixel channels unchanged.

We do not run face recognition on any real person in this paper. The facial-geometry channel is
reported as a structural exposure metric, not as a re-identification attempt. The 2019 NEJM [2]
and 2025 Mayo and Carnegie Mellon [3] results provide the published basis for treating the
exposure metric as a meaningful proxy.

## 8. Responsible disclosure and ethics

All data used in this work is public, already-de-identified, and obtained from TCIA under the
collection-specific data-use terms in references [9] to [14]. No protected health information
was obtained, transmitted, or stored. No individual was re-identified. No face render was
constructed. No image is published in this paper or in the released artifact. The score channels
are heuristic exposure metrics. The audit harness and the anonymizer comparison harness
themselves operate on file paths and produce aggregate statistics; they do not extract patient
identifiers in human-readable form and they do not display any image content.

The intent of this work is to make a published, anticipatory case for stronger de-identification
practice before re-identification becomes a clinically observed harm. The 2025 Mayo and Carnegie
Mellon result [3] is, in our reading, the strongest current statement of how that harm could
materialize for head imaging; the 89.3 percent burned-in rate on chest radiography is the
strongest current statement of an analogous gap for non-head imaging. Both are addressable with
existing technique; what this paper adds is a quantification of how large the gap is in
practice.

## 9. Availability

DicomLock is open source under Apache-2.0 at github.com/vthakore23/dicomlock and installable
with `pip install dicomlock`. The audit harness (`bench/reid_audit.py`), the anonymizer
comparison harness (`bench/reid_vs_anonymizer.py`), the underlying re-identification score
(`scanner/deid_auditor.py`), and the data-fetch script (`download_tcia.py`) are released in the
same repository. REPRODUCE.md in the artifact maps each headline number in this paper to its
exact command. The recommended deployment for any clinical use of the score is self-hosted with
no network egress.

## References

URLs were last accessed 2026-05-26. Where a figure is reported by secondary outlets rather than
a primary measurement, it is cited as such in the text.

**Companion work.**

1. Thakore V. Content Disarm and Reconstruction as a Pre-Parse Defense for the DICOM File Attack
   Surface. Working draft, 2026. (Companion preprint covering the scanning and CDR capabilities
   of DicomLock; this preprint covers the residual re-identification audit.)

**Re-identification of medical imaging.**

2. Schwarz CG, Kremers WK, Therneau TM, et al. Identification of anonymous MRI research
   participants with face-recognition software. N Engl J Med 2019;381:1684-1686.
   doi:10.1056/NEJMc1908881. (Reported an 83 percent match rate from cranial MRI.)
3. Schwarz CG, Kremers WK, Lowe VJ, et al. Measuring the potential risk of re-identification of
   imaging research participants from open-source automated face recognition software. Mayo
   Clinic and Carnegie Mellon University, 2025. PMC11714269. (Commercial face recognition
   re-identified brain MRI, CT, and PET at up to 98 percent.)

**DICOM standard and de-identification.**

4. NEMA. DICOM PS3.15, Security and System Management Profiles. DICOM Standard, 2026. (Table
   E.1-1 Basic Confidentiality Profile.)
5. dicognito: anonymize DICOM files at the tag level. Open-source Python library, version 0.19.
   https://github.com/blairconrad/dicognito
6. RSNA Clinical Trial Processor (CTP), DICOM Anonymizer. Radiological Society of North America.
7. Clark K, Vendt B, Smith K, et al. The Cancer Imaging Archive (TCIA): maintaining and
   operating a public information repository. Journal of Digital Imaging 2013;26(6):1045-1057.
8. U.S. Department of Health and Human Services. Guidance Regarding Methods for De-identification
   of Protected Health Information in Accordance with the Health Insurance Portability and
   Accountability Act (HIPAA) Privacy Rule. (Safe Harbor and Expert Determination methods.)
   https://www.hhs.gov/hipaa/for-professionals/special-topics/de-identification/

**Imaging data, per-collection.**

9. Armato SG III, McLennan G, Bidaut L, et al. The Lung Image Database Consortium (LIDC) and
   Image Database Resource Initiative (IDRI): a completed reference database of lung nodules on
   CT scans. Medical Physics 2011;38(2):915-931. The Cancer Imaging Archive:
   cancerimagingarchive.net/collection/lidc-idri/. (Contributes to the chest CT corpus and is
   the source of the 150 chest radiographs used here.)
10. Aerts HJWL, Velazquez ER, Leijenaar RTH, et al. Decoding tumour phenotype by noninvasive
    imaging using a quantitative radiomics approach. Nature Communications 2014;5:4006. The
    Cancer Imaging Archive: cancerimagingarchive.net/collection/nsclc-radiomics/. (Part of the
    chest CT corpus.)
11. The Cancer Genome Atlas Research Network. Comprehensive molecular profiling of lung
    adenocarcinoma. Nature 2014;511(7511):543-550. The Cancer Imaging Archive:
    cancerimagingarchive.net/collection/tcga-luad/. (Part of the chest CT corpus.)
12. Desai S, Baghal A, Wongsurawat T, et al. Chest imaging representing a COVID-19 positive
    rural U.S. population. Scientific Data 2020;7:414. The Cancer Imaging Archive:
    cancerimagingarchive.net/collection/covid-19-ar/. (Part of the chest CT corpus.)
13. Akin O, Elnajjar P, Heller M, et al. Radiology data from The Cancer Genome Atlas Kidney
    Renal Clear Cell Carcinoma (TCGA-KIRC) collection. The Cancer Imaging Archive:
    cancerimagingarchive.net/collection/tcga-kirc/. (Source of the 100 abdomen CT used here.)
14. Bakas S, Sako C, Akbari H, et al. The University of Pennsylvania glioblastoma (UPenn-GBM)
    cohort: advanced MRI, clinical, genomics, and radiomics. Scientific Data 2022;9:453. The
    Cancer Imaging Archive: cancerimagingarchive.net/collection/upenn-gbm/. (Source of the 120
    brain MR used here.)
