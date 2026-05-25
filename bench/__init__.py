"""DicomLock benchmark engine.

A companion tool that pairs with the `dicomlock` package and measures it. It throws a
labeled corpus of inert attacks at both a matrix of real DICOM parsers/codecs and at
DicomLock's Content Disarm & Reconstruction, then reports detection, neutralization,
fidelity, and false-positive rates. This is the runnable execution of STUDY_DESIGN.md.

It imports `scanner` but is NOT part of the shipped package (pyproject keeps
packages=["scanner"]), so the core install stays lean.

Run:  python -m bench
"""

__version__ = "0.1.0"
