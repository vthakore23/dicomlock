"""
DicomLock — File Ingestion Module

Handles reading DICOM files, computing hashes, and parsing with pydicom.
Single entry point for all scanner modules that need to load a file.
"""

import hashlib
import os
from dataclasses import dataclass
from typing import Optional

import pydicom


@dataclass
class IngestedFile:
    """Result of ingesting a DICOM file."""
    filepath: str
    filename: str
    file_size: int
    sha256: str
    dataset: Optional[pydicom.Dataset]
    error: Optional[str]


def compute_sha256(filepath: str) -> str:
    """Compute SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def ingest(filepath: str) -> IngestedFile:
    """
    Read and parse a DICOM file.

    Returns an IngestedFile with the parsed dataset and file metadata.
    If the file can't be parsed, dataset will be None and error will be set.
    """
    filepath = os.path.abspath(filepath)
    filename = os.path.basename(filepath)
    file_size = os.path.getsize(filepath)
    sha256 = compute_sha256(filepath)

    try:
        ds = pydicom.dcmread(filepath, force=True)
        return IngestedFile(
            filepath=filepath,
            filename=filename,
            file_size=file_size,
            sha256=sha256,
            dataset=ds,
            error=None,
        )
    except Exception as e:
        return IngestedFile(
            filepath=filepath,
            filename=filename,
            file_size=file_size,
            sha256=sha256,
            dataset=None,
            error=str(e),
        )
