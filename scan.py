#!/usr/bin/env python3
"""
DicomLock CLI shim — keeps `python scan.py ...` working from a source checkout.

The implementation lives in scanner/cli.py so the pip-installed `dicomlock` command and the
source-tree invocation share one code path. Usage:

    python scan.py <dicom_file_or_directory> [--disarm] [--deid]
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.cli import main

if __name__ == "__main__":
    main()
