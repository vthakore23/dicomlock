#!/usr/bin/env python3
"""
DicomLock — Validation Script

Measures false positive rate on real DICOM files and detection rate on fakes.
Run after training to get key metrics.

Usage:
    python validate.py
    python validate.py --real data/tcia_ct --fakes data/fakes
"""

import argparse
import json
import pickle
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import pydicom

sys.path.insert(0, str(Path(__file__).parent))
from scanner.pixel_advanced import extract_all_features

MODEL_DIR = Path(__file__).parent / "models"


def load_model():
    model_path = MODEL_DIR / "rf_classifier.pkl"
    meta_path = MODEL_DIR / "rf_classifier_meta.json"

    with open(model_path, "rb") as f:
        model = pickle.load(f)
    with open(meta_path) as f:
        meta = json.load(f)

    return model, meta


def classify_dir(model, meta, dicom_dir: Path, max_files: int = None):
    """Classify all files in a directory. Returns list of (filename, real_prob, fake_prob)."""
    feature_names = meta["feature_names"]
    files = sorted(dicom_dir.glob("*.dcm"))
    if max_files:
        files = files[:max_files]

    results = []
    errors = 0

    for fpath in files:
        try:
            ds = pydicom.dcmread(str(fpath), force=True)
            features = extract_all_features(ds)
            if features is None:
                errors += 1
                continue

            features.pop("modality", None)
            features.pop("rows", None)
            features.pop("cols", None)

            X = np.zeros((1, len(feature_names)))
            for j, name in enumerate(feature_names):
                val = features.get(name, 0.0)
                X[0, j] = val if np.isfinite(val) else 0.0

            proba = model.predict_proba(X)[0]
            results.append((fpath.name, proba[0], proba[1]))

        except Exception:
            errors += 1

    return results, errors


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--real", type=str, default="data/tcia_ct")
    parser.add_argument("--fakes", type=str, default="data/fakes")
    parser.add_argument("--max-real", type=int, default=None)
    args = parser.parse_args()

    base = Path(__file__).parent
    real_dir = base / args.real
    fakes_dir = base / args.fakes

    model, meta = load_model()
    print("DicomLock — Validation Report")
    print(f"Model: {meta.get('model_type', 'Unknown')}, {meta.get('n_features', '?')} features")

    # --- Validate on REAL files ---
    print(f"\n=== REAL files ({real_dir}) ===")
    real_results, real_errors = classify_dir(model, meta, real_dir, args.max_real)

    if real_results:
        false_positives = sum(1 for _, _, fp in real_results if fp > 0.5)
        high_fp = sum(1 for _, _, fp in real_results if fp > 0.7)
        avg_real_prob = np.mean([rp for _, rp, _ in real_results])

        print(f"  Files classified: {len(real_results)} (errors: {real_errors})")
        print(f"  False positive rate (>50% fake): {false_positives}/{len(real_results)} = {false_positives/len(real_results):.1%}")
        print(f"  High-confidence FP (>70% fake):  {high_fp}/{len(real_results)} = {high_fp/len(real_results):.1%}")
        print(f"  Average real probability: {avg_real_prob:.1%}")

        # Show worst false positives
        sorted_by_fp = sorted(real_results, key=lambda x: -x[2])
        print(f"\n  Worst false positives:")
        for name, rp, fp in sorted_by_fp[:5]:
            marker = " <<< FP" if fp > 0.5 else ""
            print(f"    {name}: real={rp:.0%} fake={fp:.0%}{marker}")

    # --- Validate on FAKE files (per technique) ---
    if fakes_dir.is_dir():
        print(f"\n=== FAKE files ({fakes_dir}) ===")
        for tech_dir in sorted(fakes_dir.iterdir()):
            if tech_dir.is_dir() and any(tech_dir.glob("*.dcm")):
                tech_name = tech_dir.name
                fake_results, fake_errors = classify_dir(model, meta, tech_dir, 50)

                if fake_results:
                    true_positives = sum(1 for _, _, fp in fake_results if fp > 0.5)
                    avg_fake_prob = np.mean([fp for _, _, fp in fake_results])
                    detection_rate = true_positives / len(fake_results)

                    print(f"  {tech_name:<25} detection={detection_rate:.0%}  "
                          f"avg_fake_prob={avg_fake_prob:.0%}  "
                          f"({true_positives}/{len(fake_results)})")

    print("\n--- Summary ---")
    if real_results:
        specificity = 1 - false_positives / len(real_results)
        print(f"  Specificity (real files correctly passed): {specificity:.1%}")
    print("  (Retrain with more data to improve false positive rate)")


if __name__ == "__main__":
    main()
