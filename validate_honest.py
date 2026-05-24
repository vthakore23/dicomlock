#!/usr/bin/env python3
"""
DicomLock — Honest Validation

Proper train/test split:
  1. Split real files 70/30 (RANDOMLY, not by index)
  2. Generate fakes ONLY from the 70% training real files
  3. Train on train_real + train_fakes
  4. Validate on held-out 30% real files (NEVER seen by model or fake generator)
  5. Also validate on fakes from held-out real files

This gives us defensible, honest numbers.
"""

import json
import os
import pickle
import random
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path

import numpy as np
import pydicom
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix,
)
from sklearn.model_selection import cross_val_score

sys.path.insert(0, str(Path(__file__).parent))
from scanner.pixel_advanced import extract_all_features
from generate_fakes import TECHNIQUES, read_pixels, save_fake

DATA_DIR = Path(__file__).parent / "data"
MODEL_DIR = Path(__file__).parent / "models"


def extract_features(ds):
    """Extract features and clean non-numeric fields."""
    features = extract_all_features(ds)
    if features is None:
        return None
    features.pop("modality", None)
    features.pop("rows", None)
    features.pop("cols", None)
    return features


def extract_from_dir(dicom_dir: Path, max_files=None):
    """Extract features from all DICOMs in a directory."""
    files = sorted(dicom_dir.glob("*.dcm"))
    if max_files:
        files = files[:max_files]

    results = []  # (features_dict, filename)
    for f in files:
        try:
            ds = pydicom.dcmread(str(f), force=True)
            feat = extract_features(ds)
            if feat is not None:
                results.append((feat, f.name))
        except Exception:
            pass
    return results


def generate_fakes_in_memory(real_files: list[Path], techniques: list[str],
                             count_per_technique: int = None):
    """Generate fakes and extract features without saving to disk."""
    if count_per_technique is None:
        count_per_technique = len(real_files)

    all_features = []  # (features_dict, technique_name)

    for tech_name in techniques:
        tech_fn = TECHNIQUES[tech_name]
        sources = real_files[:count_per_technique]
        generated = 0

        for i, fpath in enumerate(sources):
            try:
                ds, pixels = read_pixels(fpath)

                if tech_name == "interpolate" and len(real_files) > 1:
                    other = random.choice([f for f in real_files if f != fpath])
                    _, other_px = read_pixels(other)
                    modified = tech_fn(ds, pixels, other_px)
                else:
                    modified = tech_fn(ds, pixels)

                # Write to temp, re-read for feature extraction
                orig_pixels = ds.pixel_array
                max_val = 2 ** getattr(ds, "BitsStored", 16) - 1
                clipped = np.clip(modified, 0, max_val).astype(orig_pixels.dtype)
                ds.PixelData = clipped.tobytes()

                feat = extract_features(ds)
                if feat is not None:
                    all_features.append((feat, tech_name))
                    generated += 1
            except Exception:
                pass

        print(f"    {tech_name}: {generated} features extracted")

    return all_features


def features_to_matrix(features_list):
    """Convert list of feature dicts to numpy matrix."""
    all_keys = set()
    for f in features_list:
        all_keys.update(f.keys())
    feature_names = sorted(all_keys)

    matrix = np.zeros((len(features_list), len(feature_names)))
    for i, feat in enumerate(features_list):
        for j, key in enumerate(feature_names):
            val = feat.get(key, 0.0)
            matrix[i, j] = val if np.isfinite(val) else 0.0

    return matrix, feature_names


def main():
    random.seed(42)
    np.random.seed(42)

    real_dir = DATA_DIR / "tcia_ct"
    all_real_files = sorted(real_dir.glob("*.dcm"))
    print(f"Total real files: {len(all_real_files)}")

    # --- STEP 1: Split real files 70/30 ---
    random.shuffle(all_real_files)
    split_idx = int(len(all_real_files) * 0.7)
    train_files = all_real_files[:split_idx]
    test_files = all_real_files[split_idx:]
    print(f"Train real files: {len(train_files)}")
    print(f"Test real files (HELD OUT): {len(test_files)}")

    # --- STEP 2: Extract features from train real ---
    print(f"\n--- Extracting TRAIN real features ---")
    train_real = []
    for f in train_files:
        try:
            ds = pydicom.dcmread(str(f), force=True)
            feat = extract_features(ds)
            if feat:
                train_real.append((feat, "real"))
        except Exception:
            pass
    print(f"  {len(train_real)} train real features")

    # --- STEP 3: Generate fakes ONLY from train files ---
    print(f"\n--- Generating fakes from TRAIN files only ---")
    techniques = list(TECHNIQUES.keys())
    train_fakes = generate_fakes_in_memory(train_files, techniques,
                                            count_per_technique=len(train_files))
    print(f"  {len(train_fakes)} train fake features total")

    # --- STEP 4: Extract features from TEST real (held out) ---
    print(f"\n--- Extracting TEST real features (held out) ---")
    test_real = []
    for f in test_files:
        try:
            ds = pydicom.dcmread(str(f), force=True)
            feat = extract_features(ds)
            if feat:
                test_real.append((feat, "real"))
        except Exception:
            pass
    print(f"  {len(test_real)} test real features")

    # --- STEP 5: Generate fakes from TEST files (for testing detection) ---
    print(f"\n--- Generating fakes from TEST files ---")
    test_fakes = generate_fakes_in_memory(test_files, techniques,
                                           count_per_technique=len(test_files))
    print(f"  {len(test_fakes)} test fake features total")

    # --- STEP 6: Build train and test matrices ---
    train_features = [f for f, _ in train_real] + [f for f, _ in train_fakes]
    train_labels = [0] * len(train_real) + [1] * len(train_fakes)
    train_gens = ["real"] * len(train_real) + [t for _, t in train_fakes]

    test_features = [f for f, _ in test_real] + [f for f, _ in test_fakes]
    test_labels = [0] * len(test_real) + [1] * len(test_fakes)
    test_gens = ["real"] * len(test_real) + [t for _, t in test_fakes]

    X_train, feature_names = features_to_matrix(train_features)
    y_train = np.array(train_labels)

    # Build test matrix with same feature names
    X_test = np.zeros((len(test_features), len(feature_names)))
    for i, feat in enumerate(test_features):
        for j, key in enumerate(feature_names):
            val = feat.get(key, 0.0)
            X_test[i, j] = val if np.isfinite(val) else 0.0
    y_test = np.array(test_labels)

    X_train = np.nan_to_num(X_train)
    X_test = np.nan_to_num(X_test)

    print(f"\n{'='*60}")
    print(f"TRAINING SET: {X_train.shape[0]} samples ({sum(y_train==0)} real, {sum(y_train==1)} fake)")
    print(f"TEST SET:     {X_test.shape[0]} samples ({sum(y_test==0)} real, {sum(y_test==1)} fake)")
    print(f"Features: {X_train.shape[1]}")
    print(f"{'='*60}")

    # --- STEP 7: Train ---
    print(f"\n--- Training Random Forest ---")
    clf = RandomForestClassifier(
        n_estimators=500, max_depth=20, min_samples_leaf=3,
        class_weight="balanced", random_state=42, n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    # --- STEP 8: Evaluate on HELD-OUT test set ---
    print(f"\n{'='*60}")
    print(f"HONEST RESULTS (held-out test set)")
    print(f"{'='*60}")

    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_proba[:, 1])

    print(f"\n  Overall accuracy:     {acc:.1%}")
    print(f"  AUC:                  {auc:.3f}")
    print(f"  Precision (fake):     {prec:.1%}")
    print(f"  Recall/Sensitivity:   {rec:.1%}")
    print(f"  F1 Score:             {f1:.1%}")

    cm = confusion_matrix(y_test, y_pred)
    print(f"\n  Confusion Matrix:")
    print(f"                  Predicted Real  Predicted Fake")
    print(f"    Actual Real    {cm[0,0]:>8}       {cm[0,1]:>8}")
    print(f"    Actual Fake    {cm[1,0]:>8}       {cm[1,1]:>8}")

    # False positive rate on held-out real files
    real_mask = y_test == 0
    real_preds = y_pred[real_mask]
    fp_count = sum(real_preds == 1)
    fp_rate = fp_count / len(real_preds) if len(real_preds) > 0 else 0
    print(f"\n  FALSE POSITIVE RATE (held-out real): {fp_count}/{len(real_preds)} = {fp_rate:.1%}")

    # High-confidence FP
    real_fake_probs = y_proba[real_mask, 1]
    high_fp = sum(real_fake_probs > 0.7)
    print(f"  High-confidence FP (>70%):           {high_fp}/{len(real_preds)} = {high_fp/len(real_preds):.1%}")

    # Per-technique detection on held-out fakes
    print(f"\n  Per-Technique Detection (held-out test fakes):")
    test_gens_arr = np.array(test_gens)
    for tech in sorted(set(test_gens)):
        mask = test_gens_arr == tech
        if mask.sum() == 0:
            continue
        tech_pred = y_pred[mask]
        tech_true = y_test[mask]
        if tech == "real":
            correct = sum(tech_pred == 0)
            print(f"    {tech:<25} {correct}/{mask.sum()} correctly identified as real ({correct/mask.sum():.0%})")
        else:
            detected = sum(tech_pred == 1)
            print(f"    {tech:<25} {detected}/{mask.sum()} detected ({detected/mask.sum():.0%})")

    # --- STEP 9: Cross-validation on training set for reference ---
    print(f"\n--- Training set 5-fold CV (for reference) ---")
    cv_scores = cross_val_score(clf, X_train, y_train, cv=5, scoring="accuracy")
    print(f"  CV Accuracy: {cv_scores.mean():.1%} +/- {cv_scores.std():.1%}")

    # Feature importance
    print(f"\n--- Top 10 Features ---")
    importances = clf.feature_importances_
    indices = np.argsort(importances)[::-1]
    for rank, idx in enumerate(indices[:10]):
        print(f"  {rank+1:2d}. {feature_names[idx]:<35} {importances[idx]:.4f}")

    # --- STEP 10: Save model ---
    MODEL_DIR.mkdir(exist_ok=True)
    with open(MODEL_DIR / "rf_classifier.pkl", "wb") as f:
        pickle.dump(clf, f)

    meta = {
        "feature_names": feature_names,
        "n_features": len(feature_names),
        "model_type": "RandomForestClassifier",
        "n_estimators": 500,
        "honest_metrics": {
            "test_accuracy": float(acc),
            "test_auc": float(auc),
            "test_fp_rate": float(fp_rate),
            "test_recall": float(rec),
            "train_real": int(sum(y_train == 0)),
            "train_fake": int(sum(y_train == 1)),
            "test_real": int(sum(y_test == 0)),
            "test_fake": int(sum(y_test == 1)),
            "split": "70/30 real files, fakes generated only from train split",
            "limitations": [
                "Trained on hand-crafted tampering (not real GAN/diffusion fakes)",
                "CT-only (single modality)",
                "TCIA-only source (single data source)",
                "copy_move detection generalizes poorly to unseen techniques",
            ],
        },
    }
    with open(MODEL_DIR / "rf_classifier_meta.json", "w") as f:
        json.dump(meta, f, indent=2)

    print(f"\n  Model saved to {MODEL_DIR / 'rf_classifier.pkl'}")
    print(f"\n{'='*60}")
    print("DONE — Honest validation complete")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
