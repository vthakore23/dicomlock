#!/usr/bin/env python3
"""
DicomLock — Deepfake Classifier Training Pipeline

Trains a Random Forest classifier on the 49 extracted features to
distinguish real DICOM images from synthetic/tampered ones.

This is an interpretable, non-black-box approach:
  - Feature importance shows which research-backed features matter most
  - Decision paths are inspectable per-prediction
  - Every flagged image traces to specific feature values

No GPU required. Runs on CPU in seconds.

Usage:
    python train_classifier.py                       # defaults
    python train_classifier.py --real data/tcia_ct --fakes data/fakes
    python train_classifier.py --cross-generator     # leave-one-generator-out
"""

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from pathlib import Path

import numpy as np
import pydicom
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix, roc_auc_score,
)
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler

# Add parent dir for scanner imports
sys.path.insert(0, str(Path(__file__).parent))
from scanner.pixel_advanced import extract_all_features

DATA_DIR = Path(__file__).parent / "data"
MODEL_DIR = Path(__file__).parent / "models"


def extract_features_from_dir(
    dicom_dir: Path,
    label: int,
    label_name: str,
    generator: str = None,
    max_files: int = None,
) -> tuple[list[dict], list[int], list[str]]:
    """
    Extract features from all DICOM files in a directory.

    Returns (features_list, labels, generator_labels).
    """
    dcm_files = sorted(dicom_dir.glob("*.dcm"))
    if max_files and len(dcm_files) > max_files:
        dcm_files = dcm_files[:max_files]

    features_list = []
    labels = []
    generators = []
    errors = 0

    for i, fpath in enumerate(dcm_files):
        try:
            ds = pydicom.dcmread(str(fpath), force=True)
            features = extract_all_features(ds)

            if features is None:
                errors += 1
                continue

            # Remove non-numeric metadata fields
            features.pop("modality", None)
            features.pop("rows", None)
            features.pop("cols", None)

            features_list.append(features)
            labels.append(label)
            generators.append(generator or label_name)

        except Exception:
            errors += 1

        if (i + 1) % 100 == 0:
            sys.stdout.write(f"\r    [{len(features_list)}/{i+1}] extracted ({errors} errors)")
            sys.stdout.flush()

    if dcm_files:
        print(f"\r    {label_name}: {len(features_list)} extracted, {errors} errors" + " " * 20)

    return features_list, labels, generators


def features_to_matrix(features_list: list[dict]) -> tuple[np.ndarray, list[str]]:
    """
    Convert list of feature dicts to a numpy matrix.

    Returns (matrix, feature_names) where matrix is N x F.
    """
    # Get union of all feature keys
    all_keys = set()
    for f in features_list:
        all_keys.update(f.keys())

    feature_names = sorted(all_keys)

    matrix = np.zeros((len(features_list), len(feature_names)))
    for i, features in enumerate(features_list):
        for j, key in enumerate(feature_names):
            val = features.get(key, 0.0)
            matrix[i, j] = val if np.isfinite(val) else 0.0

    return matrix, feature_names


def train_and_evaluate(
    X: np.ndarray,
    y: np.ndarray,
    feature_names: list[str],
    generators: list[str],
    cross_generator: bool = False,
):
    """Train classifier and report metrics."""

    print(f"\n{'='*60}")
    print(f"TRAINING — {X.shape[0]} samples, {X.shape[1]} features")
    print(f"  Real: {np.sum(y == 0)}, Fake: {np.sum(y == 1)}")
    print(f"{'='*60}")

    # --- 5-fold cross-validation ---
    print("\n--- 5-Fold Cross-Validation ---")
    clf = RandomForestClassifier(
        n_estimators=500,
        max_depth=20,
        min_samples_leaf=3,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = cross_val_score(clf, X, y, cv=cv, scoring="accuracy")
    print(f"  Accuracy: {scores.mean():.1%} +/- {scores.std():.1%}")
    print(f"  Per-fold: {', '.join(f'{s:.1%}' for s in scores)}")

    # AUC
    from sklearn.model_selection import cross_val_predict
    y_proba = cross_val_predict(clf, X, y, cv=cv, method="predict_proba")
    auc = roc_auc_score(y, y_proba[:, 1])
    print(f"  AUC: {auc:.3f}")

    # --- Train on full dataset for feature importance ---
    print("\n--- Full-Dataset Training ---")
    clf.fit(X, y)
    y_pred = clf.predict(X)

    print(f"  Training accuracy: {accuracy_score(y, y_pred):.1%}")
    print(f"  Precision (fake): {precision_score(y, y_pred):.1%}")
    print(f"  Recall (fake): {recall_score(y, y_pred):.1%}")
    print(f"  F1 (fake): {f1_score(y, y_pred):.1%}")

    # Confusion matrix
    cm = confusion_matrix(y, y_pred)
    print(f"\n  Confusion Matrix:")
    print(f"                  Predicted Real  Predicted Fake")
    print(f"    Actual Real    {cm[0,0]:>8}       {cm[0,1]:>8}")
    print(f"    Actual Fake    {cm[1,0]:>8}       {cm[1,1]:>8}")

    # --- Feature importance ---
    print("\n--- Top 15 Most Important Features ---")
    importances = clf.feature_importances_
    indices = np.argsort(importances)[::-1]

    for rank, idx in enumerate(indices[:15]):
        print(f"  {rank+1:2d}. {feature_names[idx]:<35} {importances[idx]:.4f}")

    # --- Per-generator breakdown ---
    generators_arr = np.array(generators)
    unique_gens = sorted(set(generators))

    if len(unique_gens) > 2:
        print(f"\n--- Per-Generator Detection Rates ---")
        for gen in unique_gens:
            mask = generators_arr == gen
            if mask.sum() == 0:
                continue
            gen_pred = clf.predict(X[mask])
            gen_true = y[mask]
            acc = accuracy_score(gen_true, gen_pred)
            fake_count = np.sum(gen_true == 1)
            real_count = np.sum(gen_true == 0)
            if fake_count > 0:
                recall = recall_score(gen_true, gen_pred)
                print(f"  {gen:<25} n={mask.sum():>4}  accuracy={acc:.1%}  recall={recall:.1%}")
            else:
                print(f"  {gen:<25} n={mask.sum():>4}  accuracy={acc:.1%}  (all real)")

    # --- Cross-generator validation ---
    if cross_generator and len(unique_gens) > 3:
        print(f"\n--- Leave-One-Generator-Out Validation ---")
        fake_gens = [g for g in unique_gens if g != "real"]

        for held_out in fake_gens:
            # Train on everything EXCEPT this generator's fakes
            train_mask = generators_arr != held_out
            test_mask = generators_arr == held_out

            if test_mask.sum() == 0 or train_mask.sum() == 0:
                continue

            X_train, y_train = X[train_mask], y[train_mask]
            X_test, y_test = X[test_mask], y[test_mask]

            clf_cv = RandomForestClassifier(
                n_estimators=500, max_depth=20, min_samples_leaf=3,
                class_weight="balanced", random_state=42, n_jobs=-1,
            )
            clf_cv.fit(X_train, y_train)
            y_pred_cv = clf_cv.predict(X_test)
            acc = accuracy_score(y_test, y_pred_cv)
            recall = recall_score(y_test, y_pred_cv) if np.any(y_test == 1) else 0
            print(f"  Held out: {held_out:<25} accuracy={acc:.1%}  recall={recall:.1%}  n={test_mask.sum()}")

    return clf, importances, feature_names


def save_model(clf, feature_names: list[str], metrics: dict):
    """Save the trained model and metadata."""
    import pickle

    MODEL_DIR.mkdir(exist_ok=True)

    # Save model
    model_path = MODEL_DIR / "rf_classifier.pkl"
    with open(model_path, "wb") as f:
        pickle.dump(clf, f)

    # Save feature names and metadata
    meta = {
        "feature_names": feature_names,
        "n_features": len(feature_names),
        "metrics": metrics,
        "model_type": "RandomForestClassifier",
        "n_estimators": clf.n_estimators,
    }
    meta_path = MODEL_DIR / "rf_classifier_meta.json"
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)

    print(f"\n  Model saved to {model_path}")
    print(f"  Metadata saved to {meta_path}")


def main():
    parser = argparse.ArgumentParser(description="Train deepfake classifier")
    parser.add_argument("--real", type=str, default="data/tcia_ct",
                        help="Directory of real DICOM files")
    parser.add_argument("--fakes", type=str, default="data/fakes",
                        help="Directory of fake DICOM files (with subdirs per technique)")
    parser.add_argument("--max-real", type=int, default=None,
                        help="Max real files to use")
    parser.add_argument("--max-fake-per-tech", type=int, default=None,
                        help="Max fake files per technique")
    parser.add_argument("--cross-generator", action="store_true",
                        help="Run leave-one-generator-out validation")
    parser.add_argument("--save", action="store_true",
                        help="Save the trained model")
    args = parser.parse_args()

    base = Path(__file__).parent
    real_dir = base / args.real
    fakes_dir = base / args.fakes

    print("DicomLock — Classifier Training Pipeline")
    print(f"Real data: {real_dir}")
    print(f"Fake data: {fakes_dir}")

    # --- Extract features from REAL images ---
    print(f"\n--- Extracting features from REAL images ---")
    real_features, real_labels, real_gens = extract_features_from_dir(
        real_dir, label=0, label_name="real", max_files=args.max_real,
    )

    if not real_features:
        print("No real features extracted! Check your data directory.")
        sys.exit(1)

    # --- Extract features from FAKE images (each technique is a subdirectory) ---
    print(f"\n--- Extracting features from FAKE images ---")
    all_fake_features = []
    all_fake_labels = []
    all_fake_gens = []

    if fakes_dir.is_dir():
        for tech_dir in sorted(fakes_dir.iterdir()):
            if tech_dir.is_dir() and any(tech_dir.glob("*.dcm")):
                tech_name = tech_dir.name
                f, l, g = extract_features_from_dir(
                    tech_dir, label=1, label_name=tech_name,
                    generator=tech_name,
                    max_files=args.max_fake_per_tech,
                )
                all_fake_features.extend(f)
                all_fake_labels.extend(l)
                all_fake_gens.extend(g)

    if not all_fake_features:
        print("No fake features extracted! Run generate_fakes.py first.")
        sys.exit(1)

    # --- Combine into matrix ---
    all_features = real_features + all_fake_features
    all_labels = real_labels + all_fake_labels
    all_generators = real_gens + all_fake_gens

    X, feature_names = features_to_matrix(all_features)
    y = np.array(all_labels)
    generators = all_generators

    # Replace NaN/inf
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    # --- Train and evaluate ---
    start = time.time()
    clf, importances, feature_names = train_and_evaluate(
        X, y, feature_names, generators,
        cross_generator=args.cross_generator,
    )
    elapsed = time.time() - start
    print(f"\n  Training + evaluation took {elapsed:.1f}s")

    # --- Save model ---
    if args.save:
        metrics = {
            "n_real": int(np.sum(y == 0)),
            "n_fake": int(np.sum(y == 1)),
            "n_features": len(feature_names),
            "cv_accuracy": float(cross_val_score(
                clf, X, y, cv=5, scoring="accuracy"
            ).mean()),
        }
        save_model(clf, feature_names, metrics)

    print(f"\n{'='*60}")
    print("DONE — Classifier training complete")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
