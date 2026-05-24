"""
DicomLock — Feature-Based Classifier (v0.1)

Uses a trained Random Forest model to flag DICOM images that show
statistical anomalies consistent with tampering or synthetic generation.

Capabilities and limitations (be honest):
  - Detects crude image modifications (smoothing, noise replacement,
    requantization, frequency manipulation, checkerboard artifacts)
  - Does NOT reliably detect sophisticated AI-generated fakes (GAN/diffusion)
  - Does NOT reliably detect localized copy-move tampering
  - Trained on CT-only data from TCIA; accuracy on MR/X-ray is unknown
  - Feature importance is ranked and every prediction is explainable

This is a v0.1 proof-of-concept. Deep learning on real generative fakes
(CTForensics/MedForensics datasets) is required for production-grade detection.
"""

import json
import os
import pickle
from typing import Optional

import numpy as np
import pydicom

from scanner.findings import Finding
from scanner.pixel_advanced import extract_all_features

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "rf_classifier.pkl")
META_PATH = os.path.join(MODEL_DIR, "rf_classifier_meta.json")

_model = None
_meta = None


def _load_model():
    """Lazy-load the classifier and metadata."""
    global _model, _meta

    if _model is not None:
        return _model, _meta

    if not os.path.exists(MODEL_PATH):
        return None, None

    with open(MODEL_PATH, "rb") as f:
        _model = pickle.load(f)

    if os.path.exists(META_PATH):
        with open(META_PATH) as f:
            _meta = json.load(f)
    else:
        _meta = {}

    return _model, _meta


def classify_image(ds: pydicom.Dataset) -> list[Finding]:
    """
    Run the trained classifier on a DICOM image.

    Returns findings with the prediction and top contributing features.
    Uses a high threshold (>80%) to minimize false positives — better
    to miss some fakes than to wrongly flag real clinical images.
    """
    model, meta = _load_model()
    if model is None:
        return [Finding(
            "classifier", "info",
            "ML classifier not available (no trained model found)"
        )]

    # Extract features
    features = extract_all_features(ds)
    if features is None:
        return [Finding(
            "classifier", "info",
            "Cannot extract features for classification (no pixel data)"
        )]

    # Remove non-numeric fields
    modality = features.pop("modality", "UNKNOWN")
    features.pop("rows", None)
    features.pop("cols", None)

    # Build feature vector in the same order the model expects
    feature_names = meta.get("feature_names", sorted(features.keys()))
    X = np.zeros((1, len(feature_names)))
    for j, name in enumerate(feature_names):
        val = features.get(name, 0.0)
        X[0, j] = val if np.isfinite(val) else 0.0

    # Predict
    proba = model.predict_proba(X)[0]
    real_prob = proba[0]
    fake_prob = proba[1]

    # Get top contributing features
    importances = model.feature_importances_
    top_indices = np.argsort(importances)[::-1][:5]
    top_features = []
    for idx in top_indices:
        name = feature_names[idx]
        value = X[0, idx]
        imp = importances[idx]
        top_features.append(f"{name}={value:.3f} (imp={imp:.3f})")

    # Read honest metrics from meta
    honest = meta.get("honest_metrics", {})
    test_acc = honest.get("test_accuracy", 0)
    test_fp = honest.get("test_fp_rate", 0)

    # High threshold to minimize FPs on real clinical images
    if fake_prob > 0.80:
        findings = [Finding(
            "classifier", "warn",
            f"Statistical anomaly detected: {fake_prob:.0%} probability of modification "
            f"(v0.1 classifier — CT-trained, hand-crafted fakes only)",
            f"Top features: {'; '.join(top_features[:3])}. "
            f"Note: this classifier detects crude modifications (smoothing, noise "
            f"replacement, requantization). It has NOT been validated against "
            f"AI-generated deepfakes (GAN/diffusion models)."
        )]
    elif fake_prob > 0.60:
        findings = [Finding(
            "classifier", "info",
            f"Mild statistical anomaly ({fake_prob:.0%} modification probability) "
            f"— below alert threshold",
            f"Top features: {'; '.join(top_features[:3])}"
        )]
    else:
        findings = [Finding(
            "classifier", "pass",
            f"No statistical anomalies detected ({real_prob:.0%} consistent with authentic)",
        )]

    return findings
