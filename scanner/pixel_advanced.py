"""
DicomLock — Advanced Pixel Forensics

Research-grounded detection features for identifying AI-generated
or tampered medical images.

Citations:
  - Wavelet sub-band analysis: Li et al., "CTForensics" (arXiv:2603.01878, 2026)
  - FFT spectral decay: Mahara & Rishe review (arXiv:2502.15176, 2025)
  - Noise residual extraction: Li et al., "DSKI" (MICCAI 2025, arXiv:2509.15711)
  - Bilateral symmetry: Tordjman et al., Radiology (2026), DOI:10.1148/radiol.252094
  - Checkerboard artifacts: Lee et al., J. Medical Imaging 10(5), 2023
"""

import numpy as np
import pywt
from scipy import ndimage, stats, optimize
from typing import Optional
import pydicom

from scanner.findings import Finding


# ---------------------------------------------------------------------------
# Feature 1: Wavelet Sub-band Analysis (CTForensics, Tier 1)
#
# AI-generated images have distinct artifacts in high-frequency wavelet
# sub-bands that are invisible in the spatial domain. We decompose the
# image into HH/HL/LH/LL at multiple scales and analyze the statistics
# of the high-frequency bands.
# ---------------------------------------------------------------------------

def extract_wavelet_features(pixels: np.ndarray, levels: int = 3) -> dict:
    """
    Decompose image via DWT and extract statistics from each sub-band.

    Returns a dict of features keyed by sub-band name, e.g.:
      {"level1_HH_mean": ..., "level1_HH_std": ..., "level1_HH_kurtosis": ..., ...}
    """
    features = {}
    data = pixels.astype(np.float64)

    for level in range(1, levels + 1):
        try:
            coeffs = pywt.dwt2(data, "haar")
            cA, (cH, cV, cD) = coeffs  # LL, (LH, HL, HH)

            for name, band in [("LH", cH), ("HL", cV), ("HH", cD)]:
                key = f"level{level}_{name}"
                features[f"{key}_mean"] = float(np.mean(np.abs(band)))
                features[f"{key}_std"] = float(np.std(band))
                features[f"{key}_kurtosis"] = float(stats.kurtosis(band.flatten()))
                features[f"{key}_energy"] = float(np.sum(band ** 2))

            # Descend into the approximation for next level
            data = cA
        except Exception:
            break

    return features


def check_wavelet_analysis(ds: pydicom.Dataset, baselines: Optional[dict] = None) -> list[Finding]:
    """
    Analyze wavelet sub-band statistics for anomalies.

    If baselines are provided (from calibration on real images),
    flags features that deviate significantly from normal ranges.
    Without baselines, reports raw features as info.

    Grounded in: Li et al., CTForensics (2026) — ESF-CTFD detector uses
    wavelet decomposition as its core feature extraction.
    """
    findings = []

    try:
        pixels = ds.pixel_array.astype(np.float64)
    except Exception:
        return [Finding("wavelet_analysis", "info", "Cannot access pixel data for wavelet analysis")]

    if pixels.ndim > 2:
        pixels = pixels[0] if pixels.shape[0] > 1 else pixels
    if pixels.ndim == 3:
        pixels = pixels[:, :, 0]

    if pixels.shape[0] < 16 or pixels.shape[1] < 16:
        return [Finding("wavelet_analysis", "info", "Image too small for wavelet analysis")]

    features = extract_wavelet_features(pixels, levels=3)

    if not features:
        return [Finding("wavelet_analysis", "warn", "Wavelet decomposition failed")]

    # If we have baselines for this modality, compare against them
    modality = getattr(ds, "Modality", "UNKNOWN")

    if baselines and modality in baselines:
        mod_baselines = baselines[modality]
        anomalies = []

        for key, value in features.items():
            if key in mod_baselines:
                bl = mod_baselines[key]
                mean, std = bl["mean"], bl["std"]
                if std > 0:
                    z_score = abs(value - mean) / std
                    if z_score > 3.0:
                        anomalies.append((key, value, mean, std, z_score))

        if anomalies:
            worst = max(anomalies, key=lambda x: x[4])
            findings.append(Finding(
                "wavelet_analysis", "warn",
                f"Wavelet anomaly: {worst[0]} is {worst[4]:.1f} sigma from normal "
                f"(value={worst[1]:.2f}, expected={worst[2]:.2f} +/- {worst[3]:.2f})",
                f"Found {len(anomalies)} sub-band(s) outside normal range for {modality}. "
                "AI-generated images often have distinct artifacts in high-frequency "
                "wavelet sub-bands (CTForensics, Li et al. 2026)."
            ))
        else:
            findings.append(Finding(
                "wavelet_analysis", "pass",
                f"Wavelet sub-band statistics within normal range for {modality}"
            ))
    else:
        # No baselines — report raw features for calibration
        hh1_energy = features.get("level1_HH_energy", 0)
        hh1_kurtosis = features.get("level1_HH_kurtosis", 0)
        findings.append(Finding(
            "wavelet_analysis", "info",
            f"Wavelet features extracted — HH1 energy={hh1_energy:.1f}, "
            f"kurtosis={hh1_kurtosis:.2f} (no baseline for {modality} yet)"
        ))

    return findings


# ---------------------------------------------------------------------------
# Feature 2: FFT Spectral Decay (CTForensics + Review, Tier 1)
#
# Real images follow a characteristic power-law decay in the frequency
# domain: magnitude(f) ~ b1 * f^(-b2). Generated images deviate from
# this natural decay. Even a simple classifier on (b1, b2) discriminates.
# ---------------------------------------------------------------------------

def compute_radial_spectrum(pixels: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """
    Compute the radially averaged power spectrum of an image.

    Returns (frequencies, power) arrays for fitting.
    """
    # 2D FFT
    f_transform = np.fft.fft2(pixels)
    f_shift = np.fft.fftshift(f_transform)
    magnitude = np.abs(f_shift)

    # Radial average
    h, w = magnitude.shape
    cy, cx = h // 2, w // 2
    max_radius = min(cy, cx)

    radii = np.zeros(magnitude.shape)
    for y in range(h):
        for x in range(w):
            radii[y, x] = np.sqrt((y - cy) ** 2 + (x - cx) ** 2)

    # Bin the magnitudes by radius
    freq_bins = np.arange(1, max_radius)
    power = np.zeros(len(freq_bins))

    for i, r in enumerate(freq_bins):
        mask = (radii >= r - 0.5) & (radii < r + 0.5)
        if np.any(mask):
            power[i] = np.mean(magnitude[mask])

    # Remove zeros
    valid = power > 0
    return freq_bins[valid], power[valid]


def fit_spectral_decay(frequencies: np.ndarray, power: np.ndarray) -> tuple[float, float, float]:
    """
    Fit power-law decay: power = b1 * freq^(-b2).

    Returns (b1, b2, r_squared) — the decay parameters and goodness of fit.
    """
    # Log-log linear fit: log(power) = log(b1) - b2 * log(freq)
    log_freq = np.log(frequencies)
    log_power = np.log(power)

    try:
        slope, intercept, r_value, _, _ = stats.linregress(log_freq, log_power)
        b2 = -slope
        b1 = np.exp(intercept)
        r_squared = r_value ** 2
        return b1, b2, r_squared
    except Exception:
        return 0.0, 0.0, 0.0


def extract_fft_features(pixels: np.ndarray) -> dict:
    """Extract FFT spectral decay features."""
    frequencies, power = compute_radial_spectrum(pixels)
    if len(frequencies) < 10:
        return {}

    b1, b2, r_sq = fit_spectral_decay(frequencies, power)

    # Also compute energy ratio: high-freq vs low-freq
    mid = len(power) // 2
    low_energy = np.sum(power[:mid] ** 2)
    high_energy = np.sum(power[mid:] ** 2)
    hf_ratio = high_energy / (low_energy + 1e-10)

    return {
        "spectral_b1": b1,
        "spectral_b2": b2,
        "spectral_r_squared": r_sq,
        "hf_energy_ratio": hf_ratio,
    }


def check_spectral_decay(ds: pydicom.Dataset, baselines: Optional[dict] = None) -> list[Finding]:
    """
    Analyze FFT spectral decay for deviation from natural power-law.

    Real medical images follow f^(-b2) decay with modality-specific b2 values.
    Generated images deviate from this.

    Grounded in: Mahara & Rishe review (2025), CTForensics ESF-CTFD (2026).
    """
    findings = []

    try:
        pixels = ds.pixel_array.astype(np.float64)
    except Exception:
        return [Finding("spectral_decay", "info", "Cannot access pixel data for spectral analysis")]

    if pixels.ndim > 2:
        pixels = pixels[0] if pixels.shape[0] > 1 else pixels
    if pixels.ndim == 3:
        pixels = pixels[:, :, 0]

    if pixels.shape[0] < 32 or pixels.shape[1] < 32:
        return [Finding("spectral_decay", "info", "Image too small for spectral analysis")]

    features = extract_fft_features(pixels)
    if not features:
        return [Finding("spectral_decay", "warn", "FFT spectral analysis failed")]

    b2 = features["spectral_b2"]
    r_sq = features["spectral_r_squared"]
    hf_ratio = features["hf_energy_ratio"]
    modality = getattr(ds, "Modality", "UNKNOWN")

    if baselines and modality in baselines:
        mod_bl = baselines[modality]
        if "spectral_b2" in mod_bl:
            bl = mod_bl["spectral_b2"]
            z = abs(b2 - bl["mean"]) / (bl["std"] + 1e-10)
            if z > 3.0:
                findings.append(Finding(
                    "spectral_decay", "warn",
                    f"Spectral decay anomaly: b2={b2:.3f} is {z:.1f} sigma from "
                    f"normal {modality} range ({bl['mean']:.3f} +/- {bl['std']:.3f})",
                    "Real images follow a power-law spectral decay (f^-b2). "
                    "AI-generated images deviate from this natural pattern "
                    "(Mahara & Rishe 2025, CTForensics 2026)."
                ))
            else:
                findings.append(Finding(
                    "spectral_decay", "pass",
                    f"Spectral decay normal for {modality}: b2={b2:.3f} "
                    f"(R²={r_sq:.3f}, HF ratio={hf_ratio:.2e})"
                ))
    else:
        # No baseline — report for calibration
        if r_sq < 0.7:
            findings.append(Finding(
                "spectral_decay", "info",
                f"Weak power-law fit (R²={r_sq:.3f}) — spectral decay "
                f"b2={b2:.3f}, HF ratio={hf_ratio:.2e} (no baseline for {modality})"
            ))
        else:
            findings.append(Finding(
                "spectral_decay", "info",
                f"Spectral decay: b2={b2:.3f}, R²={r_sq:.3f}, "
                f"HF ratio={hf_ratio:.2e} (no baseline for {modality} yet)"
            ))

    return findings


# ---------------------------------------------------------------------------
# Feature 3: Noise Residual Analysis (DSKI, Tier 1)
#
# The single most discriminative feature. Real sensors produce noise
# governed by physics; generators approximate but get pixel relationships
# wrong. We extract noise residuals via high-pass filtering and analyze
# their statistical properties.
# ---------------------------------------------------------------------------

def extract_noise_residual(pixels: np.ndarray) -> np.ndarray:
    """
    Extract noise residual using a constrained high-pass filter.

    This implements a simplified version of the BayarConv /
    constrained convolution from DSKI (Li et al., MICCAI 2025):
    center weight = -1, surrounding weights sum to 1.
    Strips semantic content, exposes noise patterns.
    """
    # 3x3 constrained kernel: center = -1, neighbors = 1/8 each
    # This is a high-pass filter that outputs the prediction error
    kernel = np.array([
        [1/8, 1/8, 1/8],
        [1/8,  -1, 1/8],
        [1/8, 1/8, 1/8],
    ])
    residual = ndimage.convolve(pixels, kernel, mode="reflect")
    return residual


def extract_noise_features(pixels: np.ndarray) -> dict:
    """Extract statistical features from the noise residual."""
    residual = extract_noise_residual(pixels)

    features = {
        "noise_mean": float(np.mean(residual)),
        "noise_std": float(np.std(residual)),
        "noise_skewness": float(stats.skew(residual.flatten())),
        "noise_kurtosis": float(stats.kurtosis(residual.flatten())),
        "noise_entropy": float(stats.entropy(np.histogram(residual.flatten(), bins=256)[0] + 1e-10)),
    }

    # Texture-region noise consistency (Tier 2)
    # Compare noise in smooth vs textured regions
    gradient_mag = np.sqrt(ndimage.sobel(pixels, axis=0)**2 + ndimage.sobel(pixels, axis=1)**2)
    median_grad = np.median(gradient_mag)

    smooth_mask = gradient_mag < median_grad
    texture_mask = gradient_mag >= median_grad

    if np.any(smooth_mask) and np.any(texture_mask):
        smooth_noise_std = np.std(residual[smooth_mask])
        texture_noise_std = np.std(residual[texture_mask])
        # In real images, noise is consistent. In fakes, it often differs.
        features["noise_consistency"] = float(
            abs(smooth_noise_std - texture_noise_std) / (smooth_noise_std + 1e-10)
        )
    else:
        features["noise_consistency"] = 0.0

    return features


def check_noise_residual(ds: pydicom.Dataset, baselines: Optional[dict] = None) -> list[Finding]:
    """
    Analyze noise residual statistics for signs of synthetic generation.

    The constrained convolution strips semantic content and exposes the
    noise fingerprint. Generators produce statistically different noise
    than real sensor physics.

    Grounded in: Li et al., DSKI (MICCAI 2025) — constrained convolution
    is the most discriminative single component.
    """
    findings = []

    try:
        pixels = ds.pixel_array.astype(np.float64)
    except Exception:
        return [Finding("noise_residual", "info", "Cannot access pixel data for noise analysis")]

    if pixels.ndim > 2:
        pixels = pixels[0] if pixels.shape[0] > 1 else pixels
    if pixels.ndim == 3:
        pixels = pixels[:, :, 0]

    features = extract_noise_features(pixels)
    modality = getattr(ds, "Modality", "UNKNOWN")

    if baselines and modality in baselines:
        mod_bl = baselines[modality]
        anomalies = []

        for key in ["noise_std", "noise_kurtosis", "noise_consistency"]:
            if key in mod_bl and key in features:
                bl = mod_bl[key]
                z = abs(features[key] - bl["mean"]) / (bl["std"] + 1e-10)
                if z > 3.0:
                    anomalies.append((key, features[key], bl["mean"], bl["std"], z))

        if anomalies:
            worst = max(anomalies, key=lambda x: x[4])
            findings.append(Finding(
                "noise_residual", "warn",
                f"Noise residual anomaly: {worst[0]}={worst[1]:.4f} is {worst[4]:.1f} "
                f"sigma from normal (expected {worst[2]:.4f} +/- {worst[3]:.4f})",
                f"Constrained convolution noise extraction reveals pixel relationship "
                f"patterns inconsistent with real {modality} sensor physics "
                f"(DSKI, Li et al. MICCAI 2025)."
            ))
        else:
            consistency = features["noise_consistency"]
            findings.append(Finding(
                "noise_residual", "pass",
                f"Noise residual consistent with real {modality} — "
                f"std={features['noise_std']:.2f}, consistency={consistency:.4f}"
            ))
    else:
        consistency = features["noise_consistency"]
        kurtosis = features["noise_kurtosis"]

        # Even without baselines, extreme noise inconsistency is suspicious
        if consistency > 0.5:
            findings.append(Finding(
                "noise_residual", "warn",
                f"High noise inconsistency between smooth and textured regions "
                f"(ratio={consistency:.3f})",
                "Real images have consistent noise across regions. "
                "Tampered or synthetic images often show different noise levels "
                "in smooth vs textured areas (DSKI, Li et al. 2025)."
            ))
        else:
            findings.append(Finding(
                "noise_residual", "info",
                f"Noise residual: std={features['noise_std']:.2f}, "
                f"kurtosis={kurtosis:.2f}, consistency={consistency:.4f} "
                f"(no baseline for {modality} yet)"
            ))

    return findings


# ---------------------------------------------------------------------------
# Feature 4: Bilateral Symmetry (RSNA Study, Tier 2)
#
# Synthetic chest X-rays are "too symmetrical." Real chest X-rays have
# natural asymmetries in vascular markings, lung volumes, heart position.
# NCC of image vs horizontal flip: real ~0.3-0.6, fake >0.7
# Only applicable to frontal chest X-rays.
# ---------------------------------------------------------------------------

def check_bilateral_symmetry(ds: pydicom.Dataset) -> list[Finding]:
    """
    Check bilateral symmetry for chest X-rays.

    Synthetic chest X-rays are overly symmetrical compared to real ones.
    This is a key finding from the RSNA study (Tordjman et al., 2026):
    real chest X-rays have NCC ~0.3-0.6 when flipped horizontally,
    while synthetic ones score >0.7.

    Only runs on chest X-ray modalities (CR, DX with chest body part).
    """
    findings = []

    modality = getattr(ds, "Modality", "")
    body_part = getattr(ds, "BodyPartExamined", "").upper()

    # Only applicable to frontal chest X-rays
    if modality not in ("CR", "DX") or "CHEST" not in body_part:
        return []  # Not applicable, skip silently

    try:
        pixels = ds.pixel_array.astype(np.float64)
    except Exception:
        return []

    if pixels.ndim > 2:
        pixels = pixels[0] if pixels.shape[0] > 1 else pixels
    if pixels.ndim == 3:
        pixels = pixels[:, :, 0]

    # Normalize
    pmin, pmax = pixels.min(), pixels.max()
    if pmax - pmin == 0:
        return []
    normalized = (pixels - pmin) / (pmax - pmin)

    # Flip horizontally and compute normalized cross-correlation
    flipped = np.fliplr(normalized)

    # NCC: correlation coefficient between image and its mirror
    ncc = np.corrcoef(normalized.flatten(), flipped.flatten())[0, 1]

    if ncc > 0.7:
        findings.append(Finding(
            "bilateral_symmetry", "warn",
            f"Unusually high bilateral symmetry (NCC={ncc:.3f}, threshold=0.70)",
            "AI-generated chest X-rays tend to be overly symmetrical. "
            "Real chest X-rays have natural asymmetries in vascular markings, "
            "lung volumes, and heart position. NCC >0.7 is suspicious "
            "(Tordjman et al., Radiology 2026)."
        ))
    else:
        findings.append(Finding(
            "bilateral_symmetry", "pass",
            f"Natural bilateral asymmetry (NCC={ncc:.3f}) — consistent with real chest X-ray"
        ))

    return findings


# ---------------------------------------------------------------------------
# Feature 5: Bit-Depth Utilization
#
# Detect upscaled low-bit images masquerading as high-bit. A "16-bit"
# image using only 256 unique values was upscaled from 8-bit.
# ---------------------------------------------------------------------------

def check_bit_depth(ds: pydicom.Dataset) -> list[Finding]:
    """Check if the declared bit depth matches actual pixel value utilization."""
    findings = []

    try:
        pixels = ds.pixel_array
    except Exception:
        return []

    bits_stored = getattr(ds, "BitsStored", getattr(ds, "BitsAllocated", None))
    if bits_stored is None:
        return []

    max_possible = 2 ** bits_stored
    unique_values = len(np.unique(pixels))
    utilization = unique_values / max_possible

    if bits_stored > 8 and unique_values <= 256:
        findings.append(Finding(
            "bit_depth", "warn",
            f"Declared {bits_stored}-bit but only {unique_values} unique values "
            f"(suggests upscaled from 8-bit)",
            "An image stored at higher bit depth than its actual data suggests "
            "the pixel data was converted or synthetically generated at lower resolution."
        ))
    elif utilization < 0.01:
        findings.append(Finding(
            "bit_depth", "info",
            f"Low bit-depth utilization: {unique_values} unique values "
            f"out of {max_possible} possible ({utilization:.1%})"
        ))
    else:
        findings.append(Finding(
            "bit_depth", "pass",
            f"Bit depth consistent: {unique_values} unique values "
            f"in {bits_stored}-bit space ({utilization:.1%} utilization)"
        ))

    return findings


# ---------------------------------------------------------------------------
# All-features extraction (for calibration pipeline)
# ---------------------------------------------------------------------------

def extract_all_features(ds: pydicom.Dataset) -> Optional[dict]:
    """
    Extract ALL measurable features from a DICOM file.

    Used by the calibration pipeline to build per-modality baselines.
    Returns None if pixel data is unavailable.
    """
    try:
        pixels = ds.pixel_array.astype(np.float64)
    except Exception:
        return None

    if pixels.ndim > 2:
        pixels = pixels[0] if pixels.shape[0] > 1 else pixels
    if pixels.ndim == 3:
        pixels = pixels[:, :, 0]

    if pixels.shape[0] < 16 or pixels.shape[1] < 16:
        return None

    features = {}
    features["modality"] = getattr(ds, "Modality", "UNKNOWN")
    features["rows"] = pixels.shape[0]
    features["cols"] = pixels.shape[1]

    # Wavelet features
    features.update(extract_wavelet_features(pixels, levels=3))

    # FFT features
    features.update(extract_fft_features(pixels))

    # Noise residual features
    features.update(extract_noise_features(pixels))

    # Symmetry (raw NCC, no threshold applied)
    try:
        normalized = (pixels - pixels.min()) / (pixels.max() - pixels.min() + 1e-10)
        flipped = np.fliplr(normalized)
        features["bilateral_ncc"] = float(np.corrcoef(normalized.flatten(), flipped.flatten())[0, 1])
    except Exception:
        features["bilateral_ncc"] = 0.0

    # Bit depth
    bits_stored = getattr(ds, "BitsStored", getattr(ds, "BitsAllocated", 16))
    features["unique_values"] = int(len(np.unique(pixels)))
    features["bit_utilization"] = features["unique_values"] / (2 ** bits_stored)

    return features


# ---------------------------------------------------------------------------
# Runner: all advanced pixel checks
# ---------------------------------------------------------------------------

def run_advanced_pixel_checks(ds: pydicom.Dataset, baselines: Optional[dict] = None) -> list[Finding]:
    """Run all advanced pixel forensic checks."""
    if not hasattr(ds, "PixelData"):
        return [Finding("advanced_pixel", "info", "No pixel data — skipping advanced forensics")]

    all_findings = []
    checks = [
        lambda d: check_wavelet_analysis(d, baselines),
        lambda d: check_spectral_decay(d, baselines),
        lambda d: check_noise_residual(d, baselines),
        check_bilateral_symmetry,
        check_bit_depth,
    ]

    for check in checks:
        try:
            results = check(ds)
            all_findings.extend(results)
        except Exception as e:
            all_findings.append(Finding(
                "advanced_pixel", "warn", f"Advanced check error: {str(e)}"
            ))

    return all_findings
