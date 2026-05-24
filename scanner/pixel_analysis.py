"""
DicomLock — Pixel-Level Statistical Analysis

Analyzes pixel data for signs of tampering, synthetic generation,
or adversarial manipulation.
"""

import pydicom
import numpy as np
from scipy import stats, ndimage
from typing import Optional
from scanner.findings import Finding


def check_pixel_statistics(ds: pydicom.Dataset) -> list[Finding]:
    """
    Analyze basic pixel statistics for anomalies.

    Natural medical images have characteristic statistical properties.
    AI-generated or tampered images often deviate from these patterns.
    """
    findings = []

    try:
        pixels = ds.pixel_array.astype(np.float64)
    except Exception:
        findings.append(Finding(
            "pixel_stats", "info",
            "Cannot access pixel data for statistical analysis"
        ))
        return findings

    # Handle multi-frame
    if pixels.ndim > 2 and pixels.shape[0] > 1:
        pixels = pixels[0]  # Analyze first frame

    if pixels.ndim == 3:
        pixels = pixels[:, :, 0]  # Take first channel

    mean_val = np.mean(pixels)
    std_val = np.std(pixels)
    min_val = np.min(pixels)
    max_val = np.max(pixels)
    dynamic_range = max_val - min_val

    # Check for suspiciously low dynamic range
    bits = getattr(ds, "BitsStored", getattr(ds, "BitsAllocated", 16))
    max_possible = 2 ** bits - 1

    if dynamic_range < max_possible * 0.01:
        findings.append(Finding(
            "pixel_stats", "warn",
            f"Very low dynamic range: {dynamic_range:.0f} out of {max_possible} possible values",
            "Natural medical images typically use a wider range of pixel values."
        ))

    # Check for all-zero or constant images
    if std_val == 0:
        findings.append(Finding(
            "pixel_stats", "fail",
            "Image has zero variance — all pixels are identical",
            "This is not a valid medical image."
        ))
        return findings

    # Check for suspiciously uniform histogram
    hist, _ = np.histogram(pixels.flatten(), bins=256)
    hist_nonzero = hist[hist > 0]
    hist_entropy = stats.entropy(hist_nonzero)

    # Natural images typically have moderate entropy
    if hist_entropy < 1.0:
        findings.append(Finding(
            "pixel_stats", "warn",
            f"Very low histogram entropy ({hist_entropy:.2f}) — pixel distribution is unusually concentrated"
        ))

    findings.append(Finding(
        "pixel_stats", "pass",
        f"Pixel statistics: mean={mean_val:.1f}, std={std_val:.1f}, "
        f"range=[{min_val:.0f}, {max_val:.0f}], histogram entropy={hist_entropy:.2f}"
    ))

    return findings


def check_noise_analysis(ds: pydicom.Dataset) -> list[Finding]:
    """
    Analyze noise characteristics.

    Natural medical images have noise from the imaging process (quantum noise,
    electronic noise). AI-generated images often have different noise patterns:
    - Too smooth (GAN-generated)
    - Uniform noise (added artificially)
    - Inconsistent noise across regions (composite/tampered)
    """
    findings = []

    try:
        pixels = ds.pixel_array.astype(np.float64)
    except Exception:
        return findings

    if pixels.ndim > 2:
        pixels = pixels[0] if pixels.shape[0] > 1 else pixels
    if pixels.ndim == 3:
        pixels = pixels[:, :, 0]

    # Estimate noise using the median absolute deviation of the
    # high-pass filtered image (Laplacian)
    laplacian = ndimage.laplace(pixels)
    noise_estimate = np.median(np.abs(laplacian)) * 1.4826  # MAD to std conversion

    # Check noise consistency across quadrants
    h, w = pixels.shape
    quadrants = [
        pixels[:h//2, :w//2],   # top-left
        pixels[:h//2, w//2:],   # top-right
        pixels[h//2:, :w//2],   # bottom-left
        pixels[h//2:, w//2:],   # bottom-right
    ]

    quadrant_noise = []
    for q in quadrants:
        q_lap = ndimage.laplace(q)
        q_noise = np.median(np.abs(q_lap)) * 1.4826
        quadrant_noise.append(q_noise)

    noise_variation = np.std(quadrant_noise) / (np.mean(quadrant_noise) + 1e-10)

    if noise_variation > 0.5:
        findings.append(Finding(
            "noise_analysis", "warn",
            f"Inconsistent noise across image regions (variation: {noise_variation:.2f})",
            "Tampered or composite images often show different noise levels "
            "in different regions. Quadrant noise levels: "
            f"TL={quadrant_noise[0]:.1f}, TR={quadrant_noise[1]:.1f}, "
            f"BL={quadrant_noise[2]:.1f}, BR={quadrant_noise[3]:.1f}"
        ))
    elif noise_estimate < 0.1:
        findings.append(Finding(
            "noise_analysis", "warn",
            "Image is suspiciously smooth — may be AI-generated or heavily processed",
            f"Estimated noise level: {noise_estimate:.3f}"
        ))
    else:
        findings.append(Finding(
            "noise_analysis", "pass",
            f"Noise characteristics normal — estimated noise: {noise_estimate:.1f}, "
            f"regional consistency: {noise_variation:.3f}"
        ))

    return findings


def check_compression_artifacts(ds: pydicom.Dataset) -> list[Finding]:
    """
    Look for signs of re-compression (double JPEG compression).

    If an image has been modified and re-saved, it may show artifacts
    from double compression that differ from single-compression artifacts.
    """
    findings = []

    try:
        pixels = ds.pixel_array.astype(np.float64)
    except Exception:
        return findings

    if pixels.ndim > 2:
        pixels = pixels[0] if pixels.shape[0] > 1 else pixels
    if pixels.ndim == 3:
        pixels = pixels[:, :, 0]

    # Check for 8x8 block artifacts (JPEG compression signature)
    h, w = pixels.shape
    if h < 16 or w < 16:
        return findings

    # Compute block boundary discontinuity
    # In JPEG-compressed images, 8x8 block boundaries often show discontinuities
    block_size = 8
    h_blocks = (h // block_size) - 1
    w_blocks = (w // block_size) - 1

    if h_blocks < 1 or w_blocks < 1:
        return findings

    # Horizontal block boundary vs. interior discontinuity
    boundary_diffs = []
    interior_diffs = []

    for i in range(1, h_blocks + 1):
        row = i * block_size
        if row < h:
            boundary_diffs.append(np.mean(np.abs(pixels[row, :] - pixels[row-1, :])))
        interior_row = i * block_size + block_size // 2
        if interior_row < h - 1:
            interior_diffs.append(np.mean(np.abs(pixels[interior_row, :] - pixels[interior_row-1, :])))

    if boundary_diffs and interior_diffs:
        boundary_mean = np.mean(boundary_diffs)
        interior_mean = np.mean(interior_diffs)

        ratio = boundary_mean / (interior_mean + 1e-10)

        if ratio > 1.5:
            findings.append(Finding(
                "compression", "warn",
                f"Possible JPEG block artifacts detected (boundary/interior ratio: {ratio:.2f})",
                "Strong 8x8 block boundary artifacts may indicate re-compression, "
                "which can occur when an image is modified and re-saved."
            ))
        else:
            findings.append(Finding(
                "compression", "pass",
                f"No significant block compression artifacts (ratio: {ratio:.2f})"
            ))

    return findings


def check_edge_consistency(ds: pydicom.Dataset) -> list[Finding]:
    """
    Analyze edge characteristics for signs of manipulation.

    GAN-generated images and copy-paste forgeries often show
    edge artifacts that differ from natural imaging.
    """
    findings = []

    try:
        pixels = ds.pixel_array.astype(np.float64)
    except Exception:
        return findings

    if pixels.ndim > 2:
        pixels = pixels[0] if pixels.shape[0] > 1 else pixels
    if pixels.ndim == 3:
        pixels = pixels[:, :, 0]

    # Normalize to 0-1 range
    pmin, pmax = pixels.min(), pixels.max()
    if pmax - pmin > 0:
        normalized = (pixels - pmin) / (pmax - pmin)
    else:
        return findings

    # Compute gradients
    gy, gx = np.gradient(normalized)
    gradient_magnitude = np.sqrt(gx**2 + gy**2)

    # Check for unnatural gradient patterns
    grad_mean = np.mean(gradient_magnitude)
    grad_std = np.std(gradient_magnitude)
    grad_max = np.max(gradient_magnitude)

    # Ratio of max gradient to mean — extremely high can indicate sharp artificial edges
    sharpness_ratio = grad_max / (grad_mean + 1e-10)

    if sharpness_ratio > 100:
        findings.append(Finding(
            "edge_analysis", "info",
            f"High gradient sharpness ratio ({sharpness_ratio:.1f}) — may indicate artificial edges",
            "Very sharp edges relative to the image average can occur naturally "
            "(e.g., metal implants, contrast boundaries) but are also characteristic "
            "of synthetic images or copy-paste manipulation."
        ))
    else:
        findings.append(Finding(
            "edge_analysis", "pass",
            f"Edge characteristics normal — gradient mean={grad_mean:.4f}, "
            f"sharpness ratio={sharpness_ratio:.1f}"
        ))

    return findings


def run_pixel_checks(ds: pydicom.Dataset) -> list[Finding]:
    """Run all pixel-level checks on a parsed DICOM dataset."""
    if not hasattr(ds, "PixelData"):
        return [Finding("pixel_scan", "info", "No pixel data — skipping pixel analysis")]

    all_findings = []
    checks = [
        check_pixel_statistics,
        check_noise_analysis,
        check_compression_artifacts,
        check_edge_consistency,
    ]

    for check in checks:
        try:
            all_findings.extend(check(ds))
        except Exception as e:
            all_findings.append(Finding(
                check.__name__, "warn", f"Check error: {str(e)}"
            ))

    return all_findings
