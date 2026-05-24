#!/usr/bin/env python3
"""
DicomLock — Fake DICOM Generator

Creates synthetic/tampered DICOM files from real ones using multiple
techniques that mimic real-world attack vectors and generative artifacts.

Each technique produces images with known statistical signatures that the
scanner should detect. This gives us labeled training data for the classifier.

Techniques (mapped to real-world threats):
  1. gaussian_smooth  — mimics GAN over-smoothness (RSNA study finding)
  2. noise_replace    — replaces real sensor noise with synthetic Gaussian
  3. freq_manipulate  — alters frequency spectrum (breaks natural power-law)
  4. copy_move        — pastes a region from one part to another (CT-GAN attack)
  5. interpolate      — averages two images (crude generation technique)
  6. requantize       — reduces and re-expands bit depth (generation artifact)
  7. checkerboard     — adds periodic artifacts (GAN upsampling artifact)

Usage:
    python generate_fakes.py                      # defaults
    python generate_fakes.py --source data/tcia_ct --count 500
    python generate_fakes.py --techniques gaussian_smooth noise_replace
"""

import argparse
import os
import random
import sys
from pathlib import Path

import numpy as np
import pydicom
from pydicom.uid import generate_uid

DATA_DIR = Path(__file__).parent / "data"


def load_real_dicoms(source_dir: Path, max_files: int = 200) -> list[Path]:
    """Load paths to real DICOM files."""
    files = sorted(source_dir.glob("*.dcm"))
    if len(files) > max_files:
        random.seed(42)
        files = random.sample(files, max_files)
    return files


def read_pixels(path: Path) -> tuple[pydicom.Dataset, np.ndarray]:
    """Read a DICOM file and return (dataset, pixel_array)."""
    ds = pydicom.dcmread(str(path), force=True)
    pixels = ds.pixel_array.astype(np.float64)
    if pixels.ndim > 2:
        pixels = pixels[0]
    if pixels.ndim == 3:
        pixels = pixels[:, :, 0]
    return ds, pixels


def save_fake(ds: pydicom.Dataset, pixels: np.ndarray, output_path: Path,
              technique: str):
    """Save modified pixel data back into a DICOM file."""
    # Clip to valid range
    orig_pixels = ds.pixel_array
    if hasattr(ds, "BitsStored"):
        max_val = 2 ** ds.BitsStored - 1
    else:
        max_val = orig_pixels.max()

    clipped = np.clip(pixels, 0, max_val)

    if orig_pixels.dtype in (np.uint8, np.uint16, np.int16):
        clipped = clipped.astype(orig_pixels.dtype)

    # Write back
    ds.PixelData = clipped.tobytes()
    # Update UIDs to mark as modified
    ds.SOPInstanceUID = generate_uid()
    ds.SeriesInstanceUID = generate_uid()
    # Tag the fake
    ds.ImageComments = f"DICOMLOCK_FAKE:{technique}"

    ds.save_as(str(output_path))


# ---------------------------------------------------------------------------
# Technique 1: Gaussian Smoothing (mimics GAN over-smoothness)
# The RSNA study found synthetic X-rays have "overly smooth" bones and
# "excessively uniform" vascular markings. This simulates that effect.
# ---------------------------------------------------------------------------

def gaussian_smooth(ds: pydicom.Dataset, pixels: np.ndarray,
                    sigma: float = None) -> np.ndarray:
    """Apply Gaussian blur to simulate GAN over-smoothness."""
    from scipy.ndimage import gaussian_filter
    if sigma is None:
        sigma = random.uniform(1.5, 4.0)
    return gaussian_filter(pixels, sigma=sigma)


# ---------------------------------------------------------------------------
# Technique 2: Noise Replacement (replaces real sensor noise with synthetic)
# Real images have sensor-specific noise patterns; generators produce
# noise that doesn't match any real sensor physics.
# ---------------------------------------------------------------------------

def noise_replace(ds: pydicom.Dataset, pixels: np.ndarray) -> np.ndarray:
    """Replace real noise with synthetic Gaussian noise."""
    from scipy.ndimage import gaussian_filter
    # Smooth to remove real noise
    smooth = gaussian_filter(pixels, sigma=2.0)
    # Add synthetic Gaussian noise (different statistics than real)
    noise_level = np.std(pixels - smooth) * random.uniform(0.5, 1.5)
    synthetic_noise = np.random.normal(0, noise_level, pixels.shape)
    return smooth + synthetic_noise


# ---------------------------------------------------------------------------
# Technique 3: Frequency Manipulation (alters natural spectral decay)
# Real images follow f^(-b2) decay. This artificially boosts or suppresses
# high-frequency content, breaking the natural power law.
# ---------------------------------------------------------------------------

def freq_manipulate(ds: pydicom.Dataset, pixels: np.ndarray) -> np.ndarray:
    """Modify frequency spectrum to break natural power-law decay."""
    f_transform = np.fft.fft2(pixels)
    f_shift = np.fft.fftshift(f_transform)

    h, w = f_shift.shape
    cy, cx = h // 2, w // 2

    # Create distance-from-center map
    y, x = np.ogrid[:h, :w]
    dist = np.sqrt((y - cy) ** 2 + (x - cx) ** 2)
    max_dist = np.sqrt(cy ** 2 + cx ** 2)

    # Randomly boost or suppress high frequencies
    if random.random() < 0.5:
        # Boost high freq (makes image look sharper/noisier than natural)
        scale = 1.0 + 2.0 * (dist / max_dist) ** 2
    else:
        # Suppress high freq (over-smoothing, different from Gaussian)
        scale = 1.0 / (1.0 + 0.5 * (dist / max_dist) ** 2)

    f_modified = f_shift * scale
    f_unshift = np.fft.ifftshift(f_modified)
    result = np.real(np.fft.ifft2(f_unshift))

    return result


# ---------------------------------------------------------------------------
# Technique 4: Copy-Move Forgery (simulates CT-GAN tumor injection)
# Mirsky et al. (USENIX 2019): inject/remove tumors by copying regions
# from one part of the image to another.
# ---------------------------------------------------------------------------

def copy_move(ds: pydicom.Dataset, pixels: np.ndarray) -> np.ndarray:
    """Copy a region from one part of the image to another."""
    h, w = pixels.shape
    result = pixels.copy()

    # Size of region to copy (5-15% of image dimension)
    patch_h = random.randint(int(h * 0.05), int(h * 0.15))
    patch_w = random.randint(int(w * 0.05), int(w * 0.15))

    # Source and destination (in the central portion of the image)
    margin = max(patch_h, patch_w) + 10
    src_y = random.randint(margin, h - margin - patch_h)
    src_x = random.randint(margin, w - margin - patch_w)
    dst_y = random.randint(margin, h - margin - patch_h)
    dst_x = random.randint(margin, w - margin - patch_w)

    # Copy with smooth blending (feathered edges)
    patch = pixels[src_y:src_y + patch_h, src_x:src_x + patch_w].copy()

    # Create Gaussian blend mask
    yy, xx = np.mgrid[:patch_h, :patch_w]
    cy, cx = patch_h / 2, patch_w / 2
    sigma = min(patch_h, patch_w) / 4
    blend = np.exp(-((yy - cy) ** 2 + (xx - cx) ** 2) / (2 * sigma ** 2))

    existing = result[dst_y:dst_y + patch_h, dst_x:dst_x + patch_w]
    result[dst_y:dst_y + patch_h, dst_x:dst_x + patch_w] = (
        existing * (1 - blend) + patch * blend
    )

    return result


# ---------------------------------------------------------------------------
# Technique 5: Interpolation (average two images — crude generation)
# A simple but detectable technique: generated images that are linear
# combinations of real images have distinctive noise properties.
# ---------------------------------------------------------------------------

def interpolate(ds: pydicom.Dataset, pixels: np.ndarray,
                other_pixels: np.ndarray = None) -> np.ndarray:
    """Average this image with another (or a shifted version of itself)."""
    if other_pixels is not None and other_pixels.shape == pixels.shape:
        alpha = random.uniform(0.3, 0.7)
        return alpha * pixels + (1 - alpha) * other_pixels

    # Self-interpolation with a shifted version
    shift_y = random.randint(5, 20)
    shift_x = random.randint(5, 20)
    shifted = np.roll(np.roll(pixels, shift_y, axis=0), shift_x, axis=1)
    alpha = random.uniform(0.3, 0.7)
    return alpha * pixels + (1 - alpha) * shifted


# ---------------------------------------------------------------------------
# Technique 6: Requantization (reduce and re-expand bit depth)
# AI-generated images often originate at 8-bit and get upscaled to 16-bit.
# This creates telltale gaps in the pixel value histogram.
# ---------------------------------------------------------------------------

def requantize(ds: pydicom.Dataset, pixels: np.ndarray) -> np.ndarray:
    """Reduce to 8-bit and re-expand to original depth."""
    pmin, pmax = pixels.min(), pixels.max()
    if pmax - pmin < 1:
        return pixels

    # Normalize to 0-255
    normalized = (pixels - pmin) / (pmax - pmin) * 255.0
    quantized = np.round(normalized).astype(np.uint8)

    # Re-expand to original range
    result = quantized.astype(np.float64) / 255.0 * (pmax - pmin) + pmin
    return result


# ---------------------------------------------------------------------------
# Technique 7: Checkerboard Artifact (GAN upsampling artifact)
# Lee et al. (2023) found 69-78% of GAN mammograms have checkerboard
# artifacts from transposed convolution upsampling.
# ---------------------------------------------------------------------------

def checkerboard_inject(ds: pydicom.Dataset, pixels: np.ndarray) -> np.ndarray:
    """Add periodic checkerboard pattern mimicking GAN upsampling artifacts."""
    h, w = pixels.shape
    result = pixels.copy()

    # Checkerboard at stride frequency (2, 4, or 8)
    stride = random.choice([2, 4, 8])
    amplitude = np.std(pixels) * random.uniform(0.02, 0.08)

    # Create checkerboard
    yy, xx = np.mgrid[:h, :w]
    pattern = amplitude * ((-1.0) ** (yy // stride + xx // stride))

    result += pattern
    return result


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

TECHNIQUES = {
    "gaussian_smooth": gaussian_smooth,
    "noise_replace": noise_replace,
    "freq_manipulate": freq_manipulate,
    "copy_move": copy_move,
    "interpolate": interpolate,
    "requantize": requantize,
    "checkerboard": checkerboard_inject,
}


def generate_fakes_from_dir(
    source_dir: Path,
    output_dir: Path,
    techniques: list[str] = None,
    count_per_technique: int = None,
    max_source_files: int = 200,
):
    """
    Generate fake DICOM files from real ones.

    For each technique, applies it to `count_per_technique` real files
    and saves the result as a labeled fake.
    """
    if techniques is None:
        techniques = list(TECHNIQUES.keys())

    real_files = load_real_dicoms(source_dir, max_source_files)
    if not real_files:
        print(f"No .dcm files found in {source_dir}")
        return

    if count_per_technique is None:
        count_per_technique = len(real_files)

    output_dir.mkdir(parents=True, exist_ok=True)
    total_generated = 0

    for technique_name in techniques:
        technique_fn = TECHNIQUES[technique_name]
        tech_dir = output_dir / technique_name
        tech_dir.mkdir(exist_ok=True)

        print(f"\n  Generating {technique_name}...")
        generated = 0
        errors = 0

        # Select source files for this technique
        sources = real_files[:count_per_technique]

        for i, source_path in enumerate(sources):
            try:
                ds, pixels = read_pixels(source_path)

                # For interpolation, try to use a different image
                if technique_name == "interpolate" and len(real_files) > 1:
                    other_path = random.choice([f for f in real_files if f != source_path])
                    _, other_pixels = read_pixels(other_path)
                    modified = technique_fn(ds, pixels, other_pixels)
                else:
                    modified = technique_fn(ds, pixels)

                out_name = f"{technique_name}_{source_path.stem}_{i:04d}.dcm"
                save_fake(ds, modified, tech_dir / out_name, technique_name)
                generated += 1

            except Exception as e:
                errors += 1

            if (i + 1) % 50 == 0:
                sys.stdout.write(f"\r    [{generated}/{i+1}] generated ({errors} errors)")
                sys.stdout.flush()

        print(f"\r    {generated} generated, {errors} errors" + " " * 20)
        total_generated += generated

    print(f"\n  Total: {total_generated} fake files in {output_dir}")
    return total_generated


def main():
    parser = argparse.ArgumentParser(description="Generate fake DICOM files")
    parser.add_argument("--source", type=str, default="data/tcia_ct",
                        help="Source directory of real DICOM files")
    parser.add_argument("--output", type=str, default="data/fakes",
                        help="Output directory for fakes")
    parser.add_argument("--count", type=int, default=None,
                        help="Files per technique (default: all source files)")
    parser.add_argument("--max-source", type=int, default=200,
                        help="Max source files to use (default: 200)")
    parser.add_argument("--techniques", nargs="+",
                        choices=list(TECHNIQUES.keys()),
                        help="Specific techniques (default: all)")
    args = parser.parse_args()

    source_dir = Path(__file__).parent / args.source
    output_dir = Path(__file__).parent / args.output

    print("DicomLock — Fake DICOM Generator")
    print(f"Source: {source_dir}")
    print(f"Output: {output_dir}")
    print(f"Techniques: {args.techniques or 'all'}")

    real_count = len(list(source_dir.glob("*.dcm")))
    print(f"Real files available: {real_count}")

    if real_count == 0:
        print("\nNo source files! Run download_tcia.py first.")
        sys.exit(1)

    random.seed(42)
    np.random.seed(42)

    generate_fakes_from_dir(
        source_dir=source_dir,
        output_dir=output_dir,
        techniques=args.techniques,
        count_per_technique=args.count,
        max_source_files=args.max_source,
    )

    print("\nNext: python train_classifier.py")


if __name__ == "__main__":
    main()
