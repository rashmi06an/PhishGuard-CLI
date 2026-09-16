"""Web page image and visual similarity analysis module for PhishGuard-CLI.

Implements Technique (b) of the NTRO Cybersecurity Specification:
Analysis between genuine and phishing site web page images (screenshots, logos, favicons).
Evaluates visual lookalike similarity: more similarity -> higher probability score of being a lookalike phishing site.
"""

from dataclasses import dataclass, field
import io
import math
import os
from typing import Any, List, Optional, Tuple, Union

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False


@dataclass
class ImageSimilarityResult:
    """Structured result of visual image similarity analysis between genuine and target."""

    genuine_image_path: Optional[str]
    suspicious_image_path: Optional[str]
    similarity_score: float  # 0.0 to 100.0%
    visual_probability_score: float  # 0.0 to 1.0 (more similarity -> higher lookalike phishing probability)
    is_visual_lookalike: bool
    verdict: str
    dhash_distance: int
    histogram_similarity: float
    signals: List[str] = field(default_factory=list)
    error_message: Optional[str] = None

    def to_dict(self):
        return {
            "genuine_image": self.genuine_image_path,
            "suspicious_image": self.suspicious_image_path,
            "similarity_score": round(self.similarity_score, 2),
            "visual_probability_score": round(self.visual_probability_score, 4),
            "is_visual_lookalike": self.is_visual_lookalike,
            "verdict": self.verdict,
            "dhash_distance": self.dhash_distance,
            "histogram_similarity": round(self.histogram_similarity, 2),
            "signals": self.signals,
            "error_message": self.error_message,
        }


def _load_image(source: Union[str, bytes]) -> Optional[Any]:
    """Safely load an image from a file path or raw bytes."""
    if not HAS_PIL:
        return None
    try:
        if isinstance(source, bytes):
            return Image.open(io.BytesIO(source)).convert("RGB")
        if os.path.isfile(source):
            return Image.open(source).convert("RGB")
    except Exception:
        return None
    return None


def calculate_dhash(image: Any, hash_size: int = 8) -> int:
    """Compute difference hash (dHash) for an image.
    
    Robust to minor aspect-ratio shifts, compression artifacts, and resolution differences.
    """
    # Resize to (width + 1, height)
    resized = image.convert("L").resize((hash_size + 1, hash_size), Image.Resampling.LANCZOS)
    if hasattr(resized, "get_flattened_data"):
        pixels = list(resized.get_flattened_data())
    else:
        pixels = list(resized.getdata())
    
    # Compare adjacent pixels row by row
    diff = []
    width = hash_size + 1
    for row in range(hash_size):
        for col in range(hash_size):
            left_val = pixels[row * width + col]
            right_val = pixels[row * width + col + 1]
            diff.append(left_val > right_val)
            
    # Convert bool array into an integer bitmask
    decimal_val = 0
    for bit in diff:
        decimal_val = (decimal_val << 1) | int(bit)
    return decimal_val


def calculate_color_histogram_similarity(image1: Any, image2: Any) -> float:
    """Compute normalized color histogram correlation between two RGB images (0.0 to 100.0%)."""
    # Resize to equal dimensions for comparison
    img1 = image1.resize((128, 128), Image.Resampling.BILINEAR)
    img2 = image2.resize((128, 128), Image.Resampling.BILINEAR)

    h1 = img1.histogram()
    h2 = img2.histogram()

    # Calculate Pearson correlation coefficient between histograms
    n = len(h1)
    mean1 = sum(h1) / n
    mean2 = sum(h2) / n

    numerator = sum((a - mean1) * (b - mean2) for a, b in zip(h1, h2))
    denom1 = math.sqrt(sum((a - mean1) ** 2 for a in h1))
    denom2 = math.sqrt(sum((b - mean2) ** 2 for b in h2))

    if denom1 == 0 or denom2 == 0:
        return 0.0

    corr = numerator / (denom1 * denom2)
    # Map [-1.0, 1.0] to [0.0, 100.0]
    return max(0.0, min(100.0, ((corr + 1.0) / 2.0) * 100.0))


def compare_webpage_images(
    genuine_source: Union[str, bytes],
    suspicious_source: Union[str, bytes],
    hash_size: int = 8,
) -> ImageSimilarityResult:
    """Compare genuine and suspicious webpage images or screenshots.
    
    Implements NTRO requirement:
    'Web page image analysis (i.e. analysis between genuine and phishing site web page images;
    more the similarity better is the probability score of being a lookalike phishing site).'
    """
    gen_path = genuine_source if isinstance(genuine_source, str) else "<bytes>"
    susp_path = suspicious_source if isinstance(suspicious_source, str) else "<bytes>"

    if not HAS_PIL:
        return ImageSimilarityResult(
            genuine_image_path=gen_path,
            suspicious_image_path=susp_path,
            similarity_score=0.0,
            visual_probability_score=0.0,
            is_visual_lookalike=False,
            verdict="PIL / Pillow library not available",
            dhash_distance=64,
            histogram_similarity=0.0,
            error_message="Pillow is not installed",
        )

    img1 = _load_image(genuine_source)
    img2 = _load_image(suspicious_source)

    if img1 is None:
        return ImageSimilarityResult(
            genuine_image_path=gen_path,
            suspicious_image_path=susp_path,
            similarity_score=0.0,
            visual_probability_score=0.0,
            is_visual_lookalike=False,
            verdict="UNREADABLE GENUINE IMAGE",
            dhash_distance=64,
            histogram_similarity=0.0,
            error_message=f"Could not load image: {gen_path}",
        )

    if img2 is None:
        return ImageSimilarityResult(
            genuine_image_path=gen_path,
            suspicious_image_path=susp_path,
            similarity_score=0.0,
            visual_probability_score=0.0,
            is_visual_lookalike=False,
            verdict="UNREADABLE SUSPICIOUS IMAGE",
            dhash_distance=64,
            histogram_similarity=0.0,
            error_message=f"Could not load image: {susp_path}",
        )

    # 1. Perceptual Difference Hash (dHash)
    hash1 = calculate_dhash(img1, hash_size=hash_size)
    hash2 = calculate_dhash(img2, hash_size=hash_size)
    
    total_bits = hash_size * hash_size
    # Hamming distance: count of differing bits
    hamming_dist = bin(hash1 ^ hash2).count("1")
    # Structural visual similarity from dHash (0 to 100%)
    dhash_similarity = max(0.0, ((total_bits - hamming_dist) / total_bits) * 100.0)

    # 2. Color Histogram Similarity (0 to 100%)
    color_similarity = calculate_color_histogram_similarity(img1, img2)

    # 3. Composite Visual Similarity Score:
    # 60% weight to perceptual structural layout + 40% weight to color scheme
    composite_similarity = round((0.60 * dhash_similarity) + (0.40 * color_similarity), 1)

    # 4. Compute Visual Lookalike Probability Score (0.0 to 1.0):
    # As mandated by NTRO: higher similarity directly increases lookalike phishing probability
    visual_probability = round(composite_similarity / 100.0, 4)

    # Signals
    signals: List[str] = []
    if hamming_dist <= 5:
        signals.append(f"[CRITICAL] Near-identical page layout detected (dHash distance: {hamming_dist}/{total_bits})")
    elif hamming_dist <= 12:
        signals.append(f"[HIGH] Highly similar visual structure detected (dHash distance: {hamming_dist}/{total_bits})")

    if color_similarity >= 85.0:
        signals.append(f"[HIGH] Brand color scheme and palette closely match genuine site ({color_similarity:.1f}%)")
    elif color_similarity >= 70.0:
        signals.append(f"[MEDIUM] Moderate color scheme similarity to genuine brand ({color_similarity:.1f}%)")

    # Verdict
    if composite_similarity >= 80.0:
        verdict = "CRITICAL VISUAL LOOKALIKE (HIGH CONFIDENCE PHISHING)"
        is_lookalike = True
    elif composite_similarity >= 65.0:
        verdict = "SUSPICIOUS VISUAL LOOKALIKE"
        is_lookalike = True
    elif composite_similarity >= 50.0:
        verdict = "MODERATE VISUAL SIMILARITY"
        is_lookalike = False
    else:
        verdict = "DISTINCT VISUAL APPEARANCE (LOW LOOKALIKE RISK)"
        is_lookalike = False

    return ImageSimilarityResult(
        genuine_image_path=gen_path,
        suspicious_image_path=susp_path,
        similarity_score=composite_similarity,
        visual_probability_score=visual_probability,
        is_visual_lookalike=is_lookalike,
        verdict=verdict,
        dhash_distance=hamming_dist,
        histogram_similarity=color_similarity,
        signals=signals,
        error_message=None,
    )
