"""Brand similarity and lookalike domain detection module.

Uses RapidFuzz and explainable string metrics to identify typosquatting,
visual homoglyphs, and lookalike domains targeting well-known brands.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from rapidfuzz import fuzz

from phishguard.utils import normalize_target

# Curated list of high-value brands frequently targeted by phishing campaigns
POPULAR_BRANDS: List[str] = [
    "google",
    "paypal",
    "microsoft",
    "apple",
    "amazon",
    "netflix",
    "facebook",
    "instagram",
    "twitter",
    "chase",
    "wellsfargo",
    "binance",
    "steam",
    "dropbox",
    "adobe",
    "linkedin",
    "github",
]

# Simple and reliable homoglyph / visual substitution mapping (ASCII-based)
HOMOGLYPH_MAP: Dict[str, str] = {
    "0": "o",
    "1": "l",
    "5": "s",
    "8": "b",
    "v": "u",
    "vv": "w",
    "rn": "m",
}


@dataclass
class SimilarityResult:
    """Structured result of brand lookalike evaluation."""

    target_domain: str
    matched_brand: Optional[str]
    similarity_score: float
    is_lookalike: bool
    verdict: str
    signals: List[str] = field(default_factory=list)


def normalize_homoglyphs(text: str) -> str:
    """Map common visual character substitutions back to their standard Latin equivalents.

    Example: 'paypa1' -> 'paypal', 'g00gle' -> 'google', 'micros0ft' -> 'microsoft'.
    """
    normalized = text.lower()
    # Replace multi-character substitutions first
    normalized = normalized.replace("vv", "w").replace("rn", "m")
    # Replace single character substitutions
    for char, replacement in HOMOGLYPH_MAP.items():
        if len(char) == 1:
            normalized = normalized.replace(char, replacement)
    return normalized


def analyze_brand_lookalike(target: str, brand_list: Optional[List[str]] = None) -> SimilarityResult:
    """Evaluate whether a target domain is a visual lookalike or typosquat of a known brand.

    Returns a clean SimilarityResult detailing the closest brand,
    the similarity percentage, detected patterns, and risk verdict.
    """
    brands = brand_list or POPULAR_BRANDS
    info = normalize_target(target)

    # Use the domain name without suffix for brand comparison (e.g., 'paypa1-login' from 'paypa1-login.com')
    clean_name = info.domain.lower() if info.domain else info.hostname.lower()

    # Exact brand check: if the domain IS exactly the legitimate brand and no suspicious prefix/suffix
    if clean_name in brands:
        return SimilarityResult(
            target_domain=target,
            matched_brand=clean_name,
            similarity_score=100.0,
            is_lookalike=False,
            verdict="EXACT MATCH (GENUINE BRAND)",
            signals=[f"Matches known legitimate brand name '{clean_name}'"],
        )

    best_brand: Optional[str] = None
    best_score: float = 0.0
    detected_signals: List[str] = []

    dehomoglyphed_name = normalize_homoglyphs(clean_name)

    for brand in brands:
        # 1. Direct Levenshtein ratio
        direct_ratio = fuzz.ratio(clean_name, brand)

        # 2. Ratio after de-homoglyphing (e.g. paypa1 -> paypal)
        homoglyph_ratio = fuzz.ratio(dehomoglyphed_name, brand)

        # 3. Check individual tokens separated by hyphens or dots (e.g. 'paypa1' in 'paypa1-login')
        tokens = [t for t in clean_name.replace(".", "-").split("-") if t]
        dehomo_tokens = [normalize_homoglyphs(t) for t in tokens]
        
        token_best_direct = max((fuzz.ratio(t, brand) for t in tokens), default=0.0)
        token_best_homo = max((fuzz.ratio(dt, brand) for dt in dehomo_tokens), default=0.0)

        # 4. Check whether brand appears inside dehomoglyphed name (e.g., paypal-security, paypa1-login)
        is_homoglyph_exact = (dehomoglyphed_name == brand and clean_name != brand)
        is_embedded = (brand in dehomoglyphed_name and dehomoglyphed_name != brand)

        effective_score = max(direct_ratio, homoglyph_ratio, token_best_direct, token_best_homo)

        if is_embedded:
            effective_score = max(effective_score, 88.0)

        if effective_score > best_score:
            best_brand = brand
            best_score = round(effective_score, 1)

            current_signals: List[str] = []

            if is_embedded:
                current_signals.append(
                    f"Brand name '{brand}' is embedded with suspicious affix/keywords"
                )

            if (is_homoglyph_exact or homoglyph_ratio > direct_ratio or token_best_homo > token_best_direct) and effective_score >= 80.0:
                current_signals.append(
                    f"Visual character substitution/homoglyph detected mimicking '{brand}'"
                )

            if direct_ratio >= 80.0 and direct_ratio < 100.0:
                diff_len = abs(len(clean_name) - len(brand))
                if diff_len == 1:
                    current_signals.append(
                        f"Single-character insertion/deletion typosquat targeting '{brand}'"
                    )
                else:
                    current_signals.append(
                        f"Close spelling similarity ({direct_ratio:.1f}%) to brand '{brand}'"
                    )
            elif token_best_direct >= 80.0 and not is_embedded:
                current_signals.append(
                    f"Domain contains token closely mimicking '{brand}' ({token_best_direct:.1f}%)"
                )

            detected_signals = current_signals

    # Determine verdict based on threshold
    # Lookalike threshold: score >= 78% indicates strong similarity
    if best_score >= 85.0 and best_brand:
        verdict = "HIGH LOOKALIKE RISK"
        is_lookalike = True
    elif best_score >= 75.0 and best_brand:
        verdict = "SUSPICIOUS LOOKALIKE"
        is_lookalike = True
    else:
        verdict = "NO LOOKALIKE RISK"
        is_lookalike = False
        best_brand = None if best_score < 50.0 else best_brand
        detected_signals = []

    return SimilarityResult(
        target_domain=target,
        matched_brand=best_brand,
        similarity_score=best_score,
        is_lookalike=is_lookalike,
        verdict=verdict,
        signals=detected_signals,
    )


def compare_two_domains(genuine: str, suspicious: str) -> SimilarityResult:
    """Directly compare a legitimate domain against a suspicious domain."""
    gen_info = normalize_target(genuine)
    susp_info = normalize_target(suspicious)

    gen_name = gen_info.domain.lower() if gen_info.domain else gen_info.hostname.lower()
    susp_name = susp_info.domain.lower() if susp_info.domain else susp_info.hostname.lower()

    if gen_name == susp_name:
        return SimilarityResult(
            target_domain=suspicious,
            matched_brand=gen_name,
            similarity_score=100.0,
            is_lookalike=False,
            verdict="IDENTICAL DOMAINS",
            signals=["Both domains share the exact same base name"],
        )

    direct_ratio = fuzz.ratio(gen_name, susp_name)
    dehomo_susp = normalize_homoglyphs(susp_name)
    homo_ratio = fuzz.ratio(gen_name, dehomo_susp)

    # Token-level checks for hyphenated domains (e.g. paypa1-login)
    susp_tokens = [t for t in susp_name.replace(".", "-").split("-") if t]
    token_direct = max((fuzz.ratio(gen_name, t) for t in susp_tokens), default=0.0)
    token_homo = max((fuzz.ratio(gen_name, normalize_homoglyphs(t)) for t in susp_tokens), default=0.0)

    score = round(max(direct_ratio, homo_ratio, token_direct, token_homo), 1)
    signals: List[str] = []

    is_homo_exact = (dehomo_susp == gen_name and susp_name != gen_name)
    is_embedded = ((gen_name in dehomo_susp and dehomo_susp != gen_name) or (gen_name in susp_name and susp_name != gen_name))
    if is_embedded:
        signals.append(f"Target contains the entire brand string '{gen_name}'")
        score = max(score, 88.0)

    if (is_homo_exact or homo_ratio > direct_ratio or token_homo > token_direct) and score >= 80.0:
        signals.append(f"Visual character substitution/homoglyph mimicking '{gen_name}'")

    if direct_ratio >= 80.0:
        signals.append(f"High character-level spelling similarity ({direct_ratio:.1f}%)")
    elif token_direct >= 80.0 and not is_embedded:
        signals.append(f"Domain contains token closely matching '{gen_name}' ({token_direct:.1f}%)")

    diff_len = abs(len(susp_name) - len(gen_name))
    if diff_len == 1 and direct_ratio >= 75.0:
        signals.append("Single-character insertion or deletion typosquat pattern")

    if score >= 85.0:
        verdict = "HIGH LOOKALIKE RISK"
        is_lookalike = True
    elif score >= 70.0:
        verdict = "SUSPICIOUS LOOKALIKE"
        is_lookalike = True
    else:
        verdict = "LOW SIMILARITY"
        is_lookalike = False

    return SimilarityResult(
        target_domain=suspicious,
        matched_brand=gen_name,
        similarity_score=score,
        is_lookalike=is_lookalike,
        verdict=verdict,
        signals=signals,
    )
