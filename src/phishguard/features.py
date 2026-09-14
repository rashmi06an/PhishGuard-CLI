"""Lexical and security feature extraction module for PhishGuard-CLI.

Extracts explainable lexical indicators from URLs and domains.
These features serve as inputs to the machine learning classifier,
while the extracted security signals provide transparent human-readable context.
"""

import math
from collections import Counter
from dataclasses import dataclass
from typing import Dict, List, Union

from phishguard.utils import TargetInfo, normalize_target

# High-frequency keywords commonly observed in phishing and credential harvesting URLs
SUSPICIOUS_KEYWORDS = [
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "update",
    "security",
    "secure",
    "banking",
    "wallet",
    "confirm",
    "support",
    "service",
    "password",
    "authenticate",
    "credential",
    "billing",
    "recover",
]

# Canonical feature names in fixed order for machine learning pipelines
FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "num_special_chars",
    "num_subdomains",
    "has_ip",
    "entropy",
    "suspicious_keyword_count",
]


@dataclass
class FeatureResult:
    """Container for extracted features, raw vector, and security signals."""

    features: Dict[str, Union[int, float]]
    signals: List[str]
    feature_vector: List[float]
    feature_names: List[str]


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string.

    Shannon entropy measures the uncertainty / randomness of characters in the string.
    Higher entropy (e.g., > 3.8 for domain labels) often indicates
    Domain Generation Algorithms (DGA) or random obfuscation.
    """
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 4)


def extract_features(target: Union[str, TargetInfo]) -> FeatureResult:
    """Extract lexical and structural security features from a target URL/domain."""
    if isinstance(target, str):
        target_info = normalize_target(target)
    else:
        target_info = target

    url_str = target_info.normalized_url or target_info.original_input
    host_str = target_info.hostname or target_info.original_input
    registered_domain = target_info.registered_domain or host_str

    # 1. Length features
    url_length = len(url_str)
    domain_length = len(host_str)

    # 2. Character counts
    num_dots = url_str.count(".")
    num_hyphens = url_str.count("-")
    num_digits = sum(1 for c in url_str if c.isdigit())
    special_chars = set("@_~?=%&#+-/\\:")
    num_special_chars = sum(1 for c in url_str if c in special_chars)

    # 3. Subdomain count
    if target_info.subdomain:
        num_subdomains = len([s for s in target_info.subdomain.split(".") if s])
    else:
        num_subdomains = 0

    # 4. Host is an IP address
    has_ip = 1 if target_info.is_ip else 0

    # 5. Shannon entropy (computed on registered domain or hostname)
    entropy = calculate_entropy(registered_domain)

    # 6. Suspicious keyword presence
    url_lower = url_str.lower()
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    suspicious_keyword_count = len(matched_keywords)

    features: Dict[str, Union[int, float]] = {
        "url_length": url_length,
        "domain_length": domain_length,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_digits": num_digits,
        "num_special_chars": num_special_chars,
        "num_subdomains": num_subdomains,
        "has_ip": has_ip,
        "entropy": entropy,
        "suspicious_keyword_count": suspicious_keyword_count,
    }

    feature_vector = [float(features[name]) for name in FEATURE_NAMES]

    # Generate transparent, human-readable security signals
    signals: List[str] = []

    if has_ip == 1:
        signals.append("[CRITICAL] Uses direct IP address instead of domain name")

    if matched_keywords:
        kw_list = ", ".join(f"'{k}'" for k in matched_keywords[:4])
        signals.append(f"[HIGH] Contains suspicious phishing keyword(s): {kw_list}")

    if num_subdomains >= 2:
        signals.append(f"[MEDIUM] High number of subdomains ({num_subdomains})")

    if host_str.count("-") >= 2:
        signals.append(f"[MEDIUM] Multiple hyphens in domain ({host_str.count('-')})")

    if entropy >= 3.8:
        signals.append(
            f"[MEDIUM] High character entropy ({entropy:.2f}) indicates potential algorithmic generation"
        )

    if domain_length >= 35:
        signals.append(f"[LOW] Abnormally long domain name ({domain_length} chars)")

    if num_dots >= 4:
        signals.append(f"[LOW] High number of dots in URL ({num_dots})")

    return FeatureResult(
        features=features,
        signals=signals,
        feature_vector=feature_vector,
        feature_names=list(FEATURE_NAMES),
    )
