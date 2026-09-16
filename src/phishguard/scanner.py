"""Unified scanning orchestrator for PhishGuard-CLI.

Coordinates domain validation, lexical feature extraction, brand lookalike detection,
machine learning prediction, and optional live web analysis into a consolidated assessment.
"""

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from phishguard.features import extract_features
from phishguard.image_analyzer import ImageSimilarityResult, compare_webpage_images
from phishguard.predictor import DEFAULT_MODEL_PATH, predict_target
from phishguard.similarity import SimilarityResult, analyze_brand_lookalike
from phishguard.utils import TargetInfo, validate_target
from phishguard.web_analyzer import WebAnalysisResult, analyze_webpage
from phishguard.whois_analyzer import WhoisResult, lookup_whois


@dataclass
class ScanResult:
    """Comprehensive result of a domain security scan."""

    target: str
    hostname: str
    registered_domain: str
    classification: str  # SAFE, SUSPICIOUS, or PHISHING
    phishing_probability: float  # 0.0 to 1.0
    risk_level: str  # LOW, MEDIUM, HIGH, or CRITICAL
    signals: List[str]
    brand_lookalike: SimilarityResult
    features: Dict[str, Any]
    web_analysis: Optional[WebAnalysisResult] = None
    whois: Optional[WhoisResult] = None
    image_analysis: Optional[ImageSimilarityResult] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to a clean dictionary for JSON/CSV reporting."""
        data = {
            "target": self.target,
            "hostname": self.hostname,
            "registered_domain": self.registered_domain,
            "classification": self.classification,
            "phishing_probability": round(self.phishing_probability, 4),
            "phishing_percentage": f"{self.phishing_probability * 100:.1f}%",
            "risk_level": self.risk_level,
            "signals": list(self.signals),
            "brand_lookalike": {
                "matched_brand": self.brand_lookalike.matched_brand,
                "similarity_score": self.brand_lookalike.similarity_score,
                "is_lookalike": self.brand_lookalike.is_lookalike,
                "verdict": self.brand_lookalike.verdict,
            },
            "features": self.features,
        }
        if self.web_analysis:
            data["web_analysis"] = asdict(self.web_analysis)
        if self.whois:
            data["whois"] = self.whois.to_dict()
        if self.image_analysis:
            data["image_analysis"] = self.image_analysis.to_dict()
        return data


def calculate_risk_level(
    probability: float,
    is_lookalike: bool,
    signal_count: int,
    is_newly_registered: bool = False,
    is_visual_lookalike: bool = False,
) -> str:
    """Determine composite security risk tier based on probability and security signals."""
    if (
        probability >= 0.80
        or (probability >= 0.60 and (is_lookalike or is_visual_lookalike))
        or (is_newly_registered and is_lookalike)
    ):
        return "CRITICAL"
    if probability >= 0.65 or is_lookalike or is_visual_lookalike or is_newly_registered or signal_count >= 3:
        return "HIGH"
    if probability >= 0.40 or signal_count >= 1:
        return "MEDIUM"
    return "LOW"


def scan_target(
    raw_target: str,
    model_path: str = DEFAULT_MODEL_PATH,
    analyze_web: bool = False,
    lookup_domain_whois: bool = False,
    suspicious_image_path: Optional[str] = None,
    genuine_image_path: Optional[str] = None,
) -> ScanResult:
    """Execute end-to-end security evaluation for a domain or URL.

    Raises:
        ValueError: If the target domain/URL is invalid or malformed.
        ModelNotFoundError: If the detection model has not been trained yet.
    """
    # 1. Input normalization & validation
    target_info: TargetInfo = validate_target(raw_target)

    # 2. Extract lexical and structural features
    feat_res = extract_features(target_info)

    # 3. Analyze brand lookalike / typosquatting similarity
    sim_res = analyze_brand_lookalike(target_info.original_input)

    # 4. Machine learning classification (raises ModelNotFoundError if missing)
    pred_res = predict_target(target_info.original_input, model_path=model_path)

    # 5. Optional live web content analysis
    web_res: Optional[WebAnalysisResult] = None
    if analyze_web:
        web_res = analyze_webpage(target_info.normalized_url or target_info.original_input)

    # 6. Optional WHOIS database newly registered domain (NRD) analysis
    whois_res: Optional[WhoisResult] = None
    if lookup_domain_whois:
        lookup_host = target_info.registered_domain or target_info.hostname
        whois_res = lookup_whois(lookup_host)

    # 7. Optional web page image analysis (Technique b)
    img_res: Optional[ImageSimilarityResult] = None
    if suspicious_image_path and genuine_image_path:
        img_res = compare_webpage_images(genuine_image_path, suspicious_image_path)

    # 8. Aggregate transparent security signals
    all_signals: List[str] = list(feat_res.signals)

    if sim_res.is_lookalike:
        for s in sim_res.signals:
            if s not in all_signals:
                all_signals.append(f"[HIGH] {s}")

    if web_res and web_res.signals:
        all_signals.extend(web_res.signals)

    if whois_res and whois_res.signals:
        all_signals.extend(whois_res.signals)

    if img_res and img_res.signals:
        all_signals.extend(img_res.signals)

    # 9. Compute composite risk tier
    is_nrd = bool(whois_res and whois_res.is_newly_registered)
    is_vis = bool(img_res and img_res.is_visual_lookalike)

    risk_level = calculate_risk_level(
        probability=pred_res.probability,
        is_lookalike=sim_res.is_lookalike,
        signal_count=len(all_signals),
        is_newly_registered=is_nrd,
        is_visual_lookalike=is_vis,
    )

    return ScanResult(
        target=target_info.original_input,
        hostname=target_info.hostname,
        registered_domain=target_info.registered_domain,
        classification=pred_res.classification,
        phishing_probability=pred_res.probability,
        risk_level=risk_level,
        signals=all_signals,
        brand_lookalike=sim_res,
        features=feat_res.features,
        web_analysis=web_res,
        whois=whois_res,
        image_analysis=img_res,
    )
