"""Unified scanning orchestrator for PhishGuard-CLI.

Coordinates domain validation, lexical feature extraction, brand lookalike detection,
machine learning prediction, and optional live web analysis into a consolidated assessment.
"""

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

from phishguard.features import extract_features
from phishguard.predictor import DEFAULT_MODEL_PATH, predict_target
from phishguard.similarity import SimilarityResult, analyze_brand_lookalike
from phishguard.utils import TargetInfo, validate_target
from phishguard.web_analyzer import WebAnalysisResult, analyze_webpage


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
        return data


def calculate_risk_level(probability: float, is_lookalike: bool, signal_count: int) -> str:
    """Determine composite security risk tier based on probability and security signals."""
    if probability >= 0.80 or (probability >= 0.60 and is_lookalike):
        return "CRITICAL"
    if probability >= 0.65 or is_lookalike or signal_count >= 3:
        return "HIGH"
    if probability >= 0.40 or signal_count >= 1:
        return "MEDIUM"
    return "LOW"


def scan_target(
    raw_target: str,
    model_path: str = DEFAULT_MODEL_PATH,
    analyze_web: bool = False,
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

    # 6. Aggregate transparent security signals
    all_signals: List[str] = list(feat_res.signals)

    if sim_res.is_lookalike:
        for s in sim_res.signals:
            if s not in all_signals:
                all_signals.append(f"[HIGH] {s}")

    if web_res and web_res.signals:
        all_signals.extend(web_res.signals)

    # 7. Compute composite risk tier
    risk_level = calculate_risk_level(
        probability=pred_res.probability,
        is_lookalike=sim_res.is_lookalike,
        signal_count=len(all_signals),
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
    )
