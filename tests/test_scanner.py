"""Unit tests for the unified scanner orchestrator."""

import pytest

from phishguard.scanner import ScanResult, calculate_risk_level, scan_target


class TestScanner:
    """Test suite for domain scanning and risk assessment."""

    def test_scan_benign_domain(self):
        res = scan_target("google.com")
        assert isinstance(res, ScanResult)
        assert res.classification == "SAFE"
        assert res.risk_level == "LOW"
        assert res.phishing_probability < 0.40
        assert res.registered_domain == "google.com"

    def test_scan_phishing_domain(self):
        res = scan_target("paypal-update-account-verification.com")
        assert isinstance(res, ScanResult)
        assert res.classification == "PHISHING"
        assert res.risk_level in ["HIGH", "CRITICAL"]
        assert res.phishing_probability >= 0.70
        assert any("keyword" in s.lower() for s in res.signals)

    def test_scan_lookalike_domain(self):
        res = scan_target("paypa1-security-center.com")
        assert isinstance(res, ScanResult)
        assert res.brand_lookalike.matched_brand == "paypal"
        assert res.brand_lookalike.is_lookalike is True
        assert res.risk_level in ["HIGH", "CRITICAL"]

    def test_scan_invalid_domain_raises_value_error(self):
        with pytest.raises(ValueError):
            scan_target("bad domain with spaces.com")

        with pytest.raises(ValueError):
            scan_target("user:pass@invalid.com")

    def test_scan_result_dict_serialization(self):
        res = scan_target("wikipedia.org")
        data = res.to_dict()
        assert isinstance(data, dict)
        assert data["target"] == "wikipedia.org"
        assert "phishing_probability" in data
        assert "risk_level" in data
        assert "brand_lookalike" in data
        assert "features" in data
        assert isinstance(data["signals"], list)

    def test_calculate_risk_level_tiers(self):
        # Critical tier
        assert calculate_risk_level(probability=0.85, is_lookalike=False, signal_count=1) == "CRITICAL"
        assert calculate_risk_level(probability=0.65, is_lookalike=True, signal_count=2) == "CRITICAL"

        # High tier
        assert calculate_risk_level(probability=0.70, is_lookalike=False, signal_count=0) == "HIGH"
        assert calculate_risk_level(probability=0.20, is_lookalike=True, signal_count=0) == "HIGH"

        # Medium tier
        assert calculate_risk_level(probability=0.45, is_lookalike=False, signal_count=0) == "MEDIUM"
        assert calculate_risk_level(probability=0.10, is_lookalike=False, signal_count=2) == "MEDIUM"

        # Low tier
        assert calculate_risk_level(probability=0.05, is_lookalike=False, signal_count=0) == "LOW"
