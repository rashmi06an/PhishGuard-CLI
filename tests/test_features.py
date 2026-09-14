"""Unit tests for domain normalization, validation, and feature extraction."""

import pytest

from phishguard.features import FEATURE_NAMES, calculate_entropy, extract_features
from phishguard.utils import normalize_target, validate_target


class TestTargetValidation:
    """Test suite for URL/domain validation in utils.py."""

    def test_valid_domain(self):
        target = normalize_target("example.com")
        assert target.is_valid is True
        assert target.hostname == "example.com"
        assert target.registered_domain == "example.com"
        assert target.is_ip is False

    def test_url_with_protocol(self):
        target = normalize_target("https://secure.example.com/login?redirect=1")
        assert target.is_valid is True
        assert target.hostname == "secure.example.com"
        assert target.subdomain == "secure"
        assert target.domain == "example"
        assert target.path == "/login"

    def test_subdomains(self):
        target = normalize_target("portal.auth.service.corp.com")
        assert target.is_valid is True
        assert target.hostname == "portal.auth.service.corp.com"
        assert target.subdomain == "portal.auth.service"
        assert target.registered_domain == "corp.com"

    def test_ip_address_target(self):
        target = normalize_target("http://192.168.1.1/admin")
        assert target.is_valid is True
        assert target.is_ip is True
        assert target.hostname == "192.168.1.1"

    def test_raw_ip_without_protocol(self):
        target = normalize_target("10.0.0.1")
        assert target.is_valid is True
        assert target.is_ip is True
        assert target.hostname == "10.0.0.1"

    def test_empty_input(self):
        target = normalize_target("")
        assert target.is_valid is False
        assert "empty" in target.error_message.lower()

        target_whitespace = normalize_target("   ")
        assert target_whitespace.is_valid is False

    def test_malformed_input(self):
        # Invalid chars / spaces / credentials syntax
        bad_space = normalize_target("bad domain.com")
        assert bad_space.is_valid is False

        bad_at = normalize_target("user:pass@legit.com")
        assert bad_at.is_valid is False

        bad_dots = normalize_target("example..com")
        assert bad_dots.is_valid is False

    def test_validate_target_raises_error(self):
        with pytest.raises(ValueError) as exc_info:
            validate_target("bad domain.com")
        assert "Invalid target" in str(exc_info.value)

        # Valid domain should not raise
        info = validate_target("google.com")
        assert info.is_valid is True


class TestFeatureExtraction:
    """Test suite for lexical feature extraction in features.py."""

    def test_feature_vector_structure_and_types(self):
        result = extract_features("example.com")
        assert len(result.feature_names) == len(FEATURE_NAMES)
        assert len(result.feature_vector) == len(FEATURE_NAMES)
        assert all(isinstance(x, (int, float)) for x in result.feature_vector)
        assert result.features["num_dots"] >= 1
        assert result.features["domain_length"] == len("example.com")

    def test_suspicious_keywords_detection(self):
        result = extract_features("paypal-login-verify-account.com")
        assert result.features["suspicious_keyword_count"] >= 3
        # Should produce at least one high signal for keywords
        assert any("[HIGH] Contains suspicious phishing keyword" in s for s in result.signals)

    def test_ip_address_signal(self):
        result = extract_features("http://192.168.1.50/login")
        assert result.features["has_ip"] == 1
        assert any("[CRITICAL] Uses direct IP address" in s for s in result.signals)

    def test_subdomains_signal(self):
        result = extract_features("secure.login.portal.bank-update.com")
        assert result.features["num_subdomains"] >= 2
        assert any("[MEDIUM] High number of subdomains" in s for s in result.signals)

    def test_entropy_calculation(self):
        # Repetitive string has low entropy
        low_ent = calculate_entropy("aaaaaaa")
        # Varied random-like string has higher entropy
        high_ent = calculate_entropy("q7w8e9r0tz1x2c3")
        assert low_ent == 0.0
        assert high_ent > 3.0

    def test_clean_benign_domain_signals(self):
        result = extract_features("google.com")
        # Benign simple domain should have 0 suspicious keywords and no IP address
        assert result.features["suspicious_keyword_count"] == 0
        assert result.features["has_ip"] == 0
        assert len(result.signals) == 0
