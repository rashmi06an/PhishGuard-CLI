"""Unit tests for brand lookalike similarity and typosquatting detection."""

import pytest

from phishguard.similarity import (
    SimilarityResult,
    analyze_brand_lookalike,
    compare_two_domains,
    normalize_homoglyphs,
)


class TestHomoglyphNormalization:
    """Test suite for character normalization of visual lookalikes."""

    def test_digit_substitutions(self):
        # 0 -> o, 1 -> l, 5 -> s
        assert normalize_homoglyphs("g00gle") == "google"
        assert normalize_homoglyphs("paypa1") == "paypal"
        assert normalize_homoglyphs("ch0sen") == "chosen"

    def test_multi_char_substitutions(self):
        # vv -> w, rn -> m
        assert normalize_homoglyphs("vveb") == "web"
        assert normalize_homoglyphs("arnazon") == "amazon"


class TestBrandLookalikeAnalysis:
    """Test suite for analyze_brand_lookalike against known target brands."""

    def test_exact_genuine_brand_matches(self):
        result = analyze_brand_lookalike("google.com")
        assert isinstance(result, SimilarityResult)
        assert result.matched_brand == "google"
        assert result.similarity_score == 100.0
        assert result.is_lookalike is False
        assert result.verdict == "EXACT MATCH (GENUINE BRAND)"
        assert any("Matches known legitimate brand" in s for s in result.signals)

        result_ms = analyze_brand_lookalike("microsoft.com")
        assert result_ms.matched_brand == "microsoft"
        assert result_ms.is_lookalike is False
        assert result_ms.verdict == "EXACT MATCH (GENUINE BRAND)"

    def test_homoglyph_normalized_lookalikes(self):
        # g00gle and goog1e reach 100% normalized similarity via visual de-homoglyphing,
        # but are explicitly flagged as lookalikes, not genuine domains.
        res_0 = analyze_brand_lookalike("g00gle.com")
        assert res_0.matched_brand == "google"
        assert res_0.similarity_score == 100.0
        assert res_0.is_lookalike is True
        assert res_0.verdict == "HIGH LOOKALIKE RISK"
        assert any("homoglyph" in s.lower() for s in res_0.signals)

        res_1 = analyze_brand_lookalike("goog1e.com")
        assert res_1.matched_brand == "google"
        assert res_1.similarity_score == 100.0
        assert res_1.is_lookalike is True
        assert res_1.verdict == "HIGH LOOKALIKE RISK"
        assert any("homoglyph" in s.lower() for s in res_1.signals)

    def test_obvious_typosquatting(self):
        # Insertion / deletion typosquatting
        res_insert = analyze_brand_lookalike("gooogle.com")
        assert res_insert.matched_brand == "google"
        assert res_insert.is_lookalike is True
        assert res_insert.similarity_score >= 80.0

        res_del = analyze_brand_lookalike("amazn.com")
        assert res_del.matched_brand == "amazon"
        assert res_del.is_lookalike is True
        assert res_del.similarity_score >= 80.0

    def test_suspicious_brand_affixes(self):
        # paypal with -security or -login affix
        res = analyze_brand_lookalike("paypal-security-update.com")
        assert res.matched_brand == "paypal"
        assert res.is_lookalike is True
        assert res.similarity_score >= 85.0
        assert any("embedded with suspicious affix" in s for s in res.signals)

        res_apple = analyze_brand_lookalike("apple-login-portal.net")
        assert res_apple.matched_brand == "apple"
        assert res_apple.is_lookalike is True

    def test_unrelated_domains(self):
        # Clean unrelated domains must not produce false positive high lookalike alerts
        res_wiki = analyze_brand_lookalike("wikipedia.org")
        assert res_wiki.is_lookalike is False
        assert res_wiki.verdict == "NO LOOKALIKE RISK"

        res_example = analyze_brand_lookalike("example.com")
        assert res_example.is_lookalike is False
        assert res_example.verdict == "NO LOOKALIKE RISK"

    def test_score_boundaries_and_structure(self):
        test_inputs = [
            "google.com",
            "g00gle.com",
            "paypal-update.net",
            "randomblogsite.org",
            "chase-verify.com",
        ]
        for inp in test_inputs:
            res = analyze_brand_lookalike(inp)
            assert 0.0 <= res.similarity_score <= 100.0
            assert isinstance(res.signals, list)
            assert isinstance(res.is_lookalike, bool)
            assert res.target_domain == inp


class TestPairwiseDomainComparison:
    """Test suite for compare_two_domains."""

    def test_pairwise_genuine_vs_lookalike(self):
        res = compare_two_domains("paypal.com", "paypa1-login.com")
        assert res.matched_brand == "paypal"
        assert res.is_lookalike is True
        assert res.similarity_score >= 85.0
        assert res.verdict == "HIGH LOOKALIKE RISK"
        assert any("homoglyph" in s.lower() for s in res.signals)
        assert any("brand string 'paypal'" in s for s in res.signals)

    def test_pairwise_identical_domains(self):
        res = compare_two_domains("paypal.com", "paypal.com")
        assert res.similarity_score == 100.0
        assert res.is_lookalike is False
        assert res.verdict == "IDENTICAL DOMAINS"
        assert any("same base name" in s for s in res.signals)

    def test_pairwise_completely_unrelated(self):
        res = compare_two_domains("microsoft.com", "tropicalvacations.org")
        assert res.is_lookalike is False
        assert res.similarity_score < 50.0
        assert res.verdict == "LOW SIMILARITY"

    def test_pairwise_single_char_diff(self):
        res = compare_two_domains("github.com", "githhub.com")
        assert res.is_lookalike is True
        assert res.similarity_score >= 80.0
        assert any("typosquat pattern" in s for s in res.signals)
