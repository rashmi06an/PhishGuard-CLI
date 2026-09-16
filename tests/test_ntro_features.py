"""Unit tests for NTRO 2023 cybersecurity features.

Covers:
(a) Backend code / content similarity in web pages
(b) Web page image analysis and visual lookalike probability scoring
(c) Open source WHOIS database & newly registered domain (NRD) analysis
"""

import os
from unittest.mock import MagicMock, patch
import pytest
from PIL import Image

from phishguard.image_analyzer import (
    calculate_color_histogram_similarity,
    calculate_dhash,
    compare_webpage_images,
)
from phishguard.web_analyzer import compare_webpage_content
from phishguard.whois_analyzer import _parse_creation_date, lookup_whois


class TestImageAnalyzer:
    """Test suite for Technique (b): Web page image analysis."""

    def test_calculate_dhash_identical_images(self, tmp_path):
        img_path = str(tmp_path / "test1.png")
        img = Image.new("RGB", (64, 64), color=(100, 150, 200))
        img.save(img_path)

        hash1 = calculate_dhash(img)
        hash2 = calculate_dhash(img)
        assert hash1 == hash2

    def test_compare_webpage_images_cloned(self, tmp_path):
        p1 = str(tmp_path / "gen.png")
        p2 = str(tmp_path / "phish.png")

        img1 = Image.new("RGB", (100, 100), color=(0, 50, 200))
        img2 = Image.new("RGB", (100, 100), color=(0, 50, 200))
        img1.save(p1)
        img2.save(p2)

        res = compare_webpage_images(p1, p2)
        assert res.is_visual_lookalike is True
        assert res.similarity_score >= 95.0
        assert res.visual_probability_score >= 0.95
        assert res.dhash_distance == 0

    def test_compare_webpage_images_distinct(self, tmp_path):
        from PIL import ImageDraw
        p1 = str(tmp_path / "img1.png")
        p2 = str(tmp_path / "img2.png")

        img1 = Image.new("RGB", (100, 100), color=(255, 255, 255))
        d1 = ImageDraw.Draw(img1)
        d1.rectangle([(10, 10), (90, 40)], fill=(0, 0, 255))

        img2 = Image.new("RGB", (100, 100), color=(200, 250, 200))
        d2 = ImageDraw.Draw(img2)
        d2.ellipse([(20, 50), (80, 90)], fill=(255, 0, 0))

        img1.save(p1)
        img2.save(p2)

        res = compare_webpage_images(p1, p2)
        assert res.is_visual_lookalike is False

    def test_compare_images_missing_file(self):
        res = compare_webpage_images("nonexistent_img_1.png", "nonexistent_img_2.png")
        assert res.is_visual_lookalike is False
        assert "Could not load image" in (res.error_message or "")


class TestContentSimilarity:
    """Test suite for Technique (a): Backend code / content similarity."""

    def test_identical_dom_and_forms(self):
        html1 = """
        <html><head><title>Account Sign In</title></head>
        <body><form action='/login'><input type='password' name='pass'/></form></body></html>
        """
        html2 = """
        <html><head><title>Account Sign In</title></head>
        <body><form action='/login'><input type='password' name='pass'/></form></body></html>
        """
        res = compare_webpage_content(html1, html2)
        assert res.is_content_lookalike is True
        assert res.content_similarity_score >= 95.0
        assert res.similarity_probability >= 0.95
        assert res.dom_similarity == 100.0
        assert res.form_similarity == 100.0

    def test_distinct_dom_and_content(self):
        html1 = "<html><body><form><input type='password'/></form></body></html>"
        html2 = "<html><body><h1>Welcome to encyclopedia</h1><p>Articles list</p></body></html>"
        res = compare_webpage_content(html1, html2)
        assert res.is_content_lookalike is False
        assert res.content_similarity_score < 70.0


class TestWhoisAnalyzer:
    """Test suite for Open Source WHOIS Database integration."""

    def test_parse_creation_date_formats(self):
        d1 = _parse_creation_date("2024-01-15")
        assert d1 is not None
        assert d1.year == 2024

        d2 = _parse_creation_date(["2023-05-10 12:00:00"])
        assert d2 is not None
        assert d2.year == 2023

    def test_lookup_whois_local_skip(self):
        res = lookup_whois("localhost")
        assert res.is_available is False
        assert "Skipped" in (res.error_message or "")

    def test_lookup_whois_newly_registered_mock(self):
        from datetime import datetime, timedelta, timezone

        mock_whois = MagicMock()
        mock_whois.creation_date = datetime.now(timezone.utc) - timedelta(days=5)
        mock_whois.registrar = "NameCheap, Inc."

        with patch("whois.whois", return_value=mock_whois):
            res = lookup_whois("brand-new-fake-login.xyz")
            assert res.is_available is True
            assert res.is_newly_registered is True
            assert res.domain_age_days <= 5
            assert any("Newly Registered Domain" in s for s in res.signals)
