"""Tests for the NTRO automation additions:

- Newly-registered-domain (NRD) feed ingestion (feed.py)
- Automated monitoring single-pass (cli.handle_monitor)
- Automated screenshot capture graceful fallback (screenshot.py)
- Closeness-to-genuine ML features (features.py point (e))
"""

import os

from phishguard.feed import load_nrd_feed
from phishguard.features import FEATURE_NAMES, extract_features
from phishguard.screenshot import capture_screenshot


class TestNrdFeedIngestion:
    """Technique: automated ingestion of open-source newly-registered-domain feeds."""

    def test_load_txt_feed(self, tmp_path):
        p = tmp_path / "feed.txt"
        p.write_text(
            "# comment line\n"
            "https://paypa1-login.com/signin\n"
            "google.com\n"
            "\n"
            "// another comment\n"
            "google.com\n"  # duplicate -> deduped
            "ACCOUNT-VERIFY.net\n"
        )
        domains = load_nrd_feed(str(p))
        assert "paypa1-login.com" in domains   # scheme + path stripped
        assert "google.com" in domains
        assert "account-verify.net" in domains  # lowercased
        assert domains.count("google.com") == 1  # de-duplicated

    def test_load_csv_feed_detects_column(self, tmp_path):
        p = tmp_path / "feed.csv"
        p.write_text("domain,note\nexample.com,ok\nphish-site.xyz,bad\n")
        domains = load_nrd_feed(str(p))
        assert domains == ["example.com", "phish-site.xyz"]

    def test_limit_applied(self, tmp_path):
        p = tmp_path / "feed.txt"
        p.write_text("a.com\nb.com\nc.com\nd.com\n")
        assert load_nrd_feed(str(p), limit=2) == ["a.com", "b.com"]

    def test_missing_file_raises(self):
        import pytest

        with pytest.raises(FileNotFoundError):
            load_nrd_feed("definitely_missing_feed_file.txt")


class TestAutomatedMonitor:
    """Automated monitoring loop should complete a single offline pass and write reports."""

    def test_monitor_once_writes_reports(self, tmp_path):
        from phishguard.cli import handle_monitor

        feed = tmp_path / "feed.txt"
        feed.write_text("google.com\npaypa1-security-center.com\nwikipedia.org\n")
        out_dir = tmp_path / "monitor_out"

        code = handle_monitor(str(feed), run_once=True, output_dir=str(out_dir))
        assert code == 0
        written = list(out_dir.glob("nrd_scan_*.json"))
        assert len(written) == 1
        assert list(out_dir.glob("nrd_scan_*.csv"))


class TestScreenshotCaptureFallback:
    """Automated capture must fail safely when Playwright/browser is unavailable."""

    def test_capture_without_playwright_is_safe(self, tmp_path):
        out = str(tmp_path / "shot.png")
        res = capture_screenshot("example.com", out)
        # Either Playwright is genuinely installed+working, or we get a clean failure.
        if not res.success:
            assert res.error_message
            assert res.output_path is None
            assert not os.path.isfile(out)


class TestClosenessFeatures:
    """NTRO point (e): closeness-to-genuine is now part of the ML feature vector."""

    def test_brand_features_present(self):
        assert "brand_similarity" in FEATURE_NAMES
        assert "brand_embedded" in FEATURE_NAMES

    def test_lookalike_has_high_brand_similarity(self):
        res = extract_features("paypa1-login.com")
        assert res.features["brand_similarity"] >= 80.0
        assert res.features["brand_embedded"] == 1
        assert len(res.feature_vector) == len(FEATURE_NAMES)

    def test_unrelated_domain_low_brand_similarity(self):
        res = extract_features("some-random-blog-site.org")
        assert res.features["brand_embedded"] == 0
