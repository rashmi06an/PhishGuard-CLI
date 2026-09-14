"""Integration tests for CLI entrypoints and command handlers."""

import os
import pytest

from phishguard.cli import (
    build_parser,
    handle_batch,
    handle_compare,
    handle_demo,
    handle_report,
    handle_scan,
)


class TestCLIIntegration:
    """Test suite for CLI arguments and subcommand execution handlers."""

    def test_build_parser_subcommands(self):
        parser = build_parser()
        args_scan = parser.parse_args(["scan", "example.com"])
        assert args_scan.command == "scan"
        assert args_scan.target == "example.com"

        args_comp = parser.parse_args(["compare", "paypal.com", "paypa1.com"])
        assert args_comp.command == "compare"

        args_batch = parser.parse_args(["batch", "data/demo_domains.csv"])
        assert args_batch.command == "batch"

        args_train = parser.parse_args(["train"])
        assert args_train.command == "train"

        args_demo = parser.parse_args(["demo"])
        assert args_demo.command == "demo"

    def test_handle_compare_valid_and_invalid(self):
        # Valid comparison returns 0
        code = handle_compare("paypal.com", "paypa1-login.com")
        assert code == 0

        # Invalid domain returns 1
        code_err = handle_compare("paypal.com", "invalid@@domain.com")
        assert code_err == 1

    def test_handle_scan_valid_and_invalid(self, tmp_path):
        # Valid scan returns 0
        code = handle_scan("google.com", output_format="terminal")
        assert code == 0

        # JSON format with export
        out_json = str(tmp_path / "test_scan.json")
        code_json = handle_scan("wikipedia.org", output_format="json", output_path=out_json)
        assert code_json == 0
        assert os.path.isfile(out_json)

        # Invalid domain returns 1
        code_err = handle_scan("invalid domain with spaces.com")
        assert code_err == 1

    def test_handle_batch_and_report(self, tmp_path):
        out_batch = str(tmp_path / "batch_out.json")
        code = handle_batch("data/demo_domains.csv", output_format="terminal", output_path=out_batch)
        assert code == 0
        assert os.path.isfile(out_batch)

        # Report inspector should succeed on generated JSON
        code_rep = handle_report(out_batch)
        assert code_rep == 0

        # Missing batch input returns 1
        code_missing = handle_batch("non_existent_file.csv")
        assert code_missing == 1

        # Missing report file returns 1
        code_missing_rep = handle_report("non_existent_report.json")
        assert code_missing_rep == 1

    def test_handle_demo_execution(self):
        # Full offline demo workflow
        code = handle_demo()
        assert code == 0
