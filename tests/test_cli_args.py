"""Tests for CLI argument parsing.

Module under test: scan_litellm_compromise.scanner._parse_args
"""

import pytest

from scan_litellm_compromise.scanner import _parse_args


class TestParseArgs:

    def test_defaults_when_no_args(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["scan-litellm"])

        args = _parse_args()

        assert args.scan_path is None
        assert args.resolve_c2 is False

    def test_scan_path_captures_directory(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["scan-litellm", "--scan-path", "/some/dir"])

        args = _parse_args()

        assert args.scan_path == "/some/dir"

    def test_resolve_c2_flag(self, monkeypatch):
        monkeypatch.setattr("sys.argv", ["scan-litellm", "--resolve-c2"])

        args = _parse_args()

        assert args.resolve_c2 is True

    def test_both_flags_together(self, monkeypatch):
        monkeypatch.setattr(
            "sys.argv",
            ["scan-litellm", "--scan-path", "./project", "--resolve-c2"],
        )

        args = _parse_args()

        assert args.scan_path == "./project"
        assert args.resolve_c2 is True
