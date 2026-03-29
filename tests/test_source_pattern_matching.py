"""Tests for the source scanner's pure pattern-matching helpers.

Module under test: scan_litellm_compromise.source_scanner (pure functions only)
"""

import pytest

from scan_litellm_compromise.source_scanner import (
    _extract_pinned_version,
    _is_config_file,
    _matches_config_pattern,
    _matches_source_pattern,
)


# ── _is_config_file ────────────────────────────────────────────────────


class TestIsConfigFile:

    @pytest.mark.parametrize("filename, extension", [
        ("pyproject.toml", ".toml"),
        ("setup.cfg", ".cfg"),
        ("setup.py", ".py"),
        ("requirements.txt", ".txt"),
        ("requirements-dev.txt", ".txt"),
        ("requirements-prod.txt", ".txt"),
        ("Pipfile", ""),
        ("Pipfile.lock", ".lock"),
        ("poetry.lock", ".lock"),
        ("pdm.lock", ".lock"),
        ("uv.lock", ".lock"),
    ])
    def test_recognizes_known_config_filenames(self, filename, extension):
        assert _is_config_file(filename, extension) is True

    @pytest.mark.parametrize("filename, extension", [
        ("requirements-custom.txt", ".txt"),
        ("requirements_ml.txt", ".txt"),
        ("requirements-gpu.txt", ".txt"),
    ])
    def test_recognizes_requirements_filename_variants(self, filename, extension):
        assert _is_config_file(filename, extension) is True

    @pytest.mark.parametrize("filename, extension", [
        ("requirements-extra.toml", ".toml"),
        ("requirements-extra.cfg", ".cfg"),
    ])
    def test_recognizes_toml_cfg_with_require_in_name(self, filename, extension):
        assert _is_config_file(filename, extension) is True

    @pytest.mark.parametrize("filename, extension", [
        ("app.py", ".py"),
        ("README.md", ".md"),
        ("settings.toml", ".toml"),
        ("config.cfg", ".cfg"),
        ("data.json", ".json"),
        ("my-requirements.txt", ".txt"),
    ])
    def test_rejects_non_config_files(self, filename, extension):
        assert _is_config_file(filename, extension) is False


# ── _extract_pinned_version ────────────────────────────────────────────


class TestExtractPinnedVersion:

    @pytest.mark.parametrize("line, expected", [
        ("litellm==1.82.7", "1.82.7"),
        ("litellm==1.82.8", "1.82.8"),
        ("litellm == 1.82.7", "1.82.7"),
        ("litellm==1.80.0.dev3", "1.80.0.dev3"),
        ('"litellm==1.82.7"', "1.82.7"),
        ("  litellm==1.82.7  ", "1.82.7"),
    ])
    def test_returns_version_for_pinned_dependency(self, line, expected):
        assert _extract_pinned_version(line) == expected

    @pytest.mark.parametrize("line", [
        "litellm>=1.80",
        "litellm~=1.80",
        "litellm",
        "requests==2.31",
        "",
    ])
    def test_returns_none_for_unpinned_or_other_packages(self, line):
        assert _extract_pinned_version(line) is None


# ── _matches_source_pattern ────────────────────────────────────────────


class TestMatchesSourcePattern:

    @pytest.mark.parametrize("line", [
        "import litellm",
        "  import litellm",
        "from litellm import completion",
        "from litellm.proxy import handler",
        "result = litellm.completion(model='gpt-4')",
        '"litellm"',
        "'litellm'",
    ])
    def test_identifies_litellm_usage_in_source(self, line):
        assert _matches_source_pattern(line) is True

    @pytest.mark.parametrize("line", [
        "import os",
        "from os import path",
        "x = 42",
        "",
    ])
    def test_rejects_lines_without_litellm_usage(self, line):
        assert _matches_source_pattern(line) is False


# ── _matches_config_pattern ────────────────────────────────────────────


class TestMatchesConfigPattern:

    @pytest.mark.parametrize("stripped, raw", [
        ("litellm>=1.80", "litellm>=1.80"),
        ("litellm==1.82.7", "litellm==1.82.7"),
        ('"litellm"', '"litellm"'),
        ("'litellm'", "'litellm'"),
        ("litellm", "  litellm"),
    ])
    def test_identifies_litellm_dependencies(self, stripped, raw):
        assert _matches_config_pattern(stripped, raw) is True

    @pytest.mark.parametrize("stripped, raw", [
        ("requests>=2.0", "requests>=2.0"),
        ("flask==2.0", "flask==2.0"),
        ("", ""),
    ])
    def test_rejects_non_litellm_dependencies(self, stripped, raw):
        assert _matches_config_pattern(stripped, raw) is False

    def test_handles_leading_whitespace_in_raw_line(self):
        assert _matches_config_pattern("litellm>=1.0", "  litellm>=1.0") is True
