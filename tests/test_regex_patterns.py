"""Tests for the detection engine: every regex pattern in config.py.

Module under test: scan_litellm_compromise.config
"""

import pytest

from scan_litellm_compromise.config import (
    C2_DOMAINS,
    C2_KNOWN_IPS,
    COMPROMISED_VERSIONS,
    DIST_INFO_PATTERN,
    EGG_INFO_PATTERN,
    PINNED_VERSION_PATTERN,
    PYTHON_IMPORT_PATTERNS,
    REQUIREMENTS_FILENAME_PATTERN,
    REQUIREMENTS_PATTERN,
    TOML_BARE_PATTERN,
    TOML_DEPENDENCY_PATTERN,
)


# ── DIST_INFO_PATTERN ──────────────────────────────────────────────────


class TestDistInfoPattern:

    @pytest.mark.parametrize("dirname, expected_version", [
        ("litellm-1.82.7.dist-info", "1.82.7"),
        ("litellm-1.82.8.dist-info", "1.82.8"),
        ("litellm-0.0.1.dist-info", "0.0.1"),
        ("litellm-1.82.7.dev0.dist-info", "1.82.7.dev0"),
        ("litellm-2.0.0rc1.dist-info", "2.0.0rc1"),
    ])
    def test_matches_valid_litellm_dist_info_dirs(self, dirname, expected_version):
        match = DIST_INFO_PATTERN.match(dirname)
        assert match is not None
        assert match.group(1) == expected_version

    @pytest.mark.parametrize("dirname", [
        "requests-2.31.0.dist-info",
        "LITELLM-1.0.dist-info",
        "some-litellm-1.0.dist-info",
        "litellm-1.0.dist-info-extra",
        "litellm",
        ".dist-info",
        "",
    ])
    def test_rejects_non_litellm_dist_info_dirs(self, dirname):
        assert DIST_INFO_PATTERN.match(dirname) is None


# ── EGG_INFO_PATTERN ───────────────────────────────────────────────────


class TestEggInfoPattern:

    @pytest.mark.parametrize("dirname, expected_version", [
        ("litellm-1.82.7.egg-info", "1.82.7"),
        ("litellm-1.0.egg-info", "1.0"),
        ("litellm-0.0.1a1.egg-info", "0.0.1a1"),
    ])
    def test_matches_valid_litellm_egg_info_dirs(self, dirname, expected_version):
        match = EGG_INFO_PATTERN.match(dirname)
        assert match is not None
        assert match.group(1) == expected_version

    @pytest.mark.parametrize("dirname", [
        "requests-2.31.0.egg-info",
        "notlitellm-1.0.egg-info",
        "litellm-1.0.dist-info",
        "",
    ])
    def test_rejects_non_litellm_egg_info_dirs(self, dirname):
        assert EGG_INFO_PATTERN.match(dirname) is None


# ── PYTHON_IMPORT_PATTERNS ─────────────────────────────────────────────


def _matches_any_import_pattern(line: str) -> bool:
    return any(p.search(line) for p in PYTHON_IMPORT_PATTERNS)


class TestPythonImportPatterns:

    @pytest.mark.parametrize("line", [
        "import litellm",
        "  import litellm",
        "\timport litellm",
        "from litellm import completion",
        "from litellm.proxy import router",
        "from litellm.proxy.auth import handler",
        "result = litellm.completion(model='gpt-4')",
        'name = "litellm"',
        "name = 'litellm'",
        "  from litellm import something",
    ])
    def test_matches_litellm_import_statements(self, line):
        assert _matches_any_import_pattern(line) is True

    @pytest.mark.parametrize("line", [
        "import os",
        "from os import path",
        "# just a comment",
        "",
        "my_variable = 42",
        "import requests",
    ])
    def test_rejects_lines_without_litellm(self, line):
        assert _matches_any_import_pattern(line) is False

    def test_lookbehind_prevents_my_litellm_dot_match(self):
        # The third pattern has (?<![a-zA-Z0-9_]) lookbehind
        # "my_litellm." should NOT match the dotted-access pattern
        line = "my_litellm.something()"
        # Only the bare quoted pattern could match, but there are no quotes here
        # The lookbehind on pattern 3 should prevent "my_litellm." from matching
        pattern_3 = PYTHON_IMPORT_PATTERNS[2]
        assert pattern_3.search(line) is None


# ── TOML_DEPENDENCY_PATTERN ────────────────────────────────────────────


class TestTomlDependencyPattern:

    @pytest.mark.parametrize("line", [
        "litellm>=1.0",
        "litellm==1.82.7",
        "litellm~=1.80",
        "litellm!=1.82.7",
        "litellm<2.0",
        "litellm >  1.0",
        '"litellm>=1.0"',
    ])
    def test_matches_litellm_with_version_specifiers(self, line):
        assert TOML_DEPENDENCY_PATTERN.search(line) is not None

    @pytest.mark.parametrize("line", [
        "requests>=2.0",
        "my-litellm>=1.0",
        "litellm_proxy>=1.0",
        "litellm",
        "",
    ])
    def test_rejects_non_litellm_or_bare_references(self, line):
        assert TOML_DEPENDENCY_PATTERN.search(line) is None


# ── TOML_BARE_PATTERN ──────────────────────────────────────────────────


class TestTomlBarePattern:

    @pytest.mark.parametrize("line", [
        '"litellm"',
        "'litellm'",
        'dependencies = ["litellm"]',
        "dependencies = ['litellm']",
    ])
    def test_matches_quoted_litellm(self, line):
        assert TOML_BARE_PATTERN.search(line) is not None

    @pytest.mark.parametrize("line", [
        "litellm",
        '"litellm_proxy"',
        '"my-litellm"',
        "",
    ])
    def test_rejects_unquoted_or_different_packages(self, line):
        assert TOML_BARE_PATTERN.search(line) is None


# ── REQUIREMENTS_PATTERN ───────────────────────────────────────────────


class TestRequirementsPattern:

    @pytest.mark.parametrize("line", [
        "litellm==1.82.7",
        "litellm>=1.80",
        "litellm",
        "  litellm==1.0",
        "litellm<2.0",
        "litellm!=1.82.7",
    ])
    def test_matches_litellm_dependency_lines(self, line):
        assert REQUIREMENTS_PATTERN.match(line) is not None

    @pytest.mark.parametrize("line", [
        "requests==2.31",
        "# litellm==1.82.7",
        "-e git+https://litellm",
        "",
    ])
    def test_rejects_non_litellm_lines(self, line):
        assert REQUIREMENTS_PATTERN.match(line) is None


# ── REQUIREMENTS_FILENAME_PATTERN ──────────────────────────────────────


class TestRequirementsFilenamePattern:

    @pytest.mark.parametrize("filename", [
        "requirements.txt",
        "requirements-dev.txt",
        "requirements_prod.txt",
        "requirements-ml-gpu.txt",
    ])
    def test_matches_requirements_filenames(self, filename):
        assert REQUIREMENTS_FILENAME_PATTERN.match(filename) is not None

    @pytest.mark.parametrize("filename", [
        "my-requirements.txt",
        "requirements.cfg",
        "requirements.toml",
        "REQUIREMENTS.txt",
        "",
    ])
    def test_rejects_non_requirements_filenames(self, filename):
        assert REQUIREMENTS_FILENAME_PATTERN.match(filename) is None


# ── PINNED_VERSION_PATTERN ─────────────────────────────────────────────


class TestPinnedVersionPattern:

    @pytest.mark.parametrize("line, expected_version", [
        ("litellm==1.82.7", "1.82.7"),
        ("litellm==1.82.8", "1.82.8"),
        ("litellm == 1.82.7", "1.82.7"),
        ("litellm==1.80.0.dev3", "1.80.0.dev3"),
        ('"litellm==1.82.7"', "1.82.7"),
    ])
    def test_extracts_pinned_version(self, line, expected_version):
        match = PINNED_VERSION_PATTERN.search(line)
        assert match is not None
        assert match.group(1) == expected_version

    @pytest.mark.parametrize("line", [
        "litellm>=1.82.7",
        "litellm~=1.80",
        "litellm",
        "requests==2.31.0",
        "my-litellm==1.0",
        "",
    ])
    def test_returns_none_for_unpinned_or_other_packages(self, line):
        assert PINNED_VERSION_PATTERN.search(line) is None


# ── Constants ──────────────────────────────────────────────────────────


class TestConstants:

    def test_compromised_versions_contains_exactly_known_bad_versions(self):
        assert COMPROMISED_VERSIONS == frozenset({"1.82.7", "1.82.8"})

    def test_c2_domains_contains_expected_domains(self):
        assert "models.litellm.cloud" in C2_DOMAINS
        assert "checkmarx.zone" in C2_DOMAINS
        assert len(C2_DOMAINS) == 2

    def test_c2_known_ips_covers_all_domains(self):
        for domain in C2_DOMAINS:
            assert domain in C2_KNOWN_IPS
            assert len(C2_KNOWN_IPS[domain]) >= 1

    def test_c2_known_ips_contains_expected_ips(self):
        assert "46.151.182.203" in C2_KNOWN_IPS["models.litellm.cloud"]
        assert "83.142.209.11" in C2_KNOWN_IPS["checkmarx.zone"]
