"""Tests for Phase 2: extracting litellm versions from metadata.

Module under test: scan_litellm_compromise.version_checker
"""

from pathlib import Path

import pytest

from scan_litellm_compromise.models import ScanResults
from scan_litellm_compromise.version_checker import (
    _extract_version,
    _read_version_from_file,
    scan_environments,
)


# ── _read_version_from_file ───────────────────────────────────────────


class TestReadVersionFromFile:

    def test_extracts_version_from_standard_metadata(self, tmp_path):
        metadata = tmp_path / "METADATA"
        metadata.write_text(
            "Metadata-Version: 2.1\n"
            "Name: litellm\n"
            "Version: 1.82.7\n"
            "Summary: A library\n"
        )
        assert _read_version_from_file(metadata) == "1.82.7"

    def test_returns_none_for_missing_version_field(self, tmp_path):
        metadata = tmp_path / "METADATA"
        metadata.write_text("Metadata-Version: 2.1\nName: litellm\n")
        assert _read_version_from_file(metadata) is None

    def test_returns_none_for_nonexistent_file(self, tmp_path):
        assert _read_version_from_file(tmp_path / "METADATA") is None

    def test_strips_whitespace_from_version(self, tmp_path):
        metadata = tmp_path / "METADATA"
        metadata.write_text("Version:  1.82.7  \n")
        assert _read_version_from_file(metadata) == "1.82.7"

    def test_handles_permission_error(self, tmp_path, monkeypatch):
        metadata = tmp_path / "METADATA"
        metadata.write_text("Version: 1.82.7\n")
        monkeypatch.setattr(
            Path, "read_text",
            lambda *a, **kw: (_ for _ in ()).throw(PermissionError("denied")),
        )
        assert _read_version_from_file(metadata) is None


# ── _extract_version ──────────────────────────────────────────────────


class TestExtractVersion:

    def test_prefers_metadata_file_over_dirname(self, tmp_path):
        dist_info = tmp_path / "litellm-1.82.7.dist-info"
        dist_info.mkdir()
        (dist_info / "METADATA").write_text("Version: 1.82.8\n")

        # File says 1.82.8 but dirname says 1.82.7 — file wins
        assert _extract_version(dist_info) == "1.82.8"

    def test_falls_back_to_pkg_info_when_metadata_missing(self, tmp_path):
        dist_info = tmp_path / "litellm-1.82.7.dist-info"
        dist_info.mkdir()
        (dist_info / "PKG-INFO").write_text("Version: 1.82.7\n")

        assert _extract_version(dist_info) == "1.82.7"

    def test_falls_back_to_dist_info_dirname(self, tmp_path):
        dist_info = tmp_path / "litellm-1.82.7.dist-info"
        dist_info.mkdir()
        # No METADATA or PKG-INFO files

        assert _extract_version(dist_info) == "1.82.7"

    def test_falls_back_to_egg_info_dirname(self, tmp_path):
        egg_info = tmp_path / "litellm-1.82.8.egg-info"
        egg_info.mkdir()

        assert _extract_version(egg_info) == "1.82.8"

    def test_returns_none_for_unrecognized_dirname(self, tmp_path):
        unknown = tmp_path / "litellm-unknown"
        unknown.mkdir()

        assert _extract_version(unknown) is None

    def test_metadata_with_empty_version_falls_back_to_dirname(self, tmp_path):
        dist_info = tmp_path / "litellm-1.82.7.dist-info"
        dist_info.mkdir()
        (dist_info / "METADATA").write_text("Name: litellm\n")
        # METADATA exists but has no Version field, fall back to dirname

        assert _extract_version(dist_info) == "1.82.7"


# ── scan_environments (integration) ───────────────────────────────────


class TestScanEnvironments:

    def test_populates_results_with_installations(self, tmp_path):
        dist_info = tmp_path / "litellm-1.82.7.dist-info"
        dist_info.mkdir()
        (dist_info / "METADATA").write_text("Version: 1.82.7\n")

        results = ScanResults()
        scan_environments([dist_info], results)

        assert results.envs_scanned == 1
        assert len(results.installations) == 1
        assert results.installations[0].version == "1.82.7"

    def test_prints_compromised_label(self, tmp_path, capsys):
        dist_info = tmp_path / "litellm-1.82.7.dist-info"
        dist_info.mkdir()
        (dist_info / "METADATA").write_text("Version: 1.82.7\n")

        results = ScanResults()
        scan_environments([dist_info], results)

        captured = capsys.readouterr().out
        assert "COMPROMISED" in captured

    def test_prints_clean_label_for_safe_version(self, tmp_path, capsys):
        dist_info = tmp_path / "litellm-1.80.0.dist-info"
        dist_info.mkdir()
        (dist_info / "METADATA").write_text("Version: 1.80.0\n")

        results = ScanResults()
        scan_environments([dist_info], results)

        captured = capsys.readouterr().out
        assert "clean" in captured

    def test_prints_no_installations_message_when_empty(self, capsys):
        results = ScanResults()
        scan_environments([], results)

        captured = capsys.readouterr().out
        assert "No litellm installations found" in captured

    def test_skips_unreadable_metadata(self, tmp_path):
        dist_info = tmp_path / "litellm-unknown"
        dist_info.mkdir()
        # dirname doesn't match patterns, no metadata files

        results = ScanResults()
        scan_environments([dist_info], results)

        assert results.envs_scanned == 1
        assert results.installations == []
