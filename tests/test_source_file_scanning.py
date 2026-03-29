"""Tests for Phase 4 I/O: scanning source and config files for litellm references.

Module under test: scan_litellm_compromise.source_scanner (I/O functions)
"""

from pathlib import Path

import pytest

from scan_litellm_compromise.models import ScanResults
from scan_litellm_compromise.source_scanner import (
    _deduplicate_roots,
    _scan_file_lines,
    scan_source_and_configs,
)
from tests.conftest import StubPolicy


# ── _scan_file_lines ──────────────────────────────────────────────────


class TestScanFileLines:

    def test_detects_litellm_import_in_python_source(self, tmp_path):
        py_file = tmp_path / "app.py"
        py_file.write_text("import os\nimport litellm\nx = 1\n")

        results = ScanResults()
        _scan_file_lines(py_file, is_source=True, results=results)

        assert len(results.source_refs) == 1
        assert results.source_refs[0].line_number == 2
        assert "import litellm" in results.source_refs[0].line_content

    def test_detects_litellm_in_requirements_file(self, tmp_path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("flask>=2.0\nlitellm==1.82.7\nrequests>=2.0\n")

        results = ScanResults()
        _scan_file_lines(req_file, is_source=False, results=results)

        assert len(results.config_refs) == 1
        assert results.config_refs[0].pinned_version == "1.82.7"
        assert results.config_refs[0].line_number == 2

    def test_skips_file_without_litellm_keyword(self, tmp_path):
        py_file = tmp_path / "utils.py"
        py_file.write_text("import os\nimport sys\nx = 42\n")

        results = ScanResults()
        _scan_file_lines(py_file, is_source=True, results=results)

        assert results.source_refs == []

    def test_handles_permission_error_gracefully(self, tmp_path, monkeypatch):
        py_file = tmp_path / "secret.py"
        py_file.write_text("import litellm\n")
        monkeypatch.setattr(
            Path, "read_text",
            lambda *a, **kw: (_ for _ in ()).throw(PermissionError("denied")),
        )

        results = ScanResults()
        _scan_file_lines(py_file, is_source=True, results=results)

        assert results.source_refs == []

    def test_records_correct_line_numbers_for_multiple_matches(self, tmp_path):
        py_file = tmp_path / "multi.py"
        py_file.write_text(
            "# header\n"          # line 1
            "import os\n"          # line 2
            "import litellm\n"     # line 3
            "x = 1\n"             # line 4
            "y = 2\n"             # line 5
            "z = 3\n"             # line 6
            "litellm.completion()\n"  # line 7
        )

        results = ScanResults()
        _scan_file_lines(py_file, is_source=True, results=results)

        line_numbers = [ref.line_number for ref in results.source_refs]
        assert 3 in line_numbers
        assert 7 in line_numbers

    def test_extracts_pinned_version_in_config_mode(self, tmp_path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("litellm==1.82.8\n")

        results = ScanResults()
        _scan_file_lines(req_file, is_source=False, results=results)

        assert results.config_refs[0].pinned_version == "1.82.8"

    def test_records_none_version_for_unpinned_config(self, tmp_path):
        toml_file = tmp_path / "pyproject.toml"
        toml_file.write_text('dependencies = ["litellm"]\n')

        results = ScanResults()
        _scan_file_lines(toml_file, is_source=False, results=results)

        assert len(results.config_refs) == 1
        assert results.config_refs[0].pinned_version is None


# ── _deduplicate_roots ────────────────────────────────────────────────


class TestDeduplicateRoots:

    def test_removes_subdirectory_of_another_root(self, tmp_path):
        parent = tmp_path / "parent"
        child = parent / "child"
        parent.mkdir()
        child.mkdir()

        result = _deduplicate_roots([str(parent), str(child)])

        assert result == [str(parent)]

    def test_keeps_independent_roots(self, tmp_path):
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        dir_a.mkdir()
        dir_b.mkdir()

        result = _deduplicate_roots([str(dir_a), str(dir_b)])

        assert len(result) == 2

    def test_skips_nonexistent_directories(self, tmp_path):
        existing = tmp_path / "exists"
        existing.mkdir()

        result = _deduplicate_roots([str(existing), str(tmp_path / "nope")])

        assert result == [str(existing)]


# ── scan_source_and_configs with scan_path ────────────────────────────


class TestScanSourceAndConfigsWithScanPath:

    def test_scans_only_given_directory(self, tmp_path, monkeypatch):
        project = tmp_path / "myproject"
        project.mkdir()
        (project / "app.py").write_text("import litellm\n")

        # Create a file outside scan_path that should NOT be found
        other = tmp_path / "other"
        other.mkdir()
        (other / "other.py").write_text("import litellm\n")

        policy = StubPolicy()
        results = ScanResults()
        scan_source_and_configs(results, policy, scan_path=str(project))

        found_paths = {ref.file_path for ref in results.source_refs}
        assert any("myproject" in p for p in found_paths)
        assert not any("other" in p for p in found_paths)

    def test_ignores_home_when_scan_path_set(self, tmp_path, monkeypatch):
        project = tmp_path / "project"
        project.mkdir()
        (project / "main.py").write_text("import litellm\n")

        policy = StubPolicy()
        results = ScanResults()
        files_scanned = scan_source_and_configs(
            results, policy, scan_path=str(project),
        )

        assert files_scanned >= 1
        assert len(results.source_refs) >= 1
