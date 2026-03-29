"""Tests for Phase 5: summary report and output formatting.

Modules under test: scan_litellm_compromise.report, scan_litellm_compromise.formatting
"""

import pytest

from scan_litellm_compromise.models import (
    ConfigReference,
    Installation,
    ScanResults,
    SourceReference,
)
from scan_litellm_compromise.report import (
    _format_version_tag,
    _group_by_file,
    print_config_refs,
    print_source_refs,
    print_summary,
)
from tests.conftest import StubPolicy


# ── _group_by_file (pure) ────────────────────────────────────────────


class TestGroupByFile:

    def test_groups_refs_by_file_path(self):
        refs = [
            SourceReference("/a.py", 1, "import litellm"),
            SourceReference("/a.py", 5, "litellm.completion()"),
            SourceReference("/b.py", 3, "import litellm"),
        ]
        grouped = _group_by_file(refs)

        assert len(grouped) == 2
        assert len(grouped["/a.py"]) == 2
        assert len(grouped["/b.py"]) == 1

    def test_preserves_insertion_order(self):
        refs = [
            SourceReference("/z.py", 1, "a"),
            SourceReference("/a.py", 1, "b"),
            SourceReference("/m.py", 1, "c"),
        ]
        grouped = _group_by_file(refs)

        assert list(grouped.keys()) == ["/z.py", "/a.py", "/m.py"]

    def test_returns_empty_dict_for_empty_input(self):
        assert _group_by_file([]) == {}


# ── _format_version_tag (pure) ───────────────────────────────────────


class TestFormatVersionTag:

    def test_shows_compromised_label_for_bad_version(self):
        ref = ConfigReference("r.txt", 1, "litellm==1.82.7", "1.82.7")
        tag = _format_version_tag(ref)
        assert "COMPROMISED" in tag

    def test_shows_safe_version_for_good_version(self):
        ref = ConfigReference("r.txt", 1, "litellm==1.80.0", "1.80.0")
        tag = _format_version_tag(ref)
        assert "v1.80.0" in tag

    def test_returns_empty_string_when_no_pinned_version(self):
        ref = ConfigReference("r.txt", 1, '"litellm"', None)
        assert _format_version_tag(ref) == ""


# ── print_source_refs (stdout) ───────────────────────────────────────


class TestPrintSourceRefs:

    def test_shows_file_paths_and_line_contents(self, capsys):
        refs = [
            SourceReference("/app.py", 10, "import litellm"),
            SourceReference("/utils.py", 5, "from litellm import completion"),
        ]
        print_source_refs(refs)

        captured = capsys.readouterr().out
        assert "/app.py" in captured
        assert "/utils.py" in captured
        assert "import litellm" in captured

    def test_truncates_after_five_lines_per_file(self, capsys):
        refs = [
            SourceReference("/big.py", i, f"litellm line {i}")
            for i in range(1, 9)
        ]
        print_source_refs(refs)

        captured = capsys.readouterr().out
        assert "and 3 more references" in captured

    def test_shows_clean_message_when_empty(self, capsys):
        print_source_refs([])

        captured = capsys.readouterr().out
        assert "No litellm imports found" in captured


# ── print_config_refs (stdout) ───────────────────────────────────────


class TestPrintConfigRefs:

    def test_shows_version_annotations(self, capsys):
        refs = [
            ConfigReference("r.txt", 1, "litellm==1.82.7", "1.82.7"),
            ConfigReference("r.txt", 3, "litellm==1.80.0", "1.80.0"),
        ]
        print_config_refs(refs)

        captured = capsys.readouterr().out
        assert "COMPROMISED" in captured
        assert "v1.80.0" in captured

    def test_shows_clean_message_when_empty(self, capsys):
        print_config_refs([])

        captured = capsys.readouterr().out
        assert "No litellm dependencies found" in captured


# ── print_summary (stdout) ───────────────────────────────────────────


class TestPrintSummary:

    def test_shows_clean_verdict_when_no_issues(self, capsys):
        results = ScanResults()
        print_summary(results, StubPolicy())

        captured = capsys.readouterr().out
        assert "No compromise detected" in captured

    def test_shows_remediation_when_compromised(self, capsys):
        results = ScanResults(
            installations=[Installation("/env", "1.82.7")],
        )
        print_summary(results, StubPolicy())

        captured = capsys.readouterr().out
        assert "REMEDIATION" in captured
        assert "litellm==1.82.6" in captured

    def test_shows_warning_when_refs_exist_but_clean(self, capsys):
        results = ScanResults(
            source_refs=[SourceReference("/app.py", 1, "import litellm")],
        )
        print_summary(results, StubPolicy())

        captured = capsys.readouterr().out
        assert "No compromise detected" in captured
        assert "NOTE" in captured

    def test_shows_ioc_count_when_present(self, capsys):
        results = ScanResults(iocs=["/tmp/pglog"])
        print_summary(results, StubPolicy())

        captured = capsys.readouterr().out
        assert "REMEDIATION" in captured

    def test_shows_compromised_config_remediation(self, capsys):
        results = ScanResults(config_refs=[
            ConfigReference("r.txt", 5, "litellm==1.82.8", "1.82.8"),
        ])
        print_summary(results, StubPolicy())

        captured = capsys.readouterr().out
        assert "r.txt" in captured
        assert "REMEDIATION" in captured
