"""Tests for TOML threat-profile parsing.

Module under test: scan_supply_chain.threat_profile
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

from scan_supply_chain.threat_profile import (
    GitArtifactsIOC,
    InvalidThreatProfileError,
    _load_from_dir,
    load_threat_file,
)


_MINIMAL_HEADER = """
[threat]
id          = "test-2026-05"
name        = "Test"
date        = "2026-05-14"
ecosystem   = "npm"
package     = "test-package"
compromised = ["1.0.0"]
safe        = "0.9.9"
advisory    = "https://example.com"
"""


def _write_toml(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "threat.toml"
    path.write_text(_MINIMAL_HEADER + body)
    return path


class TestParseGitArtifacts:
    def test_missing_block_yields_empty_iocs(self, tmp_path):
        profile = load_threat_file(_write_toml(tmp_path, ""))
        assert isinstance(profile.git_artifacts, GitArtifactsIOC)
        assert profile.git_artifacts.is_empty

    def test_full_block_parses_all_fields(self, tmp_path):
        body = """
[ioc.git_artifacts]
workflow_filenames    = ["discussion.yaml", "shai-hulud-workflow.yml"]
workflow_name_regexes = ['^formatter_\\d+\\.ya?ml$']
branch_names          = ["fremen", "atreides"]
branch_name_regexes   = ['^add-linter-workflow-\\d+$']
commit_author_emails  = ["claude@users.noreply.github.com"]
repo_descriptions     = ["Shai-Hulud"]
"""
        profile = load_threat_file(_write_toml(tmp_path, body))
        ga = profile.git_artifacts
        assert ga.workflow_filenames == (
            "discussion.yaml",
            "shai-hulud-workflow.yml",
        )
        # Regex fields are compiled to re.Pattern objects at load time.
        assert len(ga.workflow_name_regexes) == 1
        assert ga.workflow_name_regexes[0].search("formatter_42.yml")
        assert set(ga.branch_names) == {"fremen", "atreides"}
        assert len(ga.branch_name_regexes) == 1
        assert ga.branch_name_regexes[0].search(
            "add-linter-workflow-1732456789012"
        )
        assert ga.commit_author_emails == (
            "claude@users.noreply.github.com",
        )
        assert ga.repo_descriptions == ("Shai-Hulud",)

    def test_invalid_workflow_regex_raises_at_load_time(self, tmp_path):
        body = """
[ioc.git_artifacts]
workflow_name_regexes = ["[unclosed"]
"""
        with pytest.raises(re.error) as exc:
            load_threat_file(_write_toml(tmp_path, body))
        assert "workflow_name_regexes" in str(exc.value)
        assert "[unclosed" in str(exc.value)

    def test_invalid_branch_regex_raises_at_load_time(self, tmp_path):
        body = """
[ioc.git_artifacts]
branch_name_regexes = ["(["]
"""
        with pytest.raises(re.error) as exc:
            load_threat_file(_write_toml(tmp_path, body))
        assert "branch_name_regexes" in str(exc.value)


# ── _load_from_dir error propagation ────────────────────────────────────


class TestLoadFromDir:
    def test_invalid_regex_in_dir_raises_with_path(self, tmp_path):
        bad = tmp_path / "broken.toml"
        bad.write_text(_MINIMAL_HEADER + """
[ioc.git_artifacts]
workflow_name_regexes = ["[unclosed"]
""")
        with pytest.raises(InvalidThreatProfileError) as exc:
            _load_from_dir(tmp_path)
        assert exc.value.path == bad
        assert "broken.toml" in str(exc.value)

    def test_malformed_toml_raises_with_path(self, tmp_path):
        bad = tmp_path / "broken.toml"
        bad.write_text("this is not = valid toml [\n")
        with pytest.raises(InvalidThreatProfileError) as exc:
            _load_from_dir(tmp_path)
        assert exc.value.path == bad
        assert isinstance(exc.value.__cause__, tomllib.TOMLDecodeError)

    def test_missing_required_field_raises_with_path(self, tmp_path):
        bad = tmp_path / "broken.toml"
        # Missing [threat] section entirely
        bad.write_text('[threat]\nid = "x"\nname = "x"\n')
        with pytest.raises(InvalidThreatProfileError) as exc:
            _load_from_dir(tmp_path)
        assert exc.value.path == bad
        assert isinstance(exc.value.__cause__, KeyError)

    def test_missing_directory_returns_empty(self, tmp_path):
        # An absent user-config dir is not an error.
        result = _load_from_dir(tmp_path / "nonexistent")
        assert result == {}


class TestParsePersistenceKeywords:
    def test_missing_block_yields_empty_tuple(self, tmp_path):
        profile = load_threat_file(_write_toml(tmp_path, ""))
        assert profile.persistence_keywords == ()

    def test_terms_are_parsed(self, tmp_path):
        body = """
[ioc.persistence_keywords]
terms = ["gh-token-monitor", "shai-hulud"]
"""
        profile = load_threat_file(_write_toml(tmp_path, body))
        assert profile.persistence_keywords == (
            "gh-token-monitor",
            "shai-hulud",
        )
