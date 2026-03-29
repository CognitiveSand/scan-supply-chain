"""Tests for Phase 1: discovering litellm installations via filesystem metadata.

Module under test: scan_litellm_compromise.discovery
"""

import os

import pytest

from scan_litellm_compromise.discovery import (
    _deduplicate_by_realpath,
    _is_litellm_metadata_dir,
    _walk_for_litellm_metadata,
    find_litellm_metadata,
)

from tests.conftest import StubPolicy


# ── _is_litellm_metadata_dir (pure) ───────────────────────────────────


class TestIsLitellmMetadataDir:

    @pytest.mark.parametrize("dirname", [
        "litellm-1.82.7.dist-info",
        "litellm-1.82.8.dist-info",
        "litellm-1.0.egg-info",
        "litellm-0.0.1a1.egg-info",
        "litellm-2.0.0.dev0.dist-info",
    ])
    def test_recognizes_litellm_metadata_dirs(self, dirname):
        assert _is_litellm_metadata_dir(dirname) is True

    @pytest.mark.parametrize("dirname", [
        "requests-2.31.0.dist-info",
        "flask-3.0.egg-info",
        "litellm",
        ".dist-info",
        "",
        "__pycache__",
    ])
    def test_rejects_non_litellm_dirs(self, dirname):
        assert _is_litellm_metadata_dir(dirname) is False


# ── _walk_for_litellm_metadata (filesystem) ───────────────────────────


class TestWalkForLitellmMetadata:

    def test_finds_dist_info_in_site_packages(self, tmp_path):
        dist_info = tmp_path / "lib" / "site-packages" / "litellm-1.82.7.dist-info"
        dist_info.mkdir(parents=True)

        result = _walk_for_litellm_metadata(tmp_path)

        assert len(result) == 1
        assert result[0].name == "litellm-1.82.7.dist-info"

    def test_finds_multiple_installs_in_nested_envs(self, tmp_path):
        (tmp_path / "venv1" / "lib" / "litellm-1.82.6.dist-info").mkdir(parents=True)
        (tmp_path / "venv2" / "lib" / "litellm-1.82.7.dist-info").mkdir(parents=True)

        result = _walk_for_litellm_metadata(tmp_path)

        assert len(result) == 2
        names = {p.name for p in result}
        assert names == {"litellm-1.82.6.dist-info", "litellm-1.82.7.dist-info"}

    def test_skips_pycache_directories(self, tmp_path):
        # litellm metadata inside __pycache__ should be skipped
        (tmp_path / "__pycache__" / "litellm-1.82.7.dist-info").mkdir(parents=True)

        result = _walk_for_litellm_metadata(tmp_path)

        assert result == []

    def test_returns_empty_for_directory_without_litellm(self, tmp_path):
        (tmp_path / "lib" / "site-packages" / "requests-2.31.dist-info").mkdir(parents=True)

        result = _walk_for_litellm_metadata(tmp_path)

        assert result == []

    def test_finds_egg_info_directories(self, tmp_path):
        (tmp_path / "litellm-1.80.0.egg-info").mkdir()

        result = _walk_for_litellm_metadata(tmp_path)

        assert len(result) == 1
        assert result[0].name == "litellm-1.80.0.egg-info"

    def test_handles_permission_error_gracefully(self, tmp_path, monkeypatch):
        original_walk = os.walk

        def walk_that_raises(path, **kwargs):
            raise PermissionError("denied")

        monkeypatch.setattr("scan_litellm_compromise.discovery.os.walk", walk_that_raises)

        result = _walk_for_litellm_metadata(tmp_path)

        assert result == []


# ── _deduplicate_by_realpath (filesystem) ──────────────────────────────


class TestDeduplicateByRealpath:

    def test_removes_symlink_duplicates(self, tmp_path):
        real_dir = tmp_path / "real" / "litellm-1.82.7.dist-info"
        real_dir.mkdir(parents=True)
        link_dir = tmp_path / "link"
        link_dir.symlink_to(tmp_path / "real")
        link_target = link_dir / "litellm-1.82.7.dist-info"

        result = _deduplicate_by_realpath([real_dir, link_target])

        assert len(result) == 1

    def test_keeps_distinct_paths(self, tmp_path):
        dir_a = tmp_path / "a" / "litellm-1.82.7.dist-info"
        dir_b = tmp_path / "b" / "litellm-1.82.8.dist-info"
        dir_a.mkdir(parents=True)
        dir_b.mkdir(parents=True)

        result = _deduplicate_by_realpath([dir_a, dir_b])

        assert len(result) == 2


# ── find_litellm_metadata (integration) ───────────────────────────────


class TestFindLitellmMetadata:

    def test_returns_results_from_policy_search_roots(self, tmp_path, monkeypatch):
        site_pkg = tmp_path / "lib" / "site-packages"
        (site_pkg / "litellm-1.82.7.dist-info").mkdir(parents=True)

        policy = StubPolicy()
        policy.search_roots = [str(tmp_path)]

        # Prevent scanning real home directory
        monkeypatch.setattr("scan_litellm_compromise.discovery.Path.home", lambda: tmp_path / "fakehome")
        (tmp_path / "fakehome").mkdir()

        result = find_litellm_metadata(policy)

        assert len(result) == 1
        assert result[0].name == "litellm-1.82.7.dist-info"

    def test_returns_empty_when_no_litellm_installed(self, tmp_path, monkeypatch):
        (tmp_path / "lib" / "site-packages" / "flask-3.0.dist-info").mkdir(parents=True)

        policy = StubPolicy()
        policy.search_roots = [str(tmp_path)]

        monkeypatch.setattr("scan_litellm_compromise.discovery.Path.home", lambda: tmp_path / "fakehome")
        (tmp_path / "fakehome").mkdir()

        result = find_litellm_metadata(policy)

        assert result == []

    def test_deduplicates_results_across_roots(self, tmp_path, monkeypatch):
        dist_info = tmp_path / "lib" / "litellm-1.82.7.dist-info"
        dist_info.mkdir(parents=True)

        policy = StubPolicy()
        # Same root listed twice
        policy.search_roots = [str(tmp_path), str(tmp_path)]

        monkeypatch.setattr("scan_litellm_compromise.discovery.Path.home", lambda: tmp_path / "fakehome")
        (tmp_path / "fakehome").mkdir()

        result = find_litellm_metadata(policy)

        assert len(result) == 1

    def test_uses_scan_path_when_provided(self, tmp_path):
        target = tmp_path / "myproject"
        (target / "venv" / "lib" / "litellm-1.82.7.dist-info").mkdir(parents=True)

        policy = StubPolicy()
        policy.search_roots = ["/should/not/be/used"]

        result = find_litellm_metadata(policy, scan_path=str(target))

        assert len(result) == 1
        assert result[0].name == "litellm-1.82.7.dist-info"

    def test_ignores_policy_roots_when_scan_path_set(self, tmp_path):
        # Policy root has litellm, but scan_path points elsewhere
        policy_dir = tmp_path / "system"
        (policy_dir / "litellm-1.82.7.dist-info").mkdir(parents=True)

        scan_dir = tmp_path / "empty_project"
        scan_dir.mkdir()

        policy = StubPolicy()
        policy.search_roots = [str(policy_dir)]

        result = find_litellm_metadata(policy, scan_path=str(scan_dir))

        assert result == []
