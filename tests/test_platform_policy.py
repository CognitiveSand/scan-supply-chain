"""Tests for platform detection and policy implementations.

Modules under test: scan_litellm_compromise.platform_policy,
    scan_litellm_compromise.platform_linux,
    scan_litellm_compromise.platform_darwin,
    scan_litellm_compromise.platform_windows
"""

import sys

import pytest

from scan_litellm_compromise.platform_darwin import DarwinPolicy
from scan_litellm_compromise.platform_linux import LinuxPolicy
from scan_litellm_compromise.platform_policy import detect_platform


# ── detect_platform ──────────────────────────────────────────────────


class TestDetectPlatform:

    def test_returns_linux_policy_on_linux(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        policy = detect_platform()
        assert policy.name == "Linux"

    def test_returns_windows_policy_on_win32(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")
        policy = detect_platform()
        assert policy.name == "Windows"

    def test_returns_darwin_policy_on_darwin(self, monkeypatch):
        monkeypatch.setattr(sys, "platform", "darwin")
        policy = detect_platform()
        assert policy.name == "macOS"


# ── LinuxPolicy ──────────────────────────────────────────────────────


class TestLinuxPolicy:

    @pytest.fixture
    def policy(self):
        return LinuxPolicy()

    def test_name_is_linux(self, policy):
        assert policy.name == "Linux"

    def test_search_roots_excludes_root_home(self, policy):
        assert "/root" not in policy.search_roots

    def test_search_roots_includes_common_paths(self, policy):
        roots = policy.search_roots
        assert "/home" in roots
        assert "/opt" in roots
        assert "/usr/local" in roots

    def test_persistence_paths_include_systemd(self, policy):
        paths = policy.persistence_paths
        assert any("systemd" in p for p in paths)
        assert any("sysmon" in p for p in paths)

    def test_network_check_command_is_ss(self, policy):
        assert policy.network_check_command == ["ss", "-tnp"]

    def test_tmp_iocs_include_known_artifacts(self, policy):
        iocs = policy.tmp_iocs
        assert "/tmp/pglog" in iocs
        assert "/tmp/.pg_state" in iocs
        assert "/tmp/tpcp.tar.gz" in iocs

    def test_pth_search_roots_exclude_root(self, policy):
        assert "/root" not in policy.pth_search_roots

    def test_extra_ioc_checks_is_noop(self, policy):
        # Should not raise or modify anything
        policy.extra_ioc_checks(object())

    def test_remediation_steps_mention_systemctl(self, policy):
        steps = policy.remediation_persistence_steps()
        assert any("systemctl" in s for s in steps)

    def test_remediation_artifacts_mention_pth(self, policy):
        lines = policy.remediation_artifact_lines()
        assert any("litellm_init.pth" in line for line in lines)

    def test_home_conda_dirs_returns_known_names(self, policy):
        dirs = policy.home_conda_dirs()
        assert "miniconda3" in dirs
        assert "anaconda3" in dirs


# ── DarwinPolicy ────────────────────────────────────────────────────


class TestDarwinPolicy:

    @pytest.fixture
    def policy(self):
        return DarwinPolicy()

    def test_name_is_macos(self, policy):
        assert policy.name == "macOS"

    def test_search_roots_uses_users_not_home(self, policy):
        roots = policy.search_roots
        assert "/Users" in roots
        assert "/home" not in roots

    def test_search_roots_includes_homebrew(self, policy):
        assert "/opt/homebrew" in policy.search_roots

    def test_persistence_paths_include_sysmon(self, policy):
        paths = policy.persistence_paths
        assert any("sysmon" in p for p in paths)

    def test_persistence_description_notes_inert(self, policy):
        assert "inert" in policy.persistence_description

    def test_network_check_command_is_lsof(self, policy):
        assert policy.network_check_command == ["lsof", "-i", "-P", "-n"]

    def test_tmp_iocs_same_as_linux(self, policy):
        iocs = policy.tmp_iocs
        assert "/tmp/pglog" in iocs
        assert "/tmp/.pg_state" in iocs
        assert "/tmp/tpcp.tar.gz" in iocs

    def test_pth_search_roots_use_users(self, policy):
        roots = policy.pth_search_roots
        assert "/Users" in roots
        assert "/home" not in roots

    def test_extra_ioc_checks_is_noop(self, policy):
        policy.extra_ioc_checks(object())

    def test_remediation_steps_mention_launchctl(self, policy):
        steps = policy.remediation_persistence_steps()
        assert any("launchctl" in s for s in steps)

    def test_remediation_artifacts_mention_pth(self, policy):
        lines = policy.remediation_artifact_lines()
        assert any("litellm_init.pth" in line for line in lines)

    def test_home_conda_dirs_returns_known_names(self, policy):
        dirs = policy.home_conda_dirs()
        assert "miniconda3" in dirs
        assert "anaconda3" in dirs


# ── WindowsPolicy (env-var dependent) ────────────────────────────────


class TestWindowsPolicy:

    @pytest.fixture
    def policy(self, monkeypatch):
        # Provide required env vars so WindowsPolicy works on Linux
        monkeypatch.setenv("USERPROFILE", "/tmp/fakehome")
        monkeypatch.setenv("APPDATA", "/tmp/fakehome/AppData/Roaming")
        monkeypatch.setenv("LOCALAPPDATA", "/tmp/fakehome/AppData/Local")
        monkeypatch.setenv("TEMP", "/tmp/faketemp")
        monkeypatch.setenv("ProgramFiles", "/tmp/Program Files")

        from scan_litellm_compromise.platform_windows import WindowsPolicy
        return WindowsPolicy()

    def test_name_is_windows(self, policy):
        assert policy.name == "Windows"

    def test_persistence_paths_use_appdata(self, policy):
        paths = policy.persistence_paths
        assert any("AppData" in p or "sysmon" in p for p in paths)

    def test_tmp_iocs_use_temp_env_var(self, policy):
        iocs = policy.tmp_iocs
        assert any("faketemp" in i for i in iocs)
        assert any("pglog" in i for i in iocs)

    def test_tmp_iocs_empty_when_no_temp_var(self, monkeypatch):
        monkeypatch.delenv("TEMP", raising=False)
        monkeypatch.delenv("TMP", raising=False)

        from scan_litellm_compromise.platform_windows import WindowsPolicy
        policy = WindowsPolicy()
        assert policy.tmp_iocs == []

    def test_persistence_description_mentions_startup(self, policy):
        assert "Startup" in policy.persistence_description

    def test_home_conda_dirs_returns_windows_names(self, policy):
        dirs = policy.home_conda_dirs()
        assert "Miniconda3" in dirs
        assert "Anaconda3" in dirs

    def test_remediation_steps_mention_schtasks(self, policy):
        steps = policy.remediation_persistence_steps()
        assert any("schtasks" in s for s in steps)

    def test_remediation_artifacts_mention_pth(self, policy):
        lines = policy.remediation_artifact_lines()
        assert any("litellm_init.pth" in line for line in lines)
