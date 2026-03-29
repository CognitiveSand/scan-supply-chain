"""Tests for Phase 3: IOC artifact detection.

Module under test: scan_litellm_compromise.ioc_scanner
"""

import socket
import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from scan_litellm_compromise.config import C2_KNOWN_IPS
from scan_litellm_compromise.ioc_scanner import (
    _check_known_paths,
    _resolve_c2_ips,
    _scan_for_backdoor_pth,
    _scan_for_c2_connections,
    _scan_for_malicious_pods,
)
from scan_litellm_compromise.models import ScanResults
from tests.conftest import StubPolicy


# ── _check_known_paths ────────────────────────────────────────────────


class TestCheckKnownPaths:

    def test_flags_existing_path_as_ioc(self, tmp_path, capsys):
        ioc_file = tmp_path / "pglog"
        ioc_file.write_text("exfil data")

        results = ScanResults()
        _check_known_paths("test artifacts", [ioc_file], results)

        assert len(results.iocs) == 1
        assert str(ioc_file) in results.iocs[0]

    def test_reports_clean_when_no_paths_exist(self, tmp_path, capsys):
        results = ScanResults()
        _check_known_paths("test artifacts", [tmp_path / "nope"], results)

        assert results.iocs == []
        captured = capsys.readouterr().out
        assert "None found" in captured

    def test_flags_multiple_existing_iocs(self, tmp_path, capsys):
        (tmp_path / "pglog").write_text("a")
        (tmp_path / ".pg_state").write_text("b")

        results = ScanResults()
        _check_known_paths(
            "test", [tmp_path / "pglog", tmp_path / ".pg_state"], results,
        )

        assert len(results.iocs) == 2

    def test_handles_permission_error_on_path_check(self, monkeypatch, capsys):
        def exists_raises(self):
            raise PermissionError("denied")

        monkeypatch.setattr(Path, "exists", exists_raises)

        results = ScanResults()
        _check_known_paths("test", [Path("/fake/path")], results)

        assert results.iocs == []


# ── _scan_for_backdoor_pth ───────────────────────────────────────────


class TestScanForBackdoorPth:

    def test_finds_litellm_init_pth(self, tmp_path, capsys):
        site_pkg = tmp_path / "lib" / "site-packages"
        site_pkg.mkdir(parents=True)
        (site_pkg / "litellm_init.pth").write_text("import os")

        policy = StubPolicy()
        policy.pth_search_roots = [str(tmp_path)]

        results = ScanResults()
        _scan_for_backdoor_pth(results, policy)

        assert len(results.iocs) == 1
        assert "litellm_init.pth" in results.iocs[0]

    def test_reports_clean_when_no_pth_found(self, tmp_path, capsys):
        (tmp_path / "lib" / "site-packages").mkdir(parents=True)

        policy = StubPolicy()
        policy.pth_search_roots = [str(tmp_path)]

        results = ScanResults()
        _scan_for_backdoor_pth(results, policy)

        assert results.iocs == []
        captured = capsys.readouterr().out
        assert "None found" in captured

    def test_skips_nonexistent_search_roots(self, capsys):
        policy = StubPolicy()
        policy.pth_search_roots = ["/nonexistent/path/that/does/not/exist"]

        results = ScanResults()
        _scan_for_backdoor_pth(results, policy)

        assert results.iocs == []


# ── _resolve_c2_ips (pure helper) ────────────────────────────────────


class TestResolveC2Ips:

    def test_returns_known_ips_when_dns_disabled(self):
        result = _resolve_c2_ips(resolve_dns=False)

        for domain, known_ips in C2_KNOWN_IPS.items():
            assert domain in result
            for ip in known_ips:
                assert ip in result[domain]

    def test_does_not_call_dns_when_disabled(self, monkeypatch):
        dns_called = []
        monkeypatch.setattr(
            "scan_litellm_compromise.ioc_scanner.socket.gethostbyname",
            lambda d: dns_called.append(d) or "1.2.3.4",
        )

        _resolve_c2_ips(resolve_dns=False)

        assert dns_called == []

    def test_adds_live_ip_when_dns_enabled(self, monkeypatch):
        monkeypatch.setattr(
            "scan_litellm_compromise.ioc_scanner.socket.gethostbyname",
            lambda d: "99.99.99.99",
        )

        result = _resolve_c2_ips(resolve_dns=True)

        # Should contain both known IPs and the live-resolved IP
        for domain in C2_KNOWN_IPS:
            assert "99.99.99.99" in result[domain]

    def test_deduplicates_live_ip_matching_known(self, monkeypatch):
        known_ip = list(C2_KNOWN_IPS.values())[0][0]
        monkeypatch.setattr(
            "scan_litellm_compromise.ioc_scanner.socket.gethostbyname",
            lambda d: known_ip,
        )

        result = _resolve_c2_ips(resolve_dns=True)

        # Known IP should appear only once, not duplicated
        first_domain = list(C2_KNOWN_IPS.keys())[0]
        assert result[first_domain].count(known_ip) == 1

    def test_handles_dns_failure_gracefully(self, monkeypatch):
        monkeypatch.setattr(
            "scan_litellm_compromise.ioc_scanner.socket.gethostbyname",
            lambda d: (_ for _ in ()).throw(
                socket.gaierror("Name resolution failed"),
            ),
        )

        result = _resolve_c2_ips(resolve_dns=True)

        # Should still have the known IPs even though DNS failed
        for domain, known_ips in C2_KNOWN_IPS.items():
            assert domain in result
            for ip in known_ips:
                assert ip in result[domain]


# ── _scan_for_c2_connections ──────────────────────────────────────────


class TestScanForC2Connections:

    def _stub_ss(self, monkeypatch, stdout):
        """Helper: stub shutil.which and subprocess.run for ss command."""
        monkeypatch.setattr(
            "scan_litellm_compromise.ioc_scanner.shutil.which",
            lambda cmd: "/usr/bin/ss",
        )
        monkeypatch.setattr(
            "scan_litellm_compromise.ioc_scanner.subprocess.run",
            lambda *a, **kw: subprocess.CompletedProcess(
                args=a[0], returncode=0, stdout=stdout,
            ),
        )

    def test_flags_known_ip_without_dns(self, monkeypatch, capsys):
        known_ip = C2_KNOWN_IPS["models.litellm.cloud"][0]
        self._stub_ss(monkeypatch, f"ESTAB  0  0  10.0.0.1:443  {known_ip}:80\n")

        policy = StubPolicy()
        policy.network_check_command = ["ss", "-tnp"]

        results = ScanResults()
        _scan_for_c2_connections(results, policy)  # resolve_c2=False by default

        assert len(results.iocs) >= 1
        assert any("connection:" in ioc and known_ip in ioc for ioc in results.iocs)

    def test_no_dns_queries_by_default(self, monkeypatch, capsys):
        dns_called = []
        self._stub_ss(monkeypatch, "ESTAB  0  0  10.0.0.1:443  1.2.3.4:80\n")
        monkeypatch.setattr(
            "scan_litellm_compromise.ioc_scanner.socket.gethostbyname",
            lambda d: dns_called.append(d) or "1.2.3.4",
        )

        policy = StubPolicy()
        policy.network_check_command = ["ss", "-tnp"]

        results = ScanResults()
        _scan_for_c2_connections(results, policy)

        assert dns_called == []

    def test_dns_called_when_resolve_c2_enabled(self, monkeypatch, capsys):
        dns_called = []
        self._stub_ss(monkeypatch, "ESTAB  0  0  10.0.0.1:443  1.2.3.4:80\n")
        monkeypatch.setattr(
            "scan_litellm_compromise.ioc_scanner.socket.gethostbyname",
            lambda d: dns_called.append(d) or "99.99.99.99",
        )

        policy = StubPolicy()
        policy.network_check_command = ["ss", "-tnp"]

        results = ScanResults()
        _scan_for_c2_connections(results, policy, resolve_c2=True)

        assert len(dns_called) > 0

    def test_prints_warning_when_resolve_c2_enabled(self, monkeypatch, capsys):
        self._stub_ss(monkeypatch, "no connections\n")
        monkeypatch.setattr(
            "scan_litellm_compromise.ioc_scanner.socket.gethostbyname",
            lambda d: "99.99.99.99",
        )

        policy = StubPolicy()
        policy.network_check_command = ["ss", "-tnp"]

        results = ScanResults()
        _scan_for_c2_connections(results, policy, resolve_c2=True)

        captured = capsys.readouterr().out
        assert "--resolve-c2" in captured
        assert "DNS" in captured

    def test_reports_clean_when_no_c2_ips_in_output(self, monkeypatch, capsys):
        self._stub_ss(monkeypatch, "ESTAB  0  0  10.0.0.1:443  1.2.3.4:80\n")

        policy = StubPolicy()
        policy.network_check_command = ["ss", "-tnp"]

        results = ScanResults()
        _scan_for_c2_connections(results, policy)

        assert results.iocs == []
        captured = capsys.readouterr().out
        assert "No suspicious connections" in captured

    def test_skips_when_network_tool_unavailable(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "scan_litellm_compromise.ioc_scanner.shutil.which",
            lambda cmd: None,
        )

        policy = StubPolicy()
        policy.network_check_command = ["ss", "-tnp"]

        results = ScanResults()
        _scan_for_c2_connections(results, policy)

        assert results.iocs == []

    def test_skips_when_no_network_command_configured(self, capsys):
        policy = StubPolicy()
        policy.network_check_command = None

        results = ScanResults()
        _scan_for_c2_connections(results, policy)

        assert results.iocs == []

    def test_handles_subprocess_timeout(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "scan_litellm_compromise.ioc_scanner.shutil.which",
            lambda cmd: "/usr/bin/ss",
        )
        monkeypatch.setattr(
            "scan_litellm_compromise.ioc_scanner.subprocess.run",
            lambda *a, **kw: (_ for _ in ()).throw(
                subprocess.TimeoutExpired(cmd="ss", timeout=5),
            ),
        )

        policy = StubPolicy()
        policy.network_check_command = ["ss", "-tnp"]

        results = ScanResults()
        _scan_for_c2_connections(results, policy)

        assert results.iocs == []

    def test_dns_failure_still_uses_known_ips(self, monkeypatch, capsys):
        known_ip = C2_KNOWN_IPS["checkmarx.zone"][0]
        self._stub_ss(monkeypatch, f"ESTAB  0  0  10.0.0.1:443  {known_ip}:80\n")
        monkeypatch.setattr(
            "scan_litellm_compromise.ioc_scanner.socket.gethostbyname",
            lambda d: (_ for _ in ()).throw(
                socket.gaierror("Name resolution failed"),
            ),
        )

        policy = StubPolicy()
        policy.network_check_command = ["ss", "-tnp"]

        results = ScanResults()
        _scan_for_c2_connections(results, policy, resolve_c2=True)

        # Known IPs still work even though DNS failed
        assert len(results.iocs) >= 1
        assert any(known_ip in ioc for ioc in results.iocs)


# ── _scan_for_malicious_pods ─────────────────────────────────────────


class TestScanForMaliciousPods:

    def test_flags_node_setup_pods(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "scan_litellm_compromise.ioc_scanner.shutil.which",
            lambda cmd: "/usr/bin/kubectl" if cmd == "kubectl" else None,
        )
        monkeypatch.setattr(
            "scan_litellm_compromise.ioc_scanner.subprocess.run",
            lambda *a, **kw: subprocess.CompletedProcess(
                args=a[0], returncode=0,
                stdout="node-setup-abc123  1/1  Running  0  2h\nkube-proxy-xyz  1/1  Running  0  5d\n",
            ),
        )

        results = ScanResults()
        _scan_for_malicious_pods(results)

        assert len(results.iocs) == 1
        assert "k8s-pods:1" in results.iocs[0]

    def test_reports_clean_when_no_suspicious_pods(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "scan_litellm_compromise.ioc_scanner.shutil.which",
            lambda cmd: "/usr/bin/kubectl" if cmd == "kubectl" else None,
        )
        monkeypatch.setattr(
            "scan_litellm_compromise.ioc_scanner.subprocess.run",
            lambda *a, **kw: subprocess.CompletedProcess(
                args=a[0], returncode=0,
                stdout="kube-proxy-xyz  1/1  Running  0  5d\n",
            ),
        )

        results = ScanResults()
        _scan_for_malicious_pods(results)

        assert results.iocs == []
        captured = capsys.readouterr().out
        assert "No suspicious pods" in captured

    def test_skips_when_kubectl_not_installed(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "scan_litellm_compromise.ioc_scanner.shutil.which",
            lambda cmd: None,
        )

        results = ScanResults()
        _scan_for_malicious_pods(results)

        assert results.iocs == []

    def test_handles_kubectl_timeout(self, monkeypatch, capsys):
        monkeypatch.setattr(
            "scan_litellm_compromise.ioc_scanner.shutil.which",
            lambda cmd: "/usr/bin/kubectl" if cmd == "kubectl" else None,
        )
        monkeypatch.setattr(
            "scan_litellm_compromise.ioc_scanner.subprocess.run",
            lambda *a, **kw: (_ for _ in ()).throw(
                subprocess.TimeoutExpired(cmd="kubectl", timeout=10),
            ),
        )

        results = ScanResults()
        _scan_for_malicious_pods(results)

        assert results.iocs == []
