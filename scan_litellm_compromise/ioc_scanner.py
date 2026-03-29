"""Phase 3: Scan for Indicators of Compromise (IOC) artifacts."""

from __future__ import annotations

import logging
import os
import shutil
import socket
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

from .config import C2_DOMAINS, C2_KNOWN_IPS
from .formatting import (
    BOLD,
    RED,
    RESET,
    YELLOW,
    print_check_header,
    print_clean,
    print_ioc_found,
)
from .models import ScanResults

if TYPE_CHECKING:
    from .platform_policy import PlatformPolicy

logger = logging.getLogger(__name__)


# ── DRY helper for path-based IOC checks ────────────────────────────────


def _check_known_paths(
    description: str, paths: Iterable[Path], results: ScanResults
) -> None:
    """Check a list of known paths for IOC artifacts."""
    print_check_header(description)
    found = False
    for path in paths:
        try:
            if path.exists():
                print_ioc_found(str(path))
                results.iocs.append(str(path))
                found = True
        except PermissionError:
            logger.debug("Permission denied checking %s", path)
    if not found:
        print_clean()


# ── Individual IOC scanners ──────────────────────────────────────────────


def _scan_for_backdoor_pth(results: ScanResults, policy: PlatformPolicy) -> None:
    """Walk filesystem looking for litellm_init.pth auto-exec backdoor."""
    print_check_header("litellm_init.pth (auto-exec backdoor)")
    found = False
    for root in policy.pth_search_roots:
        root_path = Path(root)
        if not root_path.is_dir():
            continue
        try:
            for dirpath, _, filenames in os.walk(root_path):
                if "litellm_init.pth" in filenames:
                    pth_path = Path(dirpath) / "litellm_init.pth"
                    print_ioc_found(str(pth_path))
                    results.iocs.append(str(pth_path))
                    found = True
        except PermissionError:
            logger.debug("Permission denied walking %s", root)
    if not found:
        print_clean()


def _scan_for_persistence(results: ScanResults, policy: PlatformPolicy) -> None:
    """Check for sysmon backdoor persistence."""
    expanded = [Path(os.path.expanduser(sp)) for sp in policy.persistence_paths]
    _check_known_paths(policy.persistence_description, expanded, results)


def _scan_for_exfiltration_artifacts(
    results: ScanResults, policy: PlatformPolicy
) -> None:
    """Check temp directory for known exfiltration artifacts."""
    tmp_paths = [Path(artifact) for artifact in policy.tmp_iocs]
    _check_known_paths(policy.tmp_description, tmp_paths, results)


def _resolve_c2_ips(resolve_dns: bool) -> dict[str, list[str]]:
    """Build domain -> IPs mapping. Uses known IPs; optionally adds live DNS."""
    result: dict[str, list[str]] = {d: list(ips) for d, ips in C2_KNOWN_IPS.items()}
    if resolve_dns:
        for domain in C2_DOMAINS:
            try:
                live_ip = socket.gethostbyname(domain)
                ips = result.setdefault(domain, [])
                if live_ip not in ips:
                    ips.append(live_ip)
            except socket.gaierror:
                logger.debug("Cannot resolve C2 domain %s", domain)
    return result


def _scan_for_c2_connections(
    results: ScanResults, policy: PlatformPolicy, resolve_c2: bool = False
) -> None:
    """Check active network connections for C2 domain communication."""
    print_check_header("active network connections for C2 domains")
    if resolve_c2:
        print(
            f"  {YELLOW}{BOLD}NOTE:{RESET} --resolve-c2 enabled "
            f"-- making live DNS queries to C2 domains"
        )
    command = policy.network_check_command
    if command is None or not shutil.which(command[0]):
        print_clean(f"{command[0] if command else 'network tool'} not available, skipping")
        return

    found = False
    domain_ips = _resolve_c2_ips(resolve_c2)
    try:
        socket_output = subprocess.run(
            command, capture_output=True, timeout=5
        ).stdout.decode(errors="replace")

        for domain, ips in domain_ips.items():
            for ip in ips:
                if ip in socket_output:
                    print(
                        f"  {RED}{BOLD}! ACTIVE CONNECTION "
                        f"to {domain} ({ip}){RESET}"
                    )
                    results.iocs.append(f"connection:{domain}:{ip}")
                    found = True
                    break  # one match per domain is enough
    except (subprocess.TimeoutExpired, OSError):
        logger.debug("Failed to run network check command")

    if not found:
        print_clean("No suspicious connections")


def _scan_for_malicious_pods(results: ScanResults) -> None:
    """Check Kubernetes for suspicious node-setup-* pods."""
    if not shutil.which("kubectl"):
        return

    print_check_header("Kubernetes malicious pods")
    try:
        kubectl_output = subprocess.run(
            ["kubectl", "get", "pods", "-n", "kube-system", "--no-headers"],
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout

        suspicious_pods = [
            line
            for line in kubectl_output.splitlines()
            if line.strip().startswith("node-setup-")
        ]

        if suspicious_pods:
            print(f"  {RED}{BOLD}! SUSPICIOUS PODS in kube-system:{RESET}")
            for pod in suspicious_pods:
                print(f"    {RED}{pod}{RESET}")
            results.iocs.append(f"k8s-pods:{len(suspicious_pods)}")
        else:
            print_clean("No suspicious pods")
    except (subprocess.TimeoutExpired, OSError):
        logger.debug("Failed to query Kubernetes pods")


# ── Public entry point ───────────────────────────────────────────────────


def scan_iocs(
    results: ScanResults, policy: PlatformPolicy, resolve_c2: bool = False
) -> None:
    """Run all IOC artifact scans."""
    _scan_for_backdoor_pth(results, policy)
    print()
    _scan_for_persistence(results, policy)
    print()
    _scan_for_exfiltration_artifacts(results, policy)
    print()
    _scan_for_c2_connections(results, policy, resolve_c2=resolve_c2)
    _scan_for_malicious_pods(results)
    policy.extra_ioc_checks(results)
