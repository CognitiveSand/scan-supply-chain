"""Phase 3: Scan for Indicators of Compromise (IOC) artifacts."""

import logging
import os
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Iterable

from .config import C2_DOMAINS, SYSMON_PATHS, TMP_IOCS
from .formatting import (
    BOLD,
    RED,
    RESET,
    print_check_header,
    print_clean,
    print_ioc_found,
)
from .models import ScanResults

logger = logging.getLogger(__name__)

# NOTE: /root is intentionally excluded — this scanner does not access root-owned paths.
_PTH_SEARCH_ROOTS = ["/home", "/opt", "/usr", "/var", "/srv"]


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


def _scan_for_backdoor_pth(results: ScanResults) -> None:
    """Walk filesystem looking for litellm_init.pth auto-exec backdoor."""
    print_check_header("litellm_init.pth (auto-exec backdoor)")
    found = False
    for root in _PTH_SEARCH_ROOTS:
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


def _scan_for_sysmon_persistence(results: ScanResults) -> None:
    """Check for sysmon systemd backdoor persistence."""
    expanded = [Path(os.path.expanduser(sp)) for sp in SYSMON_PATHS]
    _check_known_paths("sysmon persistence (systemd backdoor)", expanded, results)


def _scan_for_exfiltration_artifacts(results: ScanResults) -> None:
    """Check /tmp for known exfiltration artifacts."""
    tmp_paths = [Path(artifact) for artifact in TMP_IOCS]
    _check_known_paths("exfiltration artifacts (/tmp)", tmp_paths, results)


def _scan_for_c2_connections(results: ScanResults) -> None:
    """Check active network connections for C2 domain communication."""
    print_check_header("active network connections for C2 domains")
    if not shutil.which("ss"):
        print_clean("ss not available, skipping")
        return

    found = False
    try:
        socket_output = subprocess.run(
            ["ss", "-tnp"], capture_output=True, text=True, timeout=5
        ).stdout

        for domain in C2_DOMAINS:
            try:
                resolved_ip = socket.gethostbyname(domain)
                if resolved_ip in socket_output:
                    print(
                        f"  {RED}{BOLD}! ACTIVE CONNECTION "
                        f"to {domain} ({resolved_ip}){RESET}"
                    )
                    results.iocs.append(f"connection:{domain}:{resolved_ip}")
                    found = True
            except socket.gaierror:
                logger.debug("Cannot resolve C2 domain %s", domain)
    except (subprocess.TimeoutExpired, OSError):
        logger.debug("Failed to run ss command")

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


def scan_iocs(results: ScanResults) -> None:
    """Run all IOC artifact scans."""
    _scan_for_backdoor_pth(results)
    print()
    _scan_for_sysmon_persistence(results)
    print()
    _scan_for_exfiltration_artifacts(results)
    print()
    _scan_for_c2_connections(results)
    _scan_for_malicious_pods(results)
