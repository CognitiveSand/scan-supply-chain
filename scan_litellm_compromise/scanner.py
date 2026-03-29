"""Main orchestrator for the LiteLLM supply chain scanner."""

import argparse
import logging
import sys

from .discovery import find_litellm_metadata
from .formatting import BOLD, RESET, print_banner, print_phase_header, print_separator
from .ioc_scanner import scan_iocs
from .models import ScanResults
from .platform_policy import detect_platform
from .report import print_config_refs, print_source_refs, print_summary
from .source_scanner import scan_source_and_configs
from .version_checker import scan_environments


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Scan for compromised LiteLLM installations (v1.82.7, v1.82.8)",
    )
    parser.add_argument(
        "--scan-path",
        metavar="DIR",
        help="Restrict scanning to this directory instead of system-wide search",
    )
    parser.add_argument(
        "--resolve-c2",
        action="store_true",
        help="Enable live DNS queries to C2 domains (default: use known IPs only)",
    )
    return parser.parse_args()


def main():
    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s: %(message)s",
    )

    args = _parse_args()

    policy = detect_platform()

    print_banner()
    print(f"  {BOLD}Platform:{RESET} {policy.name}")
    if args.scan_path:
        print(f"  {BOLD}Scan path:{RESET} {args.scan_path}")
    print(f"  {BOLD}NOTE:{RESET} {policy.exclusion_note}\n")
    results = ScanResults()

    # Phase 1: Discover litellm installations
    print_phase_header(1, "Discovering litellm installations...")
    metadata_dirs = find_litellm_metadata(policy, scan_path=args.scan_path)
    print(f"  Found {BOLD}{len(metadata_dirs)}{RESET} litellm metadata directories")

    # Phase 2: Check litellm versions
    print_separator()
    print_phase_header(2, "Checking litellm versions from metadata...")
    scan_environments(metadata_dirs, results)

    # Phase 3: IOC artifact scan
    print_phase_header(3, "Scanning for IOC artifacts...")
    scan_iocs(results, policy, resolve_c2=args.resolve_c2)

    # Phase 4: Source & config scan
    print_phase_header(4, "Scanning source files for litellm usage...")
    files_scanned = scan_source_and_configs(
        results, policy, scan_path=args.scan_path,
    )
    print(f"  Files scanned: {BOLD}{files_scanned}{RESET}\n")
    print_source_refs(results.source_refs)
    print_config_refs(results.config_refs)

    # Phase 5: Summary
    print()
    print_summary(results, policy)

    sys.exit(0 if results.is_clean else 1)
