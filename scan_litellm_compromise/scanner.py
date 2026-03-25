"""Main orchestrator for the LiteLLM supply chain scanner."""

import logging
import sys

from .discovery import find_python_envs
from .formatting import BOLD, RESET, print_banner, print_phase_header, print_separator
from .ioc_scanner import scan_iocs
from .models import ScanResults
from .report import print_config_refs, print_source_refs, print_summary
from .source_scanner import scan_source_and_configs
from .version_checker import scan_environments


def main():
    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s: %(message)s",
    )

    print_banner()
    print(f"  {BOLD}NOTE:{RESET} /root is excluded — this scanner only inspects "
          f"user-accessible paths.\n")
    results = ScanResults()

    # Phase 1: Discover Python environments
    print_phase_header(1, "Discovering Python environments...")
    envs = find_python_envs()
    print(f"  Found {BOLD}{len(envs)}{RESET} unique Python interpreters")

    # Phase 2: Check litellm versions
    print_separator()
    print_phase_header(2, "Checking litellm versions in all environments...")
    scan_environments(envs, results)

    # Phase 3: IOC artifact scan
    print_phase_header(3, "Scanning for IOC artifacts...")
    scan_iocs(results)

    # Phase 4: Source & config scan
    print_phase_header(4, "Scanning source files for litellm usage...")
    files_scanned = scan_source_and_configs(results)
    print(f"  Files scanned: {BOLD}{files_scanned}{RESET}\n")
    print_source_refs(results.source_refs)
    print_config_refs(results.config_refs)

    # Phase 5: Summary
    print()
    print_summary(results)

    sys.exit(0 if results.is_clean else 1)
