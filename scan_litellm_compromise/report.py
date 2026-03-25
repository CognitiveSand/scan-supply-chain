"""Phase 5: Summary report and remediation guidance."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .formatting import BOLD, GREEN, RED, RESET, YELLOW, print_separator
from .models import ConfigReference, ScanResults, SourceReference

if TYPE_CHECKING:
    from .platform_policy import PlatformPolicy

_MAX_LINES_PER_FILE = 5


# ── Reference display ───────────────────────────────────────────────────


def _group_by_file(refs, key=None):
    """Group references by file path, preserving order."""
    if key is None:
        key = lambda r: r.file_path
    grouped: dict[str, list] = {}
    for ref in refs:
        grouped.setdefault(key(ref), []).append(ref)
    return grouped


def _format_version_tag(ref: ConfigReference) -> str:
    """Format a version annotation for a config reference."""
    if ref.pinned_version and ref.is_compromised:
        return f"  {RED}{BOLD}! PINNED TO COMPROMISED VERSION{RESET}"
    if ref.pinned_version:
        return f"  {GREEN}(v{ref.pinned_version}){RESET}"
    return ""


def print_source_refs(refs: list[SourceReference]) -> None:
    """Print grouped source file references."""
    if not refs:
        print(f"  {GREEN}+ No litellm imports found in Python source files{RESET}\n")
        return

    by_file = _group_by_file(refs)
    print(
        f"  {BOLD}Python source files referencing litellm "
        f"({len(by_file)} files):{RESET}\n"
    )

    for file_path, file_refs in sorted(by_file.items()):
        print(f"    {YELLOW}{file_path}{RESET}")
        for ref in file_refs[:_MAX_LINES_PER_FILE]:
            print(f"      L{ref.line_number}: {ref.line_content}")
        remaining = len(file_refs) - _MAX_LINES_PER_FILE
        if remaining > 0:
            print(f"      ... and {remaining} more references")
        print()


def print_config_refs(refs: list[ConfigReference]) -> None:
    """Print grouped config file references with version annotations."""
    if not refs:
        print(
            f"  {GREEN}+ No litellm dependencies found in "
            f"config/requirements files{RESET}\n"
        )
        return

    by_file = _group_by_file(refs)
    print(
        f"  {BOLD}Config/dependency files referencing litellm "
        f"({len(by_file)} files):{RESET}\n"
    )

    for file_path, file_refs in sorted(by_file.items()):
        print(f"    {YELLOW}{file_path}{RESET}")
        for ref in file_refs:
            version_tag = _format_version_tag(ref)
            print(f"      L{ref.line_number}: {ref.line_content}{version_tag}")
        print()


# ── Stats ────────────────────────────────────────────────────────────────


def _print_stats(results: ScanResults) -> None:
    """Print scan statistics."""
    print(f"  Environments scanned:         {BOLD}{results.envs_scanned}{RESET}")
    print(
        f"  litellm installations found:  "
        f"{BOLD}{len(results.installations)}{RESET}"
    )

    compromised = results.compromised_installations
    if compromised:
        print(
            f"  {RED}{BOLD}Compromised versions found:     "
            f"{len(compromised)}{RESET}"
        )
    else:
        print(f"  Compromised versions found:    {GREEN}0{RESET}")

    if results.iocs:
        print(
            f"  {RED}{BOLD}IOC artifacts found:            "
            f"{len(results.iocs)}{RESET}"
        )
    else:
        print(f"  IOC artifacts found:           {GREEN}0{RESET}")

    print(
        f"  Python files using litellm:    "
        f"{BOLD}{len(results.source_files)}{RESET} files"
    )
    print(
        f"  Config files with litellm:     "
        f"{BOLD}{len(results.config_files)}{RESET} files"
    )

    compromised_configs = results.compromised_configs
    if compromised_configs:
        print(
            f"  {RED}{BOLD}Configs pinned to bad version:   "
            f"{len(compromised_configs)}{RESET}"
        )


# ── Verdicts ─────────────────────────────────────────────────────────────


def _print_remediation(results: ScanResults, policy: PlatformPolicy) -> None:
    """Print remediation steps for a compromised system."""
    print()
    print_separator()
    print(f"\n{RED}{BOLD}!  COMPROMISE DETECTED -- REMEDIATION STEPS:{RESET}\n")

    print(f"  1. {BOLD}Assume ALL secrets on this machine are compromised{RESET}")
    print(f"     -> Rotate SSH keys, cloud credentials (AWS/GCP/Azure), API keys")
    print(f"     -> Revoke and regenerate .env files and .gitconfig tokens")
    print()
    print(f"  2. {BOLD}Remove malicious artifacts:{RESET}")
    for line in policy.remediation_artifact_lines():
        print(f"     {line}")
    print()
    print(f"  3. {BOLD}Fix litellm:{RESET}")
    print(f"     -> pip install litellm==1.82.6  (last known safe version)")
    print(f"     -> Or upgrade past compromised range once verified")
    print()

    compromised_configs = results.compromised_configs
    if compromised_configs:
        print(f"  4. {BOLD}Update pinned versions in config files:{RESET}")
        for ref in compromised_configs:
            print(f"     -> {ref.file_path}:{ref.line_number}")
            print(f"       Change: {ref.line_content}")
        print()

    print(f"  5. {BOLD}If running Kubernetes:{RESET}")
    print(f"     -> Delete any node-setup-* pods in kube-system namespace")
    print(f"     -> Audit cluster for privileged pods with host mounts")
    print()
    print(f"  6. {BOLD}{policy.remediation_persistence_steps()[0]}{RESET}")
    for step in policy.remediation_persistence_steps()[1:]:
        print(f"     {step}")
    print()
    print(f"  Reference: https://github.com/BerriAI/litellm/issues/24512")
    print_separator()


def _print_clean_verdict(results: ScanResults) -> None:
    """Print the all-clear verdict with optional warnings."""
    print()
    print(f"  {GREEN}{BOLD}+ No compromise detected. System appears clean.{RESET}")

    if results.source_refs or results.config_refs:
        print()
        print(
            f"  {YELLOW}{BOLD}NOTE:{RESET} litellm references were found in source "
            f"or config files."
        )
        print(
            f"  Verify they use a safe version "
            f"(not 1.82.7, not 1.82.8) and update if needed."
        )

    print_separator()


# ── Public entry point ───────────────────────────────────────────────────


def print_summary(results: ScanResults, policy: PlatformPolicy) -> None:
    """Print the final scan summary and verdict."""
    print_separator()
    print(f"\n{BOLD}SCAN RESULTS{RESET}\n")
    _print_stats(results)

    if results.is_clean:
        _print_clean_verdict(results)
    else:
        _print_remediation(results, policy)
