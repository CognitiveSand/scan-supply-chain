"""Phase 2: Check litellm versions in discovered Python environments."""

import logging
import subprocess
from pathlib import Path

from .formatting import BOLD, GREEN, RED, RESET
from .models import Installation, ScanResults

logger = logging.getLogger(__name__)

_VERSION_CHECK_SCRIPT = (
    "try:\n"
    "    import importlib.metadata as md\n"
    "    print(md.version('litellm'))\n"
    "except Exception:\n"
    "    print('NOT_INSTALLED')"
)


def _is_working_interpreter(python_path: Path) -> bool:
    """Verify that a Python interpreter can execute."""
    try:
        subprocess.run(
            [str(python_path), "--version"],
            capture_output=True,
            timeout=5,
        )
        return True
    except (subprocess.TimeoutExpired, OSError):
        logger.debug("Interpreter not responding: %s", python_path)
        return False


def _get_litellm_version(python_path: Path) -> str | None:
    """Return litellm version string or None if not installed."""
    try:
        result = subprocess.run(
            [str(python_path), "-c", _VERSION_CHECK_SCRIPT],
            capture_output=True,
            text=True,
            timeout=10,
        )
        version = result.stdout.strip()
        if version and version != "NOT_INSTALLED":
            return version
    except (subprocess.TimeoutExpired, OSError):
        logger.debug("Failed to query litellm version from %s", python_path)
    return None


def _report_installation(installation: Installation) -> None:
    """Print a single installation's status."""
    if installation.is_compromised:
        print(
            f"  {RED}{BOLD}! COMPROMISED{RESET}  "
            f"litellm=={installation.version}  ->  {installation.python_path}"
        )
    else:
        print(
            f"  {GREEN}+ clean{RESET}        "
            f"litellm=={installation.version}  ->  {installation.python_path}"
        )


def scan_environments(envs: list[Path], results: ScanResults) -> None:
    """Check each Python environment for litellm and report findings."""
    for python_path in envs:
        if not _is_working_interpreter(python_path):
            continue

        results.envs_scanned += 1
        version = _get_litellm_version(python_path)
        if version is None:
            continue

        installation = Installation(
            python_path=str(python_path), version=version
        )
        results.installations.append(installation)
        _report_installation(installation)

    if not results.installations:
        print(
            f"  {GREEN}No litellm installations found "
            f"in {results.envs_scanned} environments.{RESET}"
        )
