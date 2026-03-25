"""Phase 2: Check litellm versions from discovered metadata directories."""

import logging
import re
from pathlib import Path

from .config import DIST_INFO_PATTERN, EGG_INFO_PATTERN
from .formatting import BOLD, GREEN, RED, RESET
from .models import Installation, ScanResults

logger = logging.getLogger(__name__)

_METADATA_VERSION_RE = re.compile(r"^Version:\s*(.+)$", re.MULTILINE)


def _read_version_from_file(metadata_file: Path) -> str | None:
    """Read the Version field from a METADATA or PKG-INFO file."""
    try:
        text = metadata_file.read_text(errors="ignore")
    except (PermissionError, OSError):
        logger.debug("Cannot read %s", metadata_file)
        return None

    match = _METADATA_VERSION_RE.search(text)
    return match.group(1).strip() if match else None


def _extract_version(metadata_dir: Path) -> str | None:
    """Extract litellm version from a dist-info or egg-info directory.

    Tries METADATA file first, then PKG-INFO, then falls back to
    parsing the version from the directory name.
    """
    for filename in ("METADATA", "PKG-INFO"):
        candidate = metadata_dir / filename
        if candidate.is_file():
            version = _read_version_from_file(candidate)
            if version:
                return version

    # Fallback: parse version from directory name
    for pattern in (DIST_INFO_PATTERN, EGG_INFO_PATTERN):
        match = pattern.match(metadata_dir.name)
        if match:
            return match.group(1)

    return None


def _report_installation(installation: Installation) -> None:
    """Print a single installation's status."""
    if installation.is_compromised:
        print(
            f"  {RED}{BOLD}! COMPROMISED{RESET}  "
            f"litellm=={installation.version}  ->  {installation.env_path}"
        )
    else:
        print(
            f"  {GREEN}+ clean{RESET}        "
            f"litellm=={installation.version}  ->  {installation.env_path}"
        )


def scan_environments(metadata_dirs: list[Path], results: ScanResults) -> None:
    """Check each discovered metadata directory for litellm version."""
    for metadata_dir in metadata_dirs:
        results.envs_scanned += 1
        version = _extract_version(metadata_dir)
        if version is None:
            logger.debug("Could not determine version from %s", metadata_dir)
            continue

        installation = Installation(
            env_path=str(metadata_dir), version=version
        )
        results.installations.append(installation)
        _report_installation(installation)

    if not results.installations:
        print(
            f"  {GREEN}No litellm installations found "
            f"in {results.envs_scanned} locations.{RESET}"
        )
