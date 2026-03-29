"""Phase 4: Scan source files and configs for litellm usage."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

from .config import (
    CONFIG_EXTENSIONS,
    CONFIG_FILENAMES,
    PYTHON_IMPORT_PATTERNS,
    REQUIREMENTS_FILENAME_PATTERN,
    REQUIREMENTS_PATTERN,
    SOURCE_SCAN_SKIP_DIRS,
    SOURCE_EXTENSIONS,
    TOML_BARE_PATTERN,
    TOML_DEPENDENCY_PATTERN,
    PINNED_VERSION_PATTERN,
)
from .models import ConfigReference, ScanResults, SourceReference

if TYPE_CHECKING:
    from .platform_policy import PlatformPolicy

logger = logging.getLogger(__name__)


# ── Root deduplication ───────────────────────────────────────────────────


def _deduplicate_roots(roots: list[str]) -> list[str]:
    """Remove roots that are subdirectories of other roots."""
    resolved = [(r, Path(r).resolve()) for r in roots if Path(r).is_dir()]
    resolved.sort(key=lambda x: len(x[1].parts))
    kept: list[tuple[str, Path]] = []
    for original, resolved_path in resolved:
        if any(
            resolved_path == kept_path or kept_path in resolved_path.parents
            for _, kept_path in kept
        ):
            continue
        kept.append((original, resolved_path))
    return [original for original, _ in kept]


def _build_scan_roots(policy: PlatformPolicy) -> list[str]:
    """Build deduplicated list of directories to scan."""
    return _deduplicate_roots(policy.search_roots + [str(Path.home())])


# ── File classification ──────────────────────────────────────────────────


def _is_config_file(filename: str, extension: str) -> bool:
    """Check if a filename matches known config/dependency file patterns."""
    return (
        filename in CONFIG_FILENAMES
        or bool(REQUIREMENTS_FILENAME_PATTERN.match(filename))
        or (extension in CONFIG_EXTENSIONS and "require" in filename.lower())
    )


# ── Pattern matching ─────────────────────────────────────────────────────


def _extract_pinned_version(line: str) -> str | None:
    """Extract pinned version from a dependency line (e.g. litellm==1.82.8)."""
    match = PINNED_VERSION_PATTERN.search(line)
    return match.group(1) if match else None


def _matches_source_pattern(line: str) -> bool:
    """Check if a line matches any litellm import/usage pattern."""
    return any(pattern.search(line) for pattern in PYTHON_IMPORT_PATTERNS)


def _matches_config_pattern(stripped_line: str, raw_line: str) -> bool:
    """Check if a line matches any litellm dependency pattern."""
    return (
        bool(TOML_DEPENDENCY_PATTERN.search(raw_line))
        or bool(TOML_BARE_PATTERN.search(raw_line))
        or bool(REQUIREMENTS_PATTERN.match(stripped_line))
    )


# ── Single-file scanning ────────────────────────────────────────────────


def _scan_file_lines(
    file_path: Path, is_source: bool, results: ScanResults
) -> None:
    """Scan a single file's lines for litellm references."""
    try:
        text = file_path.read_text(errors="ignore")
    except (PermissionError, OSError):
        return

    if "litellm" not in text:
        return

    for line_number, line in enumerate(text.splitlines(), 1):
        if "litellm" not in line:
            continue

        stripped = line.strip()

        if is_source and _matches_source_pattern(line):
            results.source_refs.append(
                SourceReference(str(file_path), line_number, stripped)
            )
        elif not is_source and _matches_config_pattern(stripped, line):
            results.config_refs.append(
                ConfigReference(
                    str(file_path),
                    line_number,
                    stripped,
                    _extract_pinned_version(line),
                )
            )


# ── Public entry point ───────────────────────────────────────────────────


def scan_source_and_configs(
    results: ScanResults, policy: PlatformPolicy, scan_path: str | None = None
) -> int:
    """Scan source and config files for litellm usage.

    Returns the number of files scanned.
    """
    if scan_path is not None:
        scan_roots = [scan_path]
    else:
        scan_roots = _build_scan_roots(policy)
    scanner_dir = str(Path(__file__).resolve().parent)
    seen_files: set[str] = set()
    files_scanned = 0

    print(f"  Scanning .py files, pyproject.toml, requirements*.txt, etc.")
    print(f"  Search roots: {', '.join(scan_roots)}\n")

    for root in scan_roots:
        root_path = Path(root)
        if not root_path.is_dir():
            continue
        try:
            for dirpath, dirnames, filenames in os.walk(root_path):
                dirnames[:] = [d for d in dirnames if d not in SOURCE_SCAN_SKIP_DIRS]
                dir_path = Path(dirpath)

                for filename in filenames:
                    file_path = dir_path / filename
                    extension = file_path.suffix.lower()
                    is_source = extension in SOURCE_EXTENSIONS
                    is_config = _is_config_file(filename, extension)

                    if not is_source and not is_config:
                        continue

                    try:
                        resolved = str(file_path.resolve())
                    except OSError:
                        continue
                    if resolved in seen_files or resolved.startswith(scanner_dir):
                        continue
                    seen_files.add(resolved)

                    files_scanned += 1
                    _scan_file_lines(file_path, is_source, results)
        except PermissionError:
            logger.debug("Permission denied walking %s", root)

    return files_scanned
