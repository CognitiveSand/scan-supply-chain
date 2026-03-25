"""Phase 1: Discover Python environments on the system."""

from __future__ import annotations

import glob as globmod
import logging
import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .platform_policy import PlatformPolicy

logger = logging.getLogger(__name__)

_NOISE_DIRS = frozenset({"__pycache__", ".git", "node_modules"})


def _build_search_roots(policy: PlatformPolicy) -> list[str]:
    """Combine platform roots with user-local conda/pipx directories."""
    roots = list(policy.search_roots)
    home = Path.home()

    for extra_dir in policy.home_conda_dirs():
        candidate = home / extra_dir
        if candidate.is_dir():
            roots.append(str(candidate))

    pipx_dir = policy.home_pipx_dir()
    if pipx_dir is not None:
        roots.append(str(pipx_dir))

    for pattern in policy.conda_globs:
        roots.extend(globmod.glob(pattern))

    return roots


def _is_python_binary(filename: str, policy: PlatformPolicy) -> bool:
    return (
        filename in policy.python_binary_names
        or bool(policy.python_versioned_re.match(filename))
    )


def _walk_for_pythons(root: Path, policy: PlatformPolicy) -> list[Path]:
    """Walk a directory tree and return executable Python interpreters."""
    found = []
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _NOISE_DIRS]
            for filename in filenames:
                if _is_python_binary(filename, policy):
                    full_path = Path(dirpath) / filename
                    if policy.is_executable_python(full_path):
                        found.append(full_path)
    except PermissionError:
        logger.debug("Permission denied walking %s", root)
    return found


def _deduplicate_by_realpath(paths: list[Path]) -> list[Path]:
    """Remove duplicates that resolve to the same real path."""
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in paths:
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        if resolved not in seen:
            seen.add(resolved)
            unique.append(path)
    return unique


def find_python_envs(policy: PlatformPolicy) -> list[Path]:
    """Find all unique Python interpreters on the system."""
    roots = _build_search_roots(policy)
    found: list[Path] = []

    for root in roots:
        root_path = Path(root)
        if root_path.is_dir():
            found.extend(_walk_for_pythons(root_path, policy))

    for system_python in policy.system_pythons:
        path = Path(system_python)
        if policy.is_executable_python(path):
            found.append(path)

    return _deduplicate_by_realpath(found)
