"""Phase 1: Discover Python environments on the system."""

import glob as globmod
import logging
import os
import re
from pathlib import Path

from .config import CONDA_GLOBS, SEARCH_ROOTS

logger = logging.getLogger(__name__)

_PYTHON_BINARY_NAMES = frozenset({"python", "python3"})
_PYTHON_VERSIONED_RE = re.compile(r"^python3\.\d+$")
_NOISE_DIRS = frozenset({"__pycache__", ".git", "node_modules"})
_SYSTEM_PYTHONS = ["/usr/bin/python3", "/usr/bin/python"]


def _build_search_roots() -> list[str]:
    """Combine standard roots with user-local conda/pipx directories."""
    roots = list(SEARCH_ROOTS)
    home = Path.home()

    for extra_dir in ["miniconda3", "miniforge3", "anaconda3", ".conda"]:
        candidate = home / extra_dir
        if candidate.is_dir():
            roots.append(str(candidate))

    pipx_dir = home / ".local" / "share" / "pipx"
    if pipx_dir.is_dir():
        roots.append(str(pipx_dir))

    for pattern in CONDA_GLOBS:
        roots.extend(globmod.glob(pattern))

    return roots


def _is_python_binary(filename: str) -> bool:
    return (
        filename in _PYTHON_BINARY_NAMES
        or bool(_PYTHON_VERSIONED_RE.match(filename))
    )


def _walk_for_pythons(root: Path) -> list[Path]:
    """Walk a directory tree and return executable Python interpreters."""
    found = []
    try:
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _NOISE_DIRS]
            for filename in filenames:
                if _is_python_binary(filename):
                    full_path = Path(dirpath) / filename
                    if full_path.is_file() and os.access(full_path, os.X_OK):
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


def find_python_envs() -> list[Path]:
    """Find all unique Python interpreters on the system."""
    roots = _build_search_roots()
    found: list[Path] = []

    for root in roots:
        root_path = Path(root)
        if root_path.is_dir():
            found.extend(_walk_for_pythons(root_path))

    for system_python in _SYSTEM_PYTHONS:
        path = Path(system_python)
        if path.is_file() and os.access(path, os.X_OK):
            found.append(path)

    return _deduplicate_by_realpath(found)
