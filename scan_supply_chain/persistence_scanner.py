"""Generic persistence location scanner.

Checks common persistence mechanisms that any supply chain attack
might abuse, independent of the specific threat profile.
Every checker filters by the target package name — no generic noise.
"""

from __future__ import annotations

import logging
import shutil
import sys
from pathlib import Path

from .config import read_if_contains
from .models import FindingCategory, ScanResults, scanner_check
from .subprocess_utils import run_safe

logger = logging.getLogger(__name__)


def scan_persistence(results: ScanResults, package: str) -> None:
    """Scan common persistence locations for package references."""
    with scanner_check(results, "generic persistence locations",
                       "No suspicious persistence found"):
        _check_crontab(results, package)
        _check_shell_rc(results, package)
        _check_tmp_scripts(results, package)

        if sys.platform == "linux":
            _check_config_dir(
                results,
                Path.home() / ".config" / "systemd" / "user",
                "*.service",
                "systemd user service",
                package,
            )
            _check_config_dir(
                results,
                Path.home() / ".config" / "autostart",
                "*.desktop",
                "XDG autostart",
                package,
            )
        elif sys.platform == "darwin":
            _check_config_dir(
                results,
                Path.home() / "Library" / "LaunchAgents",
                "*.plist",
                "LaunchAgent",
                package,
            )


# ── Helpers ─────────────────────────────────────────────────────────────


def _check_config_dir(
    results: ScanResults,
    directory: Path,
    glob_pattern: str,
    label: str,
    package: str,
) -> None:
    """Glob a config directory for files mentioning the package."""
    if not directory.is_dir():
        return
    try:
        for config_file in directory.glob(glob_pattern):
            text = config_file.read_text(errors="ignore")
            if package in text:
                results.add_finding(
                    FindingCategory.PERSISTENCE,
                    f"{label}: {config_file.name}",
                    str(config_file),
                    2,
                )
    except (PermissionError, OSError):
        logger.debug("Cannot read %s", directory)


# ── Individual checkers ─────────────────────────────────────────────────


def _check_crontab(results: ScanResults, package: str) -> None:
    if not shutil.which("crontab"):
        return
    output = run_safe(["crontab", "-l"])
    if output is None:
        return
    for line in output.splitlines():
        if package in line and not line.strip().startswith("#"):
            results.add_finding(
                FindingCategory.PERSISTENCE,
                f"crontab: {line.strip()}",
                "crontab -l",
                2,
            )


def _check_shell_rc(results: ScanResults, package: str) -> None:
    home = Path.home()
    for rc_name in (".bashrc", ".zshrc", ".profile", ".bash_profile"):
        rc_path = home / rc_name
        if not rc_path.is_file():
            continue
        try:
            text = rc_path.read_text(errors="ignore")
            for i, line in enumerate(text.splitlines(), 1):
                if package in line and not line.strip().startswith("#"):
                    results.add_finding(
                        FindingCategory.PERSISTENCE,
                        f"{rc_name}:{i} mentions {package}",
                        str(rc_path),
                        2,
                    )
        except (PermissionError, OSError):
            logger.debug("Cannot read %s", rc_path)


def _check_tmp_scripts(results: ScanResults, package: str) -> None:
    """Check /tmp for scripts that actually import the package."""
    tmp = Path("/tmp") if sys.platform != "win32" else None
    if tmp is None or not tmp.is_dir():
        return
    try:
        for f in tmp.iterdir():
            if not f.is_file():
                continue
            if f.suffix == ".py":
                _check_tmp_python_file(results, f, package)
            elif f.suffix in (".sh", ".bash"):
                _check_tmp_shell_file(results, f, package)
    except (PermissionError, OSError):
        logger.debug("Cannot read /tmp")


def _check_tmp_python_file(results: ScanResults, path: Path, package: str) -> None:
    """Flag a /tmp .py file only if it actually imports the package."""
    text = read_if_contains(path, package)
    if text is None:
        return

    from .ast_scanner import scan_python_imports

    lines = text.splitlines()
    ast_refs = scan_python_imports(text, lines, package, str(path))

    if ast_refs is not None:
        # AST parsed successfully — trust its result
        if ast_refs:
            results.add_finding(
                FindingCategory.PERSISTENCE,
                f"/tmp script: {path.name}",
                str(path),
                2,
            )
    else:
        # SyntaxError fallback — check non-comment lines
        if _has_active_reference(text, package):
            results.add_finding(
                FindingCategory.PERSISTENCE,
                f"/tmp script: {path.name}",
                str(path),
                2,
            )


def _check_tmp_shell_file(results: ScanResults, path: Path, package: str) -> None:
    """Flag a /tmp shell script only if it references the package."""
    text = read_if_contains(path, package)
    if text is not None and _has_active_reference(text, package):
        results.add_finding(
            FindingCategory.PERSISTENCE,
            f"/tmp script: {path.name}",
            str(path),
            2,
        )


def _has_active_reference(text: str, package: str) -> bool:
    """Check if any non-comment line contains the package name."""
    return any(
        package in line and not line.strip().startswith("#")
        for line in text.splitlines()
    )
