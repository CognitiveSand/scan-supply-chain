"""npm ecosystem plugin — finds Node.js packages via node_modules."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


class NpmPlugin:
    """Discovers npm packages installed in node_modules."""

    @property
    def name(self) -> str:
        return "npm"

    @property
    def source_extensions(self) -> frozenset[str]:
        return frozenset({".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"})

    @property
    def config_filenames(self) -> frozenset[str]:
        return frozenset({
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            ".npmrc",
        })

    @property
    def config_extensions(self) -> frozenset[str]:
        return frozenset()  # no extension-based matching for npm configs

    def metadata_dir_pattern(self, package: str) -> re.Pattern:
        # npm packages live in node_modules/{package}/
        # For scoped packages: node_modules/@scope/name/
        escaped = re.escape(package)
        return re.compile(rf"^{escaped}$")

    def extract_version(self, metadata_path: Path) -> str | None:
        """Read version from node_modules/{pkg}/package.json."""
        pkg_json = metadata_path / "package.json"
        if not pkg_json.is_file():
            return None
        try:
            data = json.loads(pkg_json.read_text(errors="ignore"))
            return data.get("version")
        except (json.JSONDecodeError, PermissionError, OSError):
            logger.debug("Cannot read %s", pkg_json)
            return None

    def import_patterns(self, package: str) -> list[re.Pattern]:
        escaped = re.escape(package)
        return [
            # require('axios') or require("axios")
            re.compile(rf"""require\s*\(\s*['"]({escaped})(?:/[^'"]*)?['"]\s*\)"""),
            # import axios from 'axios'
            re.compile(rf"""import\s+\w+\s+from\s+['"]({escaped})(?:/[^'"]*)?['"]"""),
            # import { ... } from 'axios'
            re.compile(rf"""from\s+['"]({escaped})(?:/[^'"]*)?['"]"""),
            # import 'axios' (side-effect import)
            re.compile(rf"""import\s+['"]({escaped})(?:/[^'"]*)?['"]"""),
        ]

    def dep_patterns(self, package: str) -> list[re.Pattern]:
        escaped = re.escape(package)
        return [
            # package.json: "axios": "^1.14.0"
            re.compile(rf"""["']{escaped}["']\s*:"""),
            # yarn.lock / pnpm-lock: axios@^1.14.0
            re.compile(rf"(?<![a-zA-Z0-9_@/-]){escaped}@"),
            # package-lock.json: "node_modules/axios"
            re.compile(rf"""["']node_modules/{escaped}["']"""),
        ]

    def pinned_version_pattern(self, package: str) -> re.Pattern:
        escaped = re.escape(package)
        # Matches "axios": "1.14.1" (exact version, no ^ or ~)
        return re.compile(
            rf"""["']{escaped}["']\s*:\s*["']([0-9][0-9a-zA-Z.*-]*)["']"""
        )

    def config_filename_pattern(self) -> re.Pattern | None:
        return None  # no dynamic config filenames for npm

    def extra_search_roots(self) -> list[str]:
        """Add global npm prefix to search roots."""
        roots: list[str] = []
        # Global npm modules
        if shutil.which("npm"):
            try:
                result = subprocess.run(
                    ["npm", "root", "-g"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0:
                    global_root = result.stdout.strip()
                    if global_root and Path(global_root).is_dir():
                        roots.append(global_root)
            except (subprocess.TimeoutExpired, OSError):
                logger.debug("Failed to get global npm root")

        # nvm installations
        home = Path.home()
        nvm_dir = home / ".nvm" / "versions" / "node"
        if nvm_dir.is_dir():
            for node_version in nvm_dir.iterdir():
                lib_nm = node_version / "lib" / "node_modules"
                if lib_nm.is_dir():
                    roots.append(str(lib_nm))

        return roots

    def find_phantom_deps(
        self, names: list[str], search_roots: list[str],
    ) -> list[str]:
        """Check for phantom npm dependencies in node_modules."""
        if not names:
            return []
        found: list[str] = []
        seen: set[str] = set()

        for root in search_roots:
            root_path = Path(root)
            if not root_path.is_dir():
                continue
            try:
                for dirpath, dirnames, filenames in os.walk(root_path):
                    dp = Path(dirpath)
                    # Only inspect node_modules directories
                    if dp.name == "node_modules":
                        for name in names:
                            phantom_dir = dp / name
                            if phantom_dir.is_dir():
                                resolved = str(phantom_dir.resolve())
                                if resolved not in seen:
                                    seen.add(resolved)
                                    found.append(
                                        f"phantom:{name} at {phantom_dir}"
                                    )
                    # Also check lockfiles in project directories
                    for fn in filenames:
                        if fn in ("package-lock.json", "yarn.lock"):
                            lock_path = dp / fn
                            try:
                                text = lock_path.read_text(errors="ignore")
                                for name in names:
                                    if name in text:
                                        key = f"{lock_path}:{name}"
                                        if key not in seen:
                                            seen.add(key)
                                            found.append(
                                                f"phantom:{name} in {lock_path}"
                                            )
                            except (PermissionError, OSError):
                                pass
                    # Prune unproductive subtrees
                    dirnames[:] = [
                        d for d in dirnames
                        if d not in {
                            ".git", "__pycache__", ".tox",
                            "dist", "build", ".cache",
                        }
                    ]
            except PermissionError:
                logger.debug("Permission denied walking %s", root)
        return found
