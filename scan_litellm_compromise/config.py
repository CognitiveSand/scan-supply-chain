"""Cross-platform constants and configuration for the LiteLLM scanner.

Platform-specific values (paths, commands) live in platform_linux.py
and platform_windows.py. This module holds only platform-neutral config.
"""

import re

COMPROMISED_VERSIONS = frozenset({"1.82.7", "1.82.8"})

C2_DOMAINS = ["models.litellm.cloud", "checkmarx.zone"]

# Directories always skipped during any filesystem walk
_COMMON_SKIP_DIRS = frozenset({
    "__pycache__",
    ".git",
    "node_modules",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    ".venv-bak",
    "dist",
    "build",
    ".eggs",
})

# Phase 1/2 discovery needs to enter site-packages to find dist-info
DISCOVERY_SKIP_DIRS = _COMMON_SKIP_DIRS

# Phase 4 source scanner skips site-packages (no need to scan third-party .py)
SOURCE_SCAN_SKIP_DIRS = _COMMON_SKIP_DIRS | {"site-packages"}

# ── Metadata directory patterns (for filesystem-based version detection) ─

DIST_INFO_PATTERN = re.compile(r"^litellm-([^/\\]+)\.dist-info$")
EGG_INFO_PATTERN = re.compile(r"^litellm-([^/\\]+)\.egg-info$")

SOURCE_EXTENSIONS = frozenset({".py"})

CONFIG_FILENAMES = frozenset({
    "pyproject.toml",
    "setup.cfg",
    "setup.py",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-prod.txt",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "pdm.lock",
    "uv.lock",
})

CONFIG_EXTENSIONS = frozenset({".toml", ".cfg"})

# ── Regex patterns (platform-neutral) ───────────────────────────────────

PYTHON_IMPORT_PATTERNS = [
    re.compile(r"^\s*import\s+litellm"),
    re.compile(r"^\s*from\s+litellm[\s.]"),
    re.compile(r"(?<![a-zA-Z0-9_])litellm\."),
    re.compile(r"""["']litellm["']"""),
]

TOML_DEPENDENCY_PATTERN = re.compile(r"(?<![a-zA-Z0-9_-])litellm\s*[=<>!~]")
TOML_BARE_PATTERN = re.compile(r"""["']litellm["']""")
REQUIREMENTS_PATTERN = re.compile(r"^\s*litellm\s*([=<>!~]|$)")
REQUIREMENTS_FILENAME_PATTERN = re.compile(r"^requirements.*\.txt$")
PINNED_VERSION_PATTERN = re.compile(
    r"(?<![a-zA-Z0-9_-])litellm\s*==\s*([0-9][0-9a-zA-Z.*]+)"
)
