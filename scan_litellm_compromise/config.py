"""Constants and configuration for the LiteLLM supply chain scanner."""

import re

COMPROMISED_VERSIONS = frozenset({"1.82.7", "1.82.8"})

SEARCH_ROOTS = [
    "/home",
    "/opt",
    "/usr/local",
    "/usr/lib",
    "/srv",
    "/var",
]
# NOTE: /root is intentionally excluded — this scanner does not access root-owned paths.

CONDA_GLOBS = [
    "/opt/conda",
    "/opt/miniconda*",
    "/opt/miniforge*",
]

SYSMON_PATHS = [
    "~/.config/sysmon/sysmon.py",
    "~/.config/systemd/user/sysmon.service",
]
# NOTE: /root sysmon paths excluded — this scanner does not access root-owned paths.

TMP_IOCS = ["/tmp/pglog", "/tmp/.pg_state", "/tmp/tpcp.tar.gz"]

C2_DOMAINS = ["models.litellm.cloud", "checkmarx.zone"]

SKIP_DIRS = frozenset({
    "__pycache__",
    ".git",
    "node_modules",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    "site-packages",
    ".venv-bak",
    "dist",
    "build",
    ".eggs",
})

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

# ── Regex patterns ──────────────────────────────────────────────────────

PYTHON_IMPORT_PATTERNS = [
    re.compile(r"^\s*import\s+litellm"),
    re.compile(r"^\s*from\s+litellm[\s.]"),
    re.compile(r"litellm\."),
    re.compile(r"""["']litellm["']"""),
]

TOML_DEPENDENCY_PATTERN = re.compile(r"""litellm\s*[=<>!~]""")
TOML_BARE_PATTERN = re.compile(r"""["']litellm["']""")
REQUIREMENTS_PATTERN = re.compile(r"^\s*litellm\s*([=<>!~]|$)")
REQUIREMENTS_FILENAME_PATTERN = re.compile(r"^requirements.*\.txt$")
PINNED_VERSION_PATTERN = re.compile(r"litellm\s*==\s*([0-9][0-9a-zA-Z.*]+)")
