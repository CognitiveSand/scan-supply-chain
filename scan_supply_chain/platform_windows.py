"""Windows 10/11 platform policy — OS infrastructure only."""

import os
import shutil
from pathlib import Path

from .platform_policy import BasePlatformPolicy, _first_existing_dir


class WindowsPolicy(BasePlatformPolicy):
    """Windows-specific paths and commands."""

    @property
    def name(self) -> str:
        return "Windows"

    @property
    def platform_key(self) -> str:
        return "windows"

    @property
    def search_roots(self) -> list[str]:
        roots = []
        for env_var in ("USERPROFILE", "APPDATA", "LOCALAPPDATA"):
            val = os.environ.get(env_var)
            if val and Path(val).is_dir():
                roots.append(val)
        for pf_var in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
            val = os.environ.get(pf_var)
            if val and Path(val).is_dir():
                roots.append(val)
        return roots

    @property
    def conda_globs(self) -> list[str]:
        globs = []
        for env_var in ("USERPROFILE", "LOCALAPPDATA", "ProgramData"):
            base = os.environ.get(env_var)
            if base:
                for name in ("Miniconda3", "Miniforge3", "Anaconda3"):
                    globs.append(str(Path(base) / name))
        return globs

    @property
    def network_check_command(self) -> list[str] | None:
        if shutil.which("netstat"):
            return ["netstat", "-ano"]
        return None

    @property
    def exclusion_note(self) -> str:
        return (
            "Scanning user-accessible paths (%USERPROFILE%, %APPDATA%, Program Files)."
        )

    def home_conda_dirs(self) -> list[str]:
        return ["Miniconda3", "Miniforge3", "Anaconda3", ".conda"]

    def home_pipx_dir(self) -> Path | None:
        localappdata = os.environ.get("LOCALAPPDATA", "")
        if not localappdata:
            return None
        return _first_existing_dir(Path(localappdata) / "pipx" / "venvs")
