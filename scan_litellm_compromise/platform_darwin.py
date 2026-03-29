"""macOS (Darwin) platform policy."""

from pathlib import Path


class DarwinPolicy:
    """All macOS-specific paths, commands, and behavior."""

    @property
    def name(self) -> str:
        return "macOS"

    @property
    def search_roots(self) -> list[str]:
        return ["/Users", "/opt/homebrew", "/usr/local", "/Library"]

    @property
    def conda_globs(self) -> list[str]:
        return [
            "/opt/homebrew/Caskroom/miniconda*",
            "/opt/homebrew/Caskroom/miniforge*",
            "/opt/homebrew/Caskroom/anaconda*",
        ]

    @property
    def persistence_paths(self) -> list[str]:
        # The malware writes these unconditionally on all Unix.
        # systemd is absent on macOS so the service is inert,
        # but the files may still exist on disk.
        return [
            "~/.config/sysmon/sysmon.py",
            "~/.config/systemd/user/sysmon.service",
        ]

    @property
    def persistence_description(self) -> str:
        return "sysmon persistence (systemd files — inert on macOS)"

    @property
    def tmp_iocs(self) -> list[str]:
        return ["/tmp/pglog", "/tmp/.pg_state", "/tmp/tpcp.tar.gz"]

    @property
    def tmp_description(self) -> str:
        return "exfiltration artifacts (/tmp)"

    @property
    def pth_search_roots(self) -> list[str]:
        return ["/Users", "/opt/homebrew", "/usr/local", "/Library"]

    @property
    def network_check_command(self) -> list[str] | None:
        return ["lsof", "-i", "-P", "-n"]

    @property
    def exclusion_note(self) -> str:
        return "Scanning user-accessible paths (/Users, /opt/homebrew, /Library)."

    def home_conda_dirs(self) -> list[str]:
        return ["miniconda3", "miniforge3", "anaconda3", ".conda"]

    def home_pipx_dir(self) -> Path | None:
        # pipx typically uses the XDG path on macOS too
        xdg = Path.home() / ".local" / "share" / "pipx"
        if xdg.is_dir():
            return xdg
        # Some installs use the macOS-native path
        native = Path.home() / "Library" / "Application Support" / "pipx" / "venvs"
        if native.is_dir():
            return native
        return None

    def extra_ioc_checks(self, results: object) -> None:
        pass  # No macOS-specific checks — malware has no LaunchAgent code.

    def remediation_persistence_steps(self) -> list[str]:
        return [
            "Check for sysmon artifacts (inert on macOS, but file may exist):",
            "  -> ls -la ~/.config/sysmon/",
            "  -> ls -la ~/.config/systemd/user/sysmon.service",
            "  -> launchctl list | grep sysmon  (should find nothing)",
        ]

    def remediation_artifact_lines(self) -> list[str]:
        return [
            "-> Delete any litellm_init.pth files from site-packages/",
            "-> Remove ~/.config/sysmon/ if present",
            "-> Remove /tmp/pglog, /tmp/.pg_state, /tmp/tpcp.tar.gz",
        ]
