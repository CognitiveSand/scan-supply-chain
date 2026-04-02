"""Linux platform policy — OS infrastructure only."""

from .platform_policy import BasePlatformPolicy


class LinuxPolicy(BasePlatformPolicy):
    """Linux-specific paths and commands."""

    @property
    def name(self) -> str:
        return "Linux"

    @property
    def platform_key(self) -> str:
        return "linux"

    @property
    def search_roots(self) -> list[str]:
        return ["/home", "/opt", "/usr/local", "/usr/lib", "/srv", "/var"]

    @property
    def conda_globs(self) -> list[str]:
        return ["/opt/conda", "/opt/miniconda*", "/opt/miniforge*"]

    @property
    def network_check_command(self) -> list[str] | None:
        return ["ss", "-tnp"]

    @property
    def exclusion_note(self) -> str:
        return "/root is excluded -- this scanner only inspects user-accessible paths."
