"""Data structures for scan results."""

from dataclasses import dataclass, field

from .config import COMPROMISED_VERSIONS


@dataclass(frozen=True)
class Installation:
    """A litellm installation found via filesystem metadata."""

    env_path: str
    version: str

    @property
    def is_compromised(self) -> bool:
        return self.version in COMPROMISED_VERSIONS


@dataclass(frozen=True)
class SourceReference:
    """A reference to litellm found in a Python source file."""

    file_path: str
    line_number: int
    line_content: str


@dataclass(frozen=True)
class ConfigReference:
    """A reference to litellm found in a config/dependency file."""

    file_path: str
    line_number: int
    line_content: str
    pinned_version: str | None = None

    @property
    def is_compromised(self) -> bool:
        return self.pinned_version in COMPROMISED_VERSIONS


@dataclass
class ScanResults:
    """Aggregated results from all scan phases."""

    envs_scanned: int = 0
    installations: list[Installation] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    source_refs: list[SourceReference] = field(default_factory=list)
    config_refs: list[ConfigReference] = field(default_factory=list)

    @property
    def compromised_installations(self) -> list[Installation]:
        return [i for i in self.installations if i.is_compromised]

    @property
    def compromised_configs(self) -> list[ConfigReference]:
        return [r for r in self.config_refs if r.is_compromised]

    @property
    def is_clean(self) -> bool:
        return not (
            self.compromised_installations
            or self.iocs
            or self.compromised_configs
        )

    @property
    def source_files(self) -> set[str]:
        return {ref.file_path for ref in self.source_refs}

    @property
    def config_files(self) -> set[str]:
        return {ref.file_path for ref in self.config_refs}
