"""Shared fixtures for the scan_litellm_compromise test suite."""

from pathlib import Path

import pytest

from scan_litellm_compromise.models import (
    ConfigReference,
    Installation,
    ScanResults,
    SourceReference,
)


# ── Stub policy ────────────────────────────────────────────────────────


class StubPolicy:
    """Minimal PlatformPolicy satisfying the Protocol for tests."""

    name = "TestOS"
    search_roots: list[str] = []
    conda_globs: list[str] = []
    persistence_paths: list[str] = []
    persistence_description = "test persistence"
    tmp_iocs: list[str] = []
    tmp_description = "test tmp"
    pth_search_roots: list[str] = []
    network_check_command = None
    exclusion_note = "test note"

    def home_conda_dirs(self) -> list[str]:
        return []

    def home_pipx_dir(self) -> Path | None:
        return None

    def extra_ioc_checks(self, results) -> None:
        pass

    def remediation_persistence_steps(self) -> list[str]:
        return ["Check test persistence"]

    def remediation_artifact_lines(self) -> list[str]:
        return ["-> Remove test artifacts"]


# ── Model fixtures ─────────────────────────────────────────────────────


@pytest.fixture
def clean_results() -> ScanResults:
    return ScanResults()


@pytest.fixture
def compromised_installation() -> Installation:
    return Installation(env_path="/fake/env", version="1.82.7")


@pytest.fixture
def safe_installation() -> Installation:
    return Installation(env_path="/fake/env", version="1.82.6")


@pytest.fixture
def sample_source_ref() -> SourceReference:
    return SourceReference(
        file_path="/fake/app.py", line_number=10, line_content="import litellm"
    )


@pytest.fixture
def sample_config_ref_compromised() -> ConfigReference:
    return ConfigReference(
        file_path="/fake/requirements.txt",
        line_number=3,
        line_content="litellm==1.82.7",
        pinned_version="1.82.7",
    )


@pytest.fixture
def sample_config_ref_safe() -> ConfigReference:
    return ConfigReference(
        file_path="/fake/requirements.txt",
        line_number=3,
        line_content="litellm==1.80.0",
        pinned_version="1.80.0",
    )


@pytest.fixture
def stub_policy() -> StubPolicy:
    return StubPolicy()
