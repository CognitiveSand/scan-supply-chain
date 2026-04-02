"""Safe subprocess execution helper."""

from __future__ import annotations

import logging
import subprocess

logger = logging.getLogger(__name__)


def run_safe(cmd: list[str], *, timeout: int = 5) -> str | None:
    """Run a command, return stdout as str or None on failure/timeout."""
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout
        ).stdout
    except (subprocess.TimeoutExpired, OSError):
        logger.debug("Command failed or timed out: %s", cmd)
        return None
