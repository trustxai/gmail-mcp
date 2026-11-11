"""httpx/httpcore request logs never reach stderr (the URL names what the account read)."""

from __future__ import annotations

import logging
import os
import subprocess
import sys

import pytest

from .fakes import FakeGoogle, fake_access_token, make_client


def test_httpx_logger_effective_level_is_at_least_warning() -> None:
    """Checked in a fresh subprocess: pytest pre-attaches a root handler, masking the bug in-process."""
    script = (
        "import logging, gmail_mcp.server\n"
        "level = logging.getLogger('httpx').getEffectiveLevel()\n"
        "core = logging.getLogger('httpcore').getEffectiveLevel()\n"
        "raise SystemExit(0 if level >= logging.WARNING and core >= logging.WARNING else 1)\n"
    )
    env = {"HOME": os.environ.get("HOME", ""), "PATH": os.environ.get("PATH", "")}
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, env=env)
    assert result.returncode == 0, f"httpx effective level too low (stderr: {result.stderr})"


async def test_a_request_emits_no_httpx_record_and_no_token(caplog: pytest.LogCaptureFixture) -> None:
    import gmail_mcp.server  # noqa: F401  (import triggers the fix under test)

    with caplog.at_level(logging.INFO):
        await make_client(FakeGoogle()).get("users/me/labels")

    assert not any(record.name.startswith("httpx") for record in caplog.records)
    assert not any("users/me/labels" in record.getMessage() for record in caplog.records)
    assert fake_access_token(1) not in caplog.text
