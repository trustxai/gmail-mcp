"""Harness for the live tests (read-only, against the real mailbox; how to run them: _support.py).

**One Gmail client per test.** `gmail_mcp.client.get_client()` is a process-wide singleton,
and the httpx pool inside it binds its connections to the event loop of the first request.
pytest-asyncio gives every test its own loop, so a client reused by a later test sends on a
connection whose loop is already closed: run together, two of the first seven live tests
failed with "RuntimeError: Event loop is closed" and passed alone (measured 2026-11-11). The
server never meets this, because it runs in one loop for its whole life. So every live test
starts without a client and without a scope guard (the spine's own `reset_client` /
`reset_scope`: the scope guard holds the client), and the client the test made is closed in
the test's own loop before the next one starts. Settings stay cached: they hold no loop.

**Measurements.** A few live tests measure a fact about Gmail instead of asserting one (does
an attachmentId rotate between two reads, which status and reason Gmail sends for an id it
cannot find). They call `live_record(label, value)`: the test prints the value alone (seen
with `-rP` or `-s`), it goes to the junit XML as a user property, and the run ends with a
"live measurements" section listing every value. Values are a closed vocabulary — a word, a
number, an HTTP status and reason — so a measurement can never carry mail content.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator

import pytest

from gmail_mcp import client as client_module
from gmail_mcp import scope as scope_module

from ._support import LiveRecord

_MEASUREMENTS = pytest.StashKey[list[tuple[str, str, str]]]()
# A measurement is a word or a number ("rotates", "stable", "404 notFound", "3"): never text
# that came out of a message.
_VALUE_RE = re.compile(r"[A-Za-z0-9_]{1,64}(?: [A-Za-z0-9_]{1,64}){0,3}")
_LABEL_RE = re.compile(r"[A-Za-z0-9 _.,:/()-]{1,120}")


@pytest.fixture(autouse=True)
async def _one_client_per_test() -> AsyncIterator[None]:
    """A fresh client and scope guard for the test, closed in the test's own event loop."""
    client_module.reset_client()
    scope_module.reset_scope()
    try:
        yield
    finally:
        used = client_module._client  # the singleton this test created, if any
        client_module.reset_client()
        scope_module.reset_scope()
        if used is not None:
            await used.aclose()


@pytest.fixture
def live_record(request: pytest.FixtureRequest) -> LiveRecord:
    """`record(label, value)`: keep one measurement of this test (see the module docstring)."""

    def record(label: str, value: str) -> None:
        if not _LABEL_RE.fullmatch(label):
            raise ValueError("a live measurement's label is a short fixed phrase")
        if not _VALUE_RE.fullmatch(value):
            raise ValueError("a live measurement is a word or a number, never text from the mailbox")
        print(value)
        request.node.user_properties.append((label, value))
        request.config.stash.setdefault(_MEASUREMENTS, []).append((request.node.nodeid, label, value))

    return record


def pytest_terminal_summary(terminalreporter: pytest.TerminalReporter, config: pytest.Config) -> None:
    measured = config.stash.get(_MEASUREMENTS, [])
    if not measured:
        return
    terminalreporter.section("live measurements")
    for nodeid, label, value in measured:
        terminalreporter.write_line(f"{nodeid} — {label}: {value}")
