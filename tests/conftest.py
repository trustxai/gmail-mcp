"""Shared pytest configuration: live-test gating + settings isolation.

- `live` tests (read-only, against the real mailbox) run only when GMAIL_REFRESH_TOKEN is
  set in the shell or in `.env`; otherwise they are skipped. The standard gate deselects
  them anyway (`-m "not live"`).
- Every other test runs with no ambient `GMAIL_*` variable, from an empty temporary cwd
  (so `Settings(env_file=".env")` finds nothing), and with every cache reset: settings,
  the client singleton (token cache and account pin), the scope singleton, and the
  registry of secrets to redact.
"""

from __future__ import annotations

import os

import pytest
from dotenv import load_dotenv

from gmail_mcp import client as client_module
from gmail_mcp import scope as scope_module
from gmail_mcp.config import get_settings
from gmail_mcp.errors import clear_secrets

# Load .env so live tests can pick up the real configuration; non-live tests are isolated
# from it by the autouse fixture below.
load_dotenv()


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    has_token = bool(os.environ.get("GMAIL_REFRESH_TOKEN"))
    skip_live = pytest.mark.skip(reason="live tests require GMAIL_REFRESH_TOKEN in the environment / .env")
    for item in items:
        if item.get_closest_marker("live") is not None and not has_token:
            item.add_marker(skip_live)


def reset_caches() -> None:
    get_settings.cache_clear()
    client_module.reset_client()
    scope_module.reset_scope()
    clear_secrets()


@pytest.fixture(autouse=True)
def _isolate_settings_env(
    request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    if request.node.get_closest_marker("live") is not None:
        return
    for key in list(os.environ):
        if key.startswith("GMAIL_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.chdir(tmp_path_factory.mktemp("isolated-cwd"))
    reset_caches()
    request.addfinalizer(reset_caches)
