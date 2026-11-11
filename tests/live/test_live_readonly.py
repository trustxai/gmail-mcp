"""Read-only integration tests against the REAL mailbox (task t6 runs them; never CI).

Skipped unless GMAIL_REFRESH_TOKEN is set (shell or `.env`), together with GMAIL_ACCOUNT and
the client (GMAIL_CLIENT_SECRET_FILE, or GMAIL_CLIENT_ID + GMAIL_CLIENT_SECRET):

    uv run pytest -m live -rP

Every call here is a GET (the client cannot send anything else), so these tests can read
the mailbox but never change it. No assertion prints a header, a body, an address or a
token. Each test gets its own Gmail client (tests/live/conftest.py): the process-wide one
would carry an httpx pool bound to the previous test's event loop. Each runs inside
`bounded()`, so a request that never answers fails the test instead of hanging the run. The
rest of the live suite, and its privacy rules, are in the other modules of this package (see
_support.py).
"""

from __future__ import annotations

import pytest

from gmail_mcp.auth import ALLOWED_SCOPES, READONLY_SCOPE
from gmail_mcp.client import get_client
from gmail_mcp.config import get_settings
from gmail_mcp.errors import MethodNotAllowedError
from gmail_mcp.scope import get_scope
from gmail_mcp.tools.health import gmail_health

from ._support import bounded

pytestmark = pytest.mark.live


async def test_live_the_token_is_gmail_readonly_only() -> None:
    async with bounded():
        client = get_client()
        await client.pinned_profile()
        granted = set(client.auth.granted_scopes)
        assert READONLY_SCOPE in granted
        assert granted <= ALLOWED_SCOPES


async def test_live_the_account_pin_matches() -> None:
    async with bounded():
        profile = await get_client().pinned_profile()
        # Compared into a bool: a failing `==` on the two addresses would print them.
        matches = str(profile.get("emailAddress", "")).lower() == get_settings().account_email.lower()
        assert matches, "the profile's emailAddress is not GMAIL_ACCOUNT"
        assert int(profile.get("messagesTotal", 0)) >= 0


async def test_live_health_reports_ok() -> None:
    async with bounded():
        result = await gmail_health()
        # Checked into bools: a failing `in` would print the whole result (the mailbox address).
        pin_ok = "- **pin**: OK" in result
        readonly = "(gmail.readonly" in result
        assert pin_ok, "gmail_health does not report the pin OK"
        assert readonly, "gmail_health does not report a gmail.readonly grant"


async def test_live_labels_can_be_listed() -> None:
    async with bounded():
        body = await get_client().get("users/me/labels")
        ids = {label.get("id") for label in body.get("labels", [])}
        assert "INBOX" in ids


async def test_live_a_scoped_search_runs() -> None:
    async with bounded():
        params = await get_scope().apply({"maxResults": 1}, query=None)
        assert params["includeSpamTrash"] is False
        body = await get_client().get("users/me/messages", params)
        assert isinstance(body.get("resultSizeEstimate", 0), int)


async def test_live_the_first_search_hit_passes_its_scope_check() -> None:
    async with bounded():
        params = await get_scope().apply({"maxResults": 1}, query=None)
        listed = await get_client().get("users/me/messages", params)
        messages = listed.get("messages") or []
        if not messages:
            pytest.skip("the scope has no messages to check")
        message = await get_client().get(
            f"users/me/messages/{messages[0]['id']}", {"format": "metadata", "metadataHeaders": ["Message-ID"]}
        )
        assert await get_scope().check_message(message) is True


async def test_live_a_write_is_refused_before_it_is_sent() -> None:
    async with bounded():
        with pytest.raises(MethodNotAllowedError):
            await get_client().request("POST", "users/me/drafts")
