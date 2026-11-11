"""gmail_health against a MockTransport Google: the exemplar tool, its pin and its scope report."""

from __future__ import annotations

import pytest
from mcp.server.fastmcp.exceptions import ToolError
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import TextContent

from gmail_mcp.auth import READONLY_SCOPE
from gmail_mcp.server import mcp
from gmail_mcp.tools.health import SPAM_TRASH_LINE, gmail_health

from .fakes import (
    ACCOUNT,
    FAKE_CLIENT_SECRET,
    FAKE_REFRESH_TOKEN,
    GMAIL_MODIFY,
    OTHER_ACCOUNT,
    FakeGoogle,
    fake_access_token,
    install,
    oauth_error,
)

PROFILE = "GET users/me/profile"
LABELS = "GET users/me/labels"


def _no_secrets(text: str) -> None:
    for secret in (FAKE_REFRESH_TOKEN, FAKE_CLIENT_SECRET, fake_access_token(1)):
        assert secret not in text


async def test_health_reports_the_pinned_mailbox_scopes_and_no_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(scope=f"{READONLY_SCOPE} openid")
    install(fake, monkeypatch)

    result = await gmail_health()

    assert result.startswith("# Gmail health")
    assert f"- **mailbox**: {ACCOUNT}" in result
    assert f"- **pin**: OK — the token belongs to GMAIL_ACCOUNT ({ACCOUNT})" in result
    assert "- **messagesTotal**: 42" in result
    assert "- **threadsTotal**: 17" in result
    assert f"- **granted scopes**: {READONLY_SCOPE}, openid (gmail.readonly plus identity only: openid)" in result
    assert "- **scope**: none — every message in the mailbox except spam and trash" in result
    assert SPAM_TRASH_LINE in result
    assert "- **body cap**: 20000 characters" in result
    assert "25.0 MiB each" in result
    assert "amazing-gmail-mcp" in result and "read-only: GET requests only" in result
    assert fake.log == ["token", PROFILE]  # no scope: no labels.list
    _no_secrets(result)


async def test_health_reports_an_active_label_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle()
    install(fake, monkeypatch, GMAIL_SCOPE_LABEL="Projects/Acme")

    result = await gmail_health()

    assert "- **scope**: label — a filter on what tools show, not a security boundary" in result
    assert "- **scope label**: `Projects/Acme` (id `Label_1`)" in result
    assert SPAM_TRASH_LINE in result
    assert "(gmail.readonly only)" in result
    assert fake.log == ["token", PROFILE, LABELS]


def test_the_spam_and_trash_line_says_what_the_code_does() -> None:
    # The wording promises three things; each has its own test elsewhere.
    assert "left out of every search (whatever the query)" in SPAM_TRASH_LINE  # scope.apply: -in:spam -in:trash
    assert "refused when read by id" in SPAM_TRASH_LINE  # scope.check_message, every mode
    assert "left out of every thread" in SPAM_TRASH_LINE  # gmail_get_thread, gmail_search_threads


async def test_health_reports_an_active_query_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    install(FakeGoogle(), monkeypatch, GMAIL_SCOPE_QUERY="from:example.com")

    result = await gmail_health()

    assert "- **scope**: query" in result
    assert "- **scope query**: `(from:example.com)`, ANDed with every search" in result


async def test_health_reports_both_scopes(monkeypatch: pytest.MonkeyPatch) -> None:
    install(FakeGoogle(), monkeypatch, GMAIL_SCOPE_LABEL="Label_2", GMAIL_SCOPE_QUERY="has:attachment")

    result = await gmail_health()

    assert "- **scope**: both" in result
    assert "`Receipts` (id `Label_2`)" in result
    assert "`(has:attachment)`" in result


async def test_health_fails_on_a_pin_mismatch_and_reads_nothing_else(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(profile_email=OTHER_ACCOUNT)
    install(fake, monkeypatch, GMAIL_SCOPE_LABEL="Projects/Acme")

    with pytest.raises(ToolError) as info:
        await gmail_health()

    message = str(info.value)
    assert f"pinned to GMAIL_ACCOUNT={ACCOUNT}" in message
    assert f"belongs to {OTHER_ACCOUNT}" in message
    assert "every tool is disabled" in message
    assert fake.log == ["token", PROFILE]  # the scope label was never resolved
    with pytest.raises(ToolError):
        await gmail_health()
    assert fake.log == ["token", PROFILE]
    _no_secrets(message)


async def test_health_refuses_a_token_that_can_do_more(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(scope=f"{READONLY_SCOPE} {GMAIL_MODIFY}")
    install(fake, monkeypatch)

    with pytest.raises(ToolError) as info:
        await gmail_health()

    assert f"this entry is read-only; its token can do more ({GMAIL_MODIFY})" in str(info.value)
    assert fake.log == ["token"]  # not even the profile is read


async def test_health_reports_a_dead_refresh_token(monkeypatch: pytest.MonkeyPatch) -> None:
    install(FakeGoogle(token_responses=[oauth_error("invalid_grant")]), monkeypatch)

    with pytest.raises(ToolError) as info:
        await gmail_health()

    assert f"the refresh token for {ACCOUNT} is no longer valid" in str(info.value)
    assert "\n" not in str(info.value)


async def test_health_refuses_an_unknown_scope_label(monkeypatch: pytest.MonkeyPatch) -> None:
    install(FakeGoogle(), monkeypatch, GMAIL_SCOPE_LABEL="Projects/Nope")

    with pytest.raises(ToolError, match="GMAIL_SCOPE_LABEL=Projects/Nope matches no label"):
        await gmail_health()


async def test_health_through_an_mcp_session(monkeypatch: pytest.MonkeyPatch) -> None:
    install(FakeGoogle(), monkeypatch)

    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool("gmail_health", {})

    assert result.isError is False
    [content] = result.content
    assert isinstance(content, TextContent)
    assert content.text.startswith("# Gmail health")
    _no_secrets(content.text)


async def test_a_pin_mismatch_through_an_mcp_session_is_an_is_error_result(monkeypatch: pytest.MonkeyPatch) -> None:
    install(FakeGoogle(profile_email=OTHER_ACCOUNT), monkeypatch)

    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool("gmail_health", {})

    assert result.isError is True
    [content] = result.content
    assert isinstance(content, TextContent)
    assert "every tool is disabled" in content.text
    assert "Traceback" not in content.text
