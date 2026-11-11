"""gmail_list_labels against a MockTransport Google: order, types, the scope mark, and refusals."""

from __future__ import annotations

from typing import Any

import pytest
from mcp.server.fastmcp.exceptions import ToolError
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import TextContent

import gmail_mcp.tools.labels as module
from gmail_mcp.auth import READONLY_SCOPE
from gmail_mcp.scope import ResolvedScope
from gmail_mcp.server import mcp
from gmail_mcp.tools.labels import EMPTY_LINE, SCOPE_MARK, gmail_list_labels, render_labels

from .fakes import (
    FAKE_CLIENT_SECRET,
    FAKE_REFRESH_TOKEN,
    GMAIL_MODIFY,
    OTHER_ACCOUNT,
    FakeGoogle,
    api_error,
    fake_access_token,
    install,
    oauth_error,
)

PROFILE = "GET users/me/profile"
LABELS = "GET users/me/labels"
NO_SCOPE = ResolvedScope("none", None, None, None)

# Deliberately out of order, mixed case, system labels interleaved with user ones.
SHUFFLED: list[dict[str, Any]] = [
    {"id": "Label_9", "name": "Zeta", "type": "user"},
    {"id": "STARRED", "name": "STARRED", "type": "system"},
    {"id": "Label_3", "name": "Alpha", "type": "user"},
    {"id": "INBOX", "name": "INBOX", "type": "system"},
    {"id": "Label_5", "name": "beta", "type": "user"},
    {"id": "CATEGORY_UPDATES", "name": "CATEGORY_UPDATES", "type": "system"},
]


def _label_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.startswith("- ")]


def _no_secrets(text: str) -> None:
    for secret in (FAKE_REFRESH_TOKEN, FAKE_CLIENT_SECRET, fake_access_token(1)):
        assert secret not in text


# --- registration --------------------------------------------------------------------------


async def test_list_labels_is_registered_read_only_and_takes_no_arguments() -> None:
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    tool = tools["gmail_list_labels"]
    assert mcp._tool_manager.get_tool("gmail_list_labels").fn.__module__ == module.__name__
    assert tool.annotations is not None
    assert tool.annotations.readOnlyHint is True
    assert tool.annotations.destructiveHint is False
    assert tool.annotations.openWorldHint is True
    assert tool.inputSchema.get("properties") == {}
    description = tool.description or ""
    sections = ["When to Use:", "When NOT to Use:", "Returns:", "Examples:", "Error Handling:"]
    positions = [description.find(section) for section in sections]
    assert all(position > 0 for position in positions) and positions == sorted(positions)


# --- positive ----------------------------------------------------------------------------


async def test_lists_system_labels_first_then_user_labels_each_by_name(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(routes={"users/me/labels": {"labels": SHUFFLED}})
    install(fake, monkeypatch)

    result = await gmail_list_labels()

    assert result.startswith("# Gmail labels (6: 3 system, 3 user)")
    assert _label_lines(result) == [
        "- `CATEGORY_UPDATES` · id `CATEGORY_UPDATES` · system",
        "- `INBOX` · id `INBOX` · system",
        "- `STARRED` · id `STARRED` · system",
        "- `Alpha` · id `Label_3` · user",
        "- `beta` · id `Label_5` · user",
        "- `Zeta` · id `Label_9` · user",  # "Zeta" < "beta" byte-wise: the sort folds case
    ]
    assert "No scope label: searches cover the whole mailbox" in result
    assert SCOPE_MARK not in result
    assert fake.log == ["token", PROFILE, LABELS]
    _no_secrets(result)


async def test_marks_the_scope_label_named_by_its_name_and_only_it(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle()
    install(fake, monkeypatch, GMAIL_SCOPE_LABEL="Projects/Acme")

    result = await gmail_list_labels()

    marked = [line for line in _label_lines(result) if SCOPE_MARK in line]
    assert marked == [f"- `Projects/Acme` · id `Label_1` · user · {SCOPE_MARK}"]
    assert "Scope label: `Projects/Acme` (id `Label_1`) — a filter on what tools show" in result
    # The scope resolves once (labels.list), then the listing reads labels.list again.
    assert fake.log == ["token", PROFILE, LABELS, LABELS]


async def test_marks_the_scope_label_named_by_its_id(monkeypatch: pytest.MonkeyPatch) -> None:
    install(FakeGoogle(), monkeypatch, GMAIL_SCOPE_LABEL="Label_2")

    result = await gmail_list_labels()

    assert [line for line in _label_lines(result) if SCOPE_MARK in line] == [
        f"- `Receipts` · id `Label_2` · user · {SCOPE_MARK}"
    ]


async def test_a_query_scope_marks_no_label_and_says_so(monkeypatch: pytest.MonkeyPatch) -> None:
    install(FakeGoogle(), monkeypatch, GMAIL_SCOPE_QUERY="from:example.com")

    result = await gmail_list_labels()

    assert "No scope label (the project scope is the query `(from:example.com)`)." in result
    assert SCOPE_MARK not in result
    assert len(_label_lines(result)) == 5


async def test_the_label_scope_does_not_hide_other_label_names(monkeypatch: pytest.MonkeyPatch) -> None:
    install(FakeGoogle(), monkeypatch, GMAIL_SCOPE_LABEL="Receipts")

    result = await gmail_list_labels()

    assert "`Projects/Acme` · id `Label_1` · user" in result  # a filter on messages, not on labels


async def test_list_labels_through_an_mcp_session(monkeypatch: pytest.MonkeyPatch) -> None:
    install(FakeGoogle(), monkeypatch)

    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool("gmail_list_labels", {})

    assert result.isError is False
    [content] = result.content
    assert isinstance(content, TextContent)
    assert content.text.startswith("# Gmail labels (5: 3 system, 2 user)")
    _no_secrets(content.text)


# --- negative ----------------------------------------------------------------------------


async def test_an_empty_mailbox_renders_a_clear_line(monkeypatch: pytest.MonkeyPatch) -> None:
    install(FakeGoogle(routes={"users/me/labels": {}}), monkeypatch)  # Gmail omits an empty list

    result = await gmail_list_labels()

    assert result.startswith("# Gmail labels (0: 0 system, 0 user)")
    assert EMPTY_LINE in result
    assert _label_lines(result) == []


async def test_an_explicit_empty_list_renders_the_same_line(monkeypatch: pytest.MonkeyPatch) -> None:
    install(FakeGoogle(routes={"users/me/labels": {"labels": []}}), monkeypatch)

    assert EMPTY_LINE in await gmail_list_labels()


async def test_malformed_label_entries_are_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    labels: list[Any] = [
        "INBOX",
        {"name": "no id", "type": "user"},
        {"id": "", "name": "empty id", "type": "user"},
        {"id": 7, "name": "numeric id", "type": "user"},
        {"id": "Label_4", "name": "Kept", "type": "user"},
    ]
    install(FakeGoogle(routes={"users/me/labels": {"labels": labels}}), monkeypatch)

    result = await gmail_list_labels()

    assert _label_lines(result) == ["- `Kept` · id `Label_4` · user"]


def test_a_missing_or_unknown_type_counts_as_user_and_a_missing_name_shows_the_id() -> None:
    labels: list[dict[str, Any]] = [
        {"id": "Label_7", "name": "Typeless"},
        {"id": "Label_8", "name": "Odd", "type": "weird"},
        {"id": "Label_6"},
        {"id": "SENT", "name": "SENT", "type": "SYSTEM"},
    ]

    lines = _label_lines(render_labels(labels, NO_SCOPE))

    assert lines == [
        "- `SENT` · id `SENT` · system",
        "- `Label_6` · id `Label_6` · user",
        "- `Odd` · id `Label_8` · user",
        "- `Typeless` · id `Label_7` · user",
    ]


def test_a_label_name_with_newlines_stays_on_one_line() -> None:
    labels = [{"id": "Label_1", "name": "Line one\n- `fake` · id `INBOX` · system", "type": "user"}]

    lines = _label_lines(render_labels(labels, NO_SCOPE))

    assert lines == ["- `Line one - `fake` · id `INBOX` · system` · id `Label_1` · user"]


def test_a_scope_label_missing_from_the_list_is_called_out() -> None:
    scope = ResolvedScope("label", "Label_99", "Gone", None)

    result = render_labels([{"id": "INBOX", "name": "INBOX", "type": "system"}], scope)

    assert SCOPE_MARK not in result
    assert "Note: the scope label (id `Label_99`) is not in this list any more" in result


async def test_refuses_an_unknown_scope_label(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle()
    install(fake, monkeypatch, GMAIL_SCOPE_LABEL="Projects/Nope")

    with pytest.raises(ToolError, match="GMAIL_SCOPE_LABEL=Projects/Nope matches no label"):
        await gmail_list_labels()
    assert fake.log == ["token", PROFILE, LABELS]  # the listing itself never ran


async def test_a_pin_mismatch_fails_and_lists_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(profile_email=OTHER_ACCOUNT)
    install(fake, monkeypatch)

    with pytest.raises(ToolError) as info:
        await gmail_list_labels()

    assert "every tool is disabled" in str(info.value)
    assert fake.log == ["token", PROFILE]
    _no_secrets(str(info.value))


async def test_refuses_a_token_that_can_do_more(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(scope=f"{READONLY_SCOPE} {GMAIL_MODIFY}")
    install(fake, monkeypatch)

    with pytest.raises(ToolError, match="this entry is read-only; its token can do more"):
        await gmail_list_labels()
    assert fake.log == ["token"]


async def test_a_dead_refresh_token_is_one_clear_line(monkeypatch: pytest.MonkeyPatch) -> None:
    install(FakeGoogle(token_responses=[oauth_error("invalid_grant")]), monkeypatch)

    with pytest.raises(ToolError) as info:
        await gmail_list_labels()

    assert "is no longer valid" in str(info.value)
    assert "\n" not in str(info.value)


async def test_a_gmail_error_is_one_line_with_the_fix(monkeypatch: pytest.MonkeyPatch) -> None:
    install(FakeGoogle(routes={"users/me/labels": api_error(403, "domainPolicy", "Blocked")}), monkeypatch)

    with pytest.raises(ToolError) as info:
        await gmail_list_labels()

    message = str(info.value)
    assert message.startswith("Gmail API error 403 (domainPolicy)")
    assert "API controls" in message
    assert "Traceback" not in message and "\n" not in message


async def test_an_error_through_an_mcp_session_is_an_is_error_result(monkeypatch: pytest.MonkeyPatch) -> None:
    install(FakeGoogle(profile_email=OTHER_ACCOUNT), monkeypatch)

    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool("gmail_list_labels", {})

    assert result.isError is True
    [content] = result.content
    assert isinstance(content, TextContent)
    assert "every tool is disabled" in content.text
    assert "Traceback" not in content.text
