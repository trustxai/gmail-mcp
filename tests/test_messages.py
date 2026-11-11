"""tools/messages.py — gmail_search_messages and gmail_get_message against a MockTransport Google.

Half of these tests (at least) are negative cases, named `test_refuses_…`, `test_out_of_scope_…`,
`test_not_found_…`, `test_fails_…` or `test_empty_…`: the scope is a filter, and the ways a
tool could skip it, leak through it or misreport an error matter more than the happy path.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import re
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
from mcp.server.fastmcp.exceptions import ToolError
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import TextContent
from pydantic import ValidationError

import gmail_mcp.tools.messages as messages_module
from gmail_mcp.config import MAX_BODY_MAX_CHARS
from gmail_mcp.errors import GmailApiError, NotFoundInScopeError, describe_error, redact, register_secret
from gmail_mcp.formatters import MAX_HEADER_CHARS, MAX_RESPONSE_BYTES, fit_page
from gmail_mcp.scope import EXCLUDE_SPAM_TRASH
from gmail_mcp.server import mcp
from gmail_mcp.tools.messages import (
    GetMessageInput,
    SearchMessagesInput,
    gmail_get_message,
    gmail_search_messages,
)
from gmail_mcp.validators import (
    MAX_QUERY_CHARS,
    MAX_QUERY_ENCODED,
    MAX_REQUEST_TARGET,
    MAX_SCOPE_QUERY_CHARS,
    MAX_SCOPE_QUERY_ENCODED,
    query_problem,
)

from .fakes import (
    CJK,
    DEFAULT_HEADERS,
    FAKE_CLIENT_SECRET,
    FAKE_REFRESH_TOKEN,
    FOUR_BYTES,
    GMAIL_REQUEST_TARGET_LIMIT,
    OTHER_ACCOUNT,
    OVERLONG,
    SHAPELESS_SECRET,
    FakeGoogle,
    api_error,
    attachment_part,
    fake_access_token,
    header,
    install,
    longest_request_target,
    message,
    multipart,
    text_of_encoded_size,
    text_part,
    worst_labels,
    worst_message,
)

MID = "18c2f0e9a1b2c3d4"
MID2 = "18c2f0e9a1b2c3d5"
TID = "18c2f0e9a1b2c300"
RFC822 = "msg-0001@mail.example.com"
SCOPE_QUERY = "from:example.com"
PAGE_TOKEN = "04567890123456789012"
NEXT_TOKEN = "09876543210987654321"

PROFILE = "GET users/me/profile"
LABELS = "GET users/me/labels"
LIST = "GET users/me/messages"

ESCAPES = [
    ") OR from:x (",
    "invoice) OR (in:anywhere",
    "(unclosed",
    "{from:x",
    '"unterminated ) OR from:x (',
    "( { ) OR from:bank ( } )",
    "({)}",
]
# What a message shows that must never reach an error about it.
LEAKS = ["Ada", "ada@example.com", "Quarterly", RFC822]


def _get(message_id: str = MID) -> str:
    return f"GET users/me/messages/{message_id}"


def _meta(
    message_id: str = MID,
    *,
    thread_id: str = TID,
    subject: str = "Quarterly numbers",
    sender: str = "Ada <ada@example.com>",
    labels: list[str] | None = None,
    snippet: str = "Here are the numbers",
    internal_date: str | None = "1794308400000",
) -> dict[str, Any]:
    """A `messages.get?format=metadata` object (headers only, no body)."""
    body: dict[str, Any] = {
        "id": message_id,
        "threadId": thread_id,
        "labelIds": ["INBOX", "UNREAD"] if labels is None else labels,
        "snippet": snippet,
        "payload": {
            "mimeType": "text/plain",
            "headers": [
                header("From", sender),
                header("Subject", subject),
                header("Date", "Tue, 10 Nov 2026 10:00:00 +0000"),
            ],
        },
    }
    if internal_date is not None:
        body["internalDate"] = internal_date
    return body


def _listing(*ids: str, next_token: str | None = None, estimate: int | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {
        "messages": [{"id": ident, "threadId": TID} for ident in ids],
        "resultSizeEstimate": len(ids) if estimate is None else estimate,
    }
    if next_token is not None:
        body["nextPageToken"] = next_token
    return body


def _search_fake(*ids: str, **routes: Any) -> FakeGoogle:
    table: dict[str, Any] = {"users/me/messages": _listing(*ids)}
    table.update({f"users/me/messages/{ident}": _meta(ident) for ident in ids})
    table.update({key.replace("__", "/"): value for key, value in routes.items()})
    return FakeGoogle(routes=table)


def _requests_to(fake: FakeGoogle, path: str) -> list[httpx.Request]:
    return [request for request in fake.api_requests if request.url.path.endswith(f"/gmail/v1/{path}")]


def _params(request: httpx.Request) -> dict[str, list[str]]:
    return parse_qs(request.url.query.decode(), keep_blank_values=True)


def _list_params(fake: FakeGoogle) -> dict[str, list[str]]:
    [request] = _requests_to(fake, "users/me/messages")
    return _params(request)


def _lookup(*ids: str) -> dict[str, Any]:
    return {"messages": [{"id": ident, "threadId": ident} for ident in ids], "resultSizeEstimate": len(ids)}


def _no_secrets(text: str) -> None:
    for secret in (FAKE_REFRESH_TOKEN, FAKE_CLIENT_SECRET, fake_access_token(1)):
        assert secret not in text


def _no_leak(text: str) -> None:
    for value in LEAKS:
        assert value not in text, value


async def _not_found_text(monkeypatch: pytest.MonkeyPatch, fake: FakeGoogle, **env: str) -> str:
    install(fake, monkeypatch, **env)
    with pytest.raises(ToolError) as info:
        await gmail_get_message(GetMessageInput(message_id=MID))
    return str(info.value)


# --- the tool contract ------------------------------------------------------------------------


async def test_both_tools_are_registered_with_the_house_annotations() -> None:
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    for name in ("gmail_search_messages", "gmail_get_message"):
        annotations = tools[name].annotations
        assert annotations is not None, name
        assert annotations.readOnlyHint is True
        assert annotations.destructiveHint is False
        assert annotations.openWorldHint is True
        assert annotations.idempotentHint is True
    assert (tools["gmail_search_messages"].description or "").startswith("Search messages with Gmail's query syntax")
    assert (tools["gmail_get_message"].description or "").startswith("Read one message")


@pytest.mark.parametrize(
    ("name", "model", "fields"),
    [
        ("gmail_search_messages", "SearchMessagesInput", {"query", "max_results", "page_token"}),
        ("gmail_get_message", "GetMessageInput", {"message_id", "offset"}),
    ],
)
async def test_each_tool_takes_one_params_model_that_forbids_extra_fields(
    name: str, model: str, fields: set[str]
) -> None:
    schema = {tool.name: tool for tool in await mcp.list_tools()}[name].inputSchema
    assert set(schema["properties"]) == {"params"}
    assert schema["required"] == ["params"]
    definition = schema["$defs"][model]
    assert definition["additionalProperties"] is False
    assert set(definition["properties"]) == fields


async def test_the_docstrings_have_every_house_section_in_order() -> None:
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    sections = ["When to Use:", "When NOT to Use:", "Returns:", "Examples:", "Error Handling:"]
    for name in ("gmail_search_messages", "gmail_get_message"):
        description = tools[name].description or ""
        positions = [description.find(section) for section in sections]
        assert all(position > 0 for position in positions), (name, positions)
        assert positions == sorted(positions), name


# --- gmail_search_messages: what it sends and shows ---------------------------------------------


async def test_search_lists_through_the_scope_and_renders_every_field(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _search_fake(MID, MID2)
    fake.routes["users/me/messages"] = _listing(MID, MID2, next_token=NEXT_TOKEN, estimate=57)
    install(fake, monkeypatch)

    result = await gmail_search_messages(SearchMessagesInput(query="  invoice   from:ada@example.com "))

    assert fake.log == ["token", PROFILE, LIST, _get(MID), _get(MID2)]
    assert _list_params(fake) == {
        "maxResults": ["20"],
        "q": [f"(invoice from:ada@example.com) {EXCLUDE_SPAM_TRASH}"],
        "includeSpamTrash": ["false"],
    }
    for request in _requests_to(fake, f"users/me/messages/{MID}"):
        assert _params(request) == {"format": ["metadata"], "metadataHeaders": ["From", "Subject", "Date"]}
    assert result.startswith("# Gmail search: `invoice from:ada@example.com`")
    assert "**2** message(s) on this page (Gmail estimates about 57 in total)." in result
    assert f"More available — pass `page_token` = `{NEXT_TOKEN}` to get the next page." in result
    assert "1. **Quarterly numbers** — from Ada <ada@example.com> · 2026-11-10 11:00 UTC" in result
    assert f"   id `{MID}` · threadId `{TID}` · labels: INBOX, UNREAD" in result
    assert "   snippet: Here are the numbers" in result
    assert "2. **Quarterly numbers**" in result and f"id `{MID2}`" in result
    assert "Scope:" not in result
    _no_secrets(result)


async def test_search_with_a_label_scope_sends_its_id_as_label_ids(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _search_fake(MID)
    install(fake, monkeypatch, GMAIL_SCOPE_LABEL="Projects/Acme")

    result = await gmail_search_messages(SearchMessagesInput(query="invoice"))

    assert fake.log == ["token", PROFILE, LABELS, LIST, _get(MID)]
    assert _list_params(fake) == {
        "maxResults": ["20"],
        "q": [f"(invoice) {EXCLUDE_SPAM_TRASH}"],
        "labelIds": ["Label_1"],
        "includeSpamTrash": ["false"],
    }
    assert "Scope: label `Projects/Acme` — results are limited to it" in result


async def test_search_with_a_query_scope_parenthesises_both_sides(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _search_fake(MID)
    install(fake, monkeypatch, GMAIL_SCOPE_QUERY=SCOPE_QUERY)

    result = await gmail_search_messages(SearchMessagesInput(query="invoice OR receipt"))

    assert _list_params(fake)["q"] == [f"({SCOPE_QUERY}) (invoice OR receipt) {EXCLUDE_SPAM_TRASH}"]
    assert _list_params(fake)["includeSpamTrash"] == ["false"]
    assert f"Scope: query `({SCOPE_QUERY})`" in result


async def test_search_with_both_scopes_sends_label_ids_and_the_composed_query(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _search_fake(MID)
    install(fake, monkeypatch, GMAIL_SCOPE_LABEL="Label_2", GMAIL_SCOPE_QUERY="has:attachment")

    result = await gmail_search_messages(SearchMessagesInput(query="invoice"))

    params = _list_params(fake)
    assert params["labelIds"] == ["Label_2"]
    assert params["q"] == [f"(has:attachment) (invoice) {EXCLUDE_SPAM_TRASH}"]
    assert "Scope: label `Receipts` + query `(has:attachment)`" in result


async def test_search_without_a_query_lists_the_newest_in_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _search_fake(MID)
    install(fake, monkeypatch, GMAIL_SCOPE_QUERY=SCOPE_QUERY)

    result = await gmail_search_messages(SearchMessagesInput())

    assert _list_params(fake)["q"] == [f"({SCOPE_QUERY}) {EXCLUDE_SPAM_TRASH}"]
    assert result.startswith("# Gmail search (no query: newest first)")


async def test_search_without_query_or_scope_still_excludes_spam_and_trash(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _search_fake(MID)
    install(fake, monkeypatch)

    await gmail_search_messages(SearchMessagesInput(query="   "))

    assert _list_params(fake)["q"] == [EXCLUDE_SPAM_TRASH]


@pytest.mark.parametrize("query", ["in:anywhere", "in:spam", "in:trash", "in:anywhere invoice"])
@pytest.mark.parametrize("scope", [{}, {"GMAIL_SCOPE_LABEL": "Projects/Acme"}, {"GMAIL_SCOPE_QUERY": SCOPE_QUERY}])
async def test_refuses_to_reach_spam_or_trash_with_a_query(
    monkeypatch: pytest.MonkeyPatch, query: str, scope: dict[str, str]
) -> None:
    fake = _search_fake(MID)
    install(fake, monkeypatch, **scope)

    await gmail_search_messages(SearchMessagesInput(query=query))

    sent = _list_params(fake)
    assert sent["q"][0].endswith(f"({query}) {EXCLUDE_SPAM_TRASH}")
    assert sent["includeSpamTrash"] == ["false"]


# LR-3: spam and trash are left out by the labels each hit carries too, as gmail_get_message,
# gmail_get_thread and gmail_search_threads do — not by Gmail's reading of the query alone.
MID3 = "18c2f0e9a1b2c3d6"
HIDDEN_NOTE = "message(s) Gmail listed on this page are in spam or trash: never shown, not counted above."
# What a hidden hit carries that must never reach the page.
HIDDEN_LEAKS = ("zq-hidden", "mallory@example.com", MID2, MID3)


def _hidden_meta(message_id: str, labels: Any) -> dict[str, Any]:
    meta = _meta(
        message_id,
        subject="zq-hidden subject",
        sender="Mallory <mallory@example.com>",
        snippet="zq-hidden words",
        thread_id=message_id,
    )
    meta["labelIds"] = labels
    return meta


@pytest.mark.parametrize("scope", [{}, {"GMAIL_SCOPE_LABEL": "Projects/Acme"}, {"GMAIL_SCOPE_QUERY": SCOPE_QUERY}])
async def test_refuses_to_show_hits_in_spam_or_trash_and_counts_them_in_one_line(
    monkeypatch: pytest.MonkeyPatch, scope: dict[str, str]
) -> None:
    fake = _search_fake(MID, MID2, MID3)
    fake.routes["users/me/messages"] = _listing(MID2, MID, MID3, next_token=NEXT_TOKEN)
    fake.routes[f"users/me/messages/{MID2}"] = _hidden_meta(MID2, ["TRASH"])
    fake.routes[f"users/me/messages/{MID3}"] = _hidden_meta(MID3, ["SPAM", "UNREAD"])
    install(fake, monkeypatch, **scope)

    result = await gmail_search_messages(SearchMessagesInput(query="invoice"))

    assert "**1** message(s) on this page" in result
    [note] = [line for line in result.splitlines() if HIDDEN_NOTE in line]
    assert note == f"2 {HIDDEN_NOTE}"
    assert "1. **Quarterly numbers** — from Ada <ada@example.com>" in result
    assert f"   id `{MID}` · threadId `{TID}`" in result
    assert not [line for line in result.splitlines() if line.startswith("2. ")]
    assert f"More available — pass `page_token` = `{NEXT_TOKEN}` to get the next page." in result
    for leak in HIDDEN_LEAKS:
        assert leak not in result, leak


async def test_empty_a_page_whose_every_hit_is_in_spam_or_trash_says_so_and_keeps_the_page_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeGoogle(
        routes={
            "users/me/messages": _listing(MID2, MID3, next_token=NEXT_TOKEN, estimate=9),
            f"users/me/messages/{MID2}": _hidden_meta(MID2, ["SPAM"]),
            f"users/me/messages/{MID3}": _hidden_meta(MID3, ["INBOX", "TRASH"]),
        }
    )
    install(fake, monkeypatch)

    result = await gmail_search_messages(SearchMessagesInput(query="invoice", page_token=PAGE_TOKEN))

    assert fake.log == ["token", PROFILE, LIST, _get(MID2), _get(MID3)]
    assert "**0** message(s) on this page (Gmail estimates about 9 in total)." in result
    assert f"2 {HIDDEN_NOTE}" in result
    assert "_Nothing on this page can be shown: every message Gmail listed is in spam or trash._" in result
    assert f"More available — pass `page_token` = `{NEXT_TOKEN}` to get the next page." in result
    assert "No messages matched" not in result and "past the last one" not in result
    for leak in HIDDEN_LEAKS:
        assert leak not in result, leak


@pytest.mark.parametrize("labels", ["SPAM", {"0": "INBOX"}, 7], ids=["string", "object", "number"])
async def test_refuses_to_show_a_hit_whose_labels_cannot_be_read(monkeypatch: pytest.MonkeyPatch, labels: Any) -> None:
    # Fail closed, as get_message and get_thread: labelIds that are not a list cannot prove "not spam".
    fake = _search_fake(MID, MID2)
    fake.routes[f"users/me/messages/{MID2}"] = _hidden_meta(MID2, labels)
    install(fake, monkeypatch)

    result = await gmail_search_messages(SearchMessagesInput())

    assert "**1** message(s) on this page" in result
    assert f"1 {HIDDEN_NOTE}" in result
    for leak in HIDDEN_LEAKS:
        assert leak not in result, leak


async def test_a_hit_whose_metadata_failed_stays_listed_next_to_a_hidden_one(monkeypatch: pytest.MonkeyPatch) -> None:
    # Its labels are unknown, but its row shows only the id and the cause; and one readable hit
    # (hidden or not) means the page is not a systemic failure.
    fake = _search_fake(MID, MID2)
    fake.routes[f"users/me/messages/{MID}"] = api_error(404, "notFound", "Requested entity was not found.")
    fake.routes[f"users/me/messages/{MID2}"] = _hidden_meta(MID2, ["TRASH"])
    install(fake, monkeypatch)

    result = await gmail_search_messages(SearchMessagesInput(query="invoice"))

    assert "**1** message(s) on this page" in result
    assert f"1 {HIDDEN_NOTE}" in result
    assert "1. _metadata unavailable_ — Gmail API error 404 (notFound): Requested entity was not found." in result
    assert f"   id `{MID}` · threadId `{TID}`" in result
    for leak in HIDDEN_LEAKS:
        assert leak not in result, leak


async def test_a_page_without_hidden_hits_has_no_spam_or_trash_note(monkeypatch: pytest.MonkeyPatch) -> None:
    install(_search_fake(MID, MID2), monkeypatch)

    result = await gmail_search_messages(SearchMessagesInput(query="invoice"))

    assert "spam or trash" not in result
    assert "**2** message(s) on this page" in result


# Each kind of text at both caps: wide text at the encoded caps, ASCII punctuation (3 each) at the
# character caps. Before the encoded caps, 1,500 4-byte characters loaded and broke every search.
def _at_caps(char: str) -> tuple[str, str]:
    if char == ":":
        return ":" * MAX_SCOPE_QUERY_CHARS, ":" * MAX_QUERY_CHARS
    return text_of_encoded_size(char, MAX_SCOPE_QUERY_ENCODED), text_of_encoded_size(char, MAX_QUERY_ENCODED)


CAP_CHARS = [FOUR_BYTES, CJK, "é", ":"]
CAP_IDS = ["4-byte", "CJK", "accented", "ascii"]


@pytest.mark.parametrize("char", CAP_CHARS, ids=CAP_IDS)
async def test_search_at_both_query_caps_fits_gmails_url_limit(monkeypatch: pytest.MonkeyPatch, char: str) -> None:
    scope, query = _at_caps(char)
    fake = _search_fake(MID)
    fake.max_request_target = GMAIL_REQUEST_TARGET_LIMIT
    install(fake, monkeypatch, GMAIL_SCOPE_QUERY=scope)

    result = await gmail_search_messages(SearchMessagesInput(query=query, page_token="=" * 1024))

    assert fake.log == ["token", PROFILE, LIST, _get(MID)]
    assert _list_params(fake)["q"] == [f"({scope}) ({query}) {EXCLUDE_SPAM_TRASH}"]
    assert longest_request_target(fake) <= MAX_REQUEST_TARGET
    assert "1. **Quarterly numbers**" in result


@pytest.mark.parametrize("char", CAP_CHARS, ids=CAP_IDS)
async def test_get_message_in_a_query_scope_at_the_cap_is_found_by_its_lookup(
    monkeypatch: pytest.MonkeyPatch, char: str
) -> None:
    # The review's second symptom: a lookup past Gmail's limit fails, so every id was "not found".
    scope, _ = _at_caps(char)
    rfc822 = ("!#$%&'*+/=?^" * 83)[:995]
    found = message(headers=[*DEFAULT_HEADERS[:-1], header("Message-ID", f"<{rfc822}>")])
    fake = FakeGoogle(
        routes={f"users/me/messages/{MID}": found, "users/me/messages": _lookup(MID)},
        max_request_target=GMAIL_REQUEST_TARGET_LIMIT,
    )
    install(fake, monkeypatch, GMAIL_SCOPE_QUERY=scope)

    result = await gmail_get_message(GetMessageInput(message_id=MID))

    assert fake.log == ["token", PROFILE, _get(MID), LIST]
    assert _list_params(fake)["q"] == [f"({scope}) rfc822msgid:{rfc822}"]
    assert longest_request_target(fake) <= MAX_REQUEST_TARGET
    assert f"# Gmail message `{MID}`" in result


async def test_fails_the_fake_front_end_refuses_a_request_past_gmails_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    # The control: the limit the two tests above run under does bite (the review's reproduction).
    fake = FakeGoogle(routes={"users/me/messages": {}}, max_request_target=GMAIL_REQUEST_TARGET_LIMIT)
    client = install(fake, monkeypatch)
    q = "a" * (GMAIL_REQUEST_TARGET_LIMIT - len("/gmail/v1/users/me/messages?q="))
    await client.get("users/me/messages", {"q": q})
    with pytest.raises(GmailApiError) as info:
        await client.get("users/me/messages", {"q": q + "a"})
    assert info.value.status == 400


async def test_search_passes_the_page_token_and_max_results(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _search_fake(MID)
    install(fake, monkeypatch)

    await gmail_search_messages(SearchMessagesInput(query="invoice", max_results=100, page_token=PAGE_TOKEN))

    params = _list_params(fake)
    assert params["maxResults"] == ["100"]
    assert params["pageToken"] == [PAGE_TOKEN]


@pytest.mark.parametrize("blank", [None, "", "   "])
async def test_search_treats_a_blank_page_token_as_the_first_page(monkeypatch: pytest.MonkeyPatch, blank: Any) -> None:
    fake = _search_fake(MID)
    install(fake, monkeypatch)

    params_in = SearchMessagesInput(query="invoice", page_token=blank, max_results="5")
    await gmail_search_messages(params_in)

    assert params_in.page_token is None
    assert "pageToken" not in _list_params(fake)
    assert _list_params(fake)["maxResults"] == ["5"]


async def test_search_decodes_encoded_headers_and_snippet_entities(monkeypatch: pytest.MonkeyPatch) -> None:
    encoded = "=?utf-8?b?" + base64.b64encode("Reunión mañana".encode()).decode() + "?="
    fake = _search_fake(MID)
    fake.routes[f"users/me/messages/{MID}"] = _meta(
        subject=encoded, sender="Ada\r\n  <ada@example.com>", snippet="it&#39;s &amp; done\nnext line"
    )
    install(fake, monkeypatch)

    result = await gmail_search_messages(SearchMessagesInput(query="reunion"))

    assert "**Reunión mañana** — from Ada <ada@example.com>" in result
    assert "   snippet: it's & done next line" in result


async def test_search_falls_back_to_the_date_header_without_internal_date(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _search_fake(MID)
    fake.routes[f"users/me/messages/{MID}"] = _meta(internal_date=None, labels=[], subject="", sender="", snippet="")
    install(fake, monkeypatch)

    result = await gmail_search_messages(SearchMessagesInput())

    assert "1. **(no subject)** — from (unknown sender) · Tue, 10 Nov 2026 10:00:00 +0000" in result
    assert "labels: none" in result
    assert "snippet:" not in result


async def test_search_metadata_fetches_never_exceed_ten_in_flight(monkeypatch: pytest.MonkeyPatch) -> None:
    in_flight = 0
    peak = 0
    ids = [f"{n:016x}" for n in range(1, 31)]

    async def slow(request: httpx.Request) -> httpx.Response:
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.005)
        in_flight -= 1
        return httpx.Response(200, json=_meta(request.url.path.rsplit("/", 1)[-1]))

    fake = FakeGoogle(routes={"users/me/messages": _listing(*ids), **{f"users/me/messages/{i}": slow for i in ids}})
    install(fake, monkeypatch)

    result = await gmail_search_messages(SearchMessagesInput(max_results=30))

    assert peak == 10
    assert "**30** message(s)" in result
    # Rendered in the order Gmail listed them, not in completion order.
    assert [line.split("`")[1] for line in result.splitlines() if line.startswith("   id `")] == ids


async def test_search_through_an_mcp_session(monkeypatch: pytest.MonkeyPatch) -> None:
    install(_search_fake(MID), monkeypatch)

    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool("gmail_search_messages", {"params": {"query": "invoice", "max_results": 5}})

    assert result.isError is False
    [content] = result.content
    assert isinstance(content, TextContent)
    assert content.text.startswith("# Gmail search: `invoice`")


# --- gmail_search_messages: refusals and failures ------------------------------------------------


@pytest.mark.parametrize("scope", [{}, {"GMAIL_SCOPE_LABEL": "Projects/Acme"}, {"GMAIL_SCOPE_QUERY": SCOPE_QUERY}])
@pytest.mark.parametrize("query", ESCAPES)
async def test_refuses_a_scope_escape_with_the_scopes_error_and_sends_nothing(
    monkeypatch: pytest.MonkeyPatch, query: str, scope: dict[str, str]
) -> None:
    # model_construct skips the params validators: the scope itself must still refuse it.
    fake = _search_fake(MID)
    install(fake, monkeypatch, **scope)
    bypass = SearchMessagesInput.model_construct(query=query, max_results=20, page_token=None)

    with pytest.raises(ToolError) as info:
        await gmail_search_messages(bypass)

    problem = query_problem(" ".join(query.split()))
    assert problem is not None
    assert str(info.value) == f"the search query is refused: {problem}"
    assert fake.requests == []  # not even a token refresh


@pytest.mark.parametrize("query", ESCAPES)
def test_refuses_a_scope_escape_in_the_params_model(query: str) -> None:
    with pytest.raises(ValidationError) as info:
        SearchMessagesInput(query=query)
    problem = query_problem(" ".join(query.split()))
    assert problem is not None and problem in str(info.value)


async def test_refuses_a_scope_escape_through_an_mcp_session_with_the_same_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = _search_fake(MID)
    install(fake, monkeypatch, GMAIL_SCOPE_LABEL="Projects/Acme")

    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool("gmail_search_messages", {"params": {"query": ") OR from:bank ("}})

    assert result.isError is True
    [content] = result.content
    assert isinstance(content, TextContent)
    problem = query_problem(") OR from:bank (")
    assert problem is not None and problem in content.text
    assert "from:bank" not in content.text  # the rejected input is not echoed
    assert "Traceback" not in content.text
    assert fake.requests == []


@pytest.mark.parametrize("value", [0, 101, -1, True, "abc", 1.5, None])
def test_refuses_max_results_outside_one_to_a_hundred(value: Any) -> None:
    with pytest.raises(ValidationError):
        SearchMessagesInput(max_results=value)


@pytest.mark.parametrize("value", ["has space", "../profile", "a" * 1025, "tok\nen", "x;y"])
def test_refuses_a_page_token_that_no_call_printed(value: str) -> None:
    with pytest.raises(ValidationError):
        SearchMessagesInput(page_token=value)


@pytest.mark.parametrize(
    "extra", [{"include_spam_trash": True}, {"labelIds": ["SPAM"]}, {"q": "in:anywhere"}, {"includeSpamTrash": True}]
)
def test_refuses_fields_the_model_does_not_have(extra: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        SearchMessagesInput.model_validate({"query": "invoice", **extra})


@pytest.mark.parametrize("query", ["a" * 1501, FOUR_BYTES * 1501, "subject:x\x00", "tab\x7fdelete"])
def test_refuses_an_overlong_or_control_character_query(query: str) -> None:
    with pytest.raises(ValidationError):
        SearchMessagesInput(query=query)


async def test_refuses_spam_and_trash_flags_through_an_mcp_session(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _search_fake(MID)
    install(fake, monkeypatch)

    async with create_connected_server_and_client_session(mcp) as session:
        extra = await session.call_tool("gmail_search_messages", {"params": {"includeSpamTrash": True}})
        flat = await session.call_tool("gmail_search_messages", {"query": "invoice"})

    assert extra.isError is True and flat.isError is True
    assert fake.requests == []


async def test_empty_results_say_so_and_fetch_no_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(routes={"users/me/messages": {"resultSizeEstimate": 0}})
    install(fake, monkeypatch)

    result = await gmail_search_messages(SearchMessagesInput(query="nothing-matches-this"))

    assert fake.log == ["token", PROFILE, LIST]
    assert "**0** message(s) on this page (Gmail estimates about 0 in total)." in result
    assert "_No messages matched._ Check the query syntax" in result
    assert "scope above" not in result
    assert "More available" not in result


async def test_empty_results_under_a_scope_point_at_the_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    install(FakeGoogle(routes={"users/me/messages": {"messages": []}}), monkeypatch, GMAIL_SCOPE_QUERY=SCOPE_QUERY)

    result = await gmail_search_messages(SearchMessagesInput(query="invoice"))

    assert "only messages inside the scope above are searched" in result


async def test_empty_page_after_a_page_token_says_it_is_past_the_last(monkeypatch: pytest.MonkeyPatch) -> None:
    install(FakeGoogle(routes={"users/me/messages": {"resultSizeEstimate": 3}}), monkeypatch)

    result = await gmail_search_messages(SearchMessagesInput(query="invoice", page_token=PAGE_TOKEN))

    assert "_No more messages: this page is past the last one._" in result


async def test_fails_one_hit_without_failing_the_page(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _search_fake(MID, MID2)
    fake.routes[f"users/me/messages/{MID2}"] = api_error(404, "notFound", "Requested entity was not found.")
    install(fake, monkeypatch)

    result = await gmail_search_messages(SearchMessagesInput(query="invoice"))

    assert "1. **Quarterly numbers**" in result
    assert "2. _metadata unavailable_ — Gmail API error 404 (notFound): Requested entity was not found." in result
    assert f"   id `{MID2}` · threadId `{TID}`" in result


async def test_fails_the_call_when_no_hit_is_readable(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _search_fake(MID, MID2)
    for ident in (MID, MID2):
        fake.routes[f"users/me/messages/{ident}"] = api_error(403, "insufficientPermissions", "Insufficient Permission")
    install(fake, monkeypatch)

    with pytest.raises(ToolError) as info:
        await gmail_search_messages(SearchMessagesInput(query="invoice"))

    assert "Gmail API error 403 (insufficientPermissions)" in str(info.value)
    assert "the token does not carry gmail.readonly" in str(info.value)
    assert "\n" not in str(info.value)


async def test_refuses_to_put_an_unusable_hit_id_into_a_path(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _search_fake(MID)
    fake.routes["users/me/messages"] = {"messages": [{"id": "../labels"}, {"id": MID}, {"id": None}, "junk"]}
    install(fake, monkeypatch)

    result = await gmail_search_messages(SearchMessagesInput())

    assert fake.log == ["token", PROFILE, LIST, _get(MID)]
    assert "**1** message(s) on this page." in result
    assert "2 hit(s) with an id this server cannot use were skipped." in result
    assert "../labels" not in result


async def test_fails_with_a_one_line_cause_when_gmail_rejects_the_list(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(routes={"users/me/messages": api_error(400, "invalidArgument", "Invalid pageToken")})
    install(fake, monkeypatch)

    with pytest.raises(ToolError) as info:
        await gmail_search_messages(SearchMessagesInput(query="invoice", page_token=PAGE_TOKEN))

    message = str(info.value)
    assert message.startswith("Gmail API error 400 (invalidArgument): Invalid pageToken.")
    assert "check the ids, the page token and the query syntax" in message
    assert "\n" not in message
    _no_secrets(message)


async def test_fails_on_a_pin_mismatch_and_lists_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _search_fake(MID)
    fake.routes["users/me/profile"] = {"emailAddress": OTHER_ACCOUNT}
    install(fake, monkeypatch)

    with pytest.raises(ToolError) as info:
        await gmail_search_messages(SearchMessagesInput(query="invoice"))

    assert "every tool is disabled" in str(info.value)
    assert f"belongs to {OTHER_ACCOUNT}" in str(info.value)
    assert fake.log == ["token", PROFILE]
    with pytest.raises(ToolError):
        await gmail_search_messages(SearchMessagesInput(query="invoice"))
    assert fake.log == ["token", PROFILE]  # the mismatch is remembered: nothing more is sent


async def test_fails_with_an_unknown_scope_label_and_lists_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _search_fake(MID)
    install(fake, monkeypatch, GMAIL_SCOPE_LABEL="Projects/Nope")

    with pytest.raises(ToolError, match="GMAIL_SCOPE_LABEL=Projects/Nope matches no label"):
        await gmail_search_messages(SearchMessagesInput(query="invoice"))

    assert fake.log == ["token", PROFILE, LABELS]


async def test_fails_redacting_a_token_shaped_snippet(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _search_fake(MID)
    fake.routes[f"users/me/messages/{MID}"] = _meta(snippet=f"your key is {fake_access_token(7)} keep it")
    install(fake, monkeypatch)

    result = await gmail_search_messages(SearchMessagesInput())

    assert fake_access_token(7) not in result
    assert "your key is *** keep it" in result


# --- gmail_get_message: what it sends and shows ---------------------------------------------------


async def test_get_message_renders_headers_body_and_attachments(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = multipart(
        "mixed",
        multipart("alternative", text_part("Hello Ops,\n\nthe numbers.", part_id="0.0"), part_id="0"),
        attachment_part("report.pdf", "application/pdf", 12345),
    )
    fake = FakeGoogle(routes={f"users/me/messages/{MID}": message(payload, thread_id=TID, labels=["INBOX", "Label_1"])})
    install(fake, monkeypatch)

    result = await gmail_get_message(GetMessageInput(message_id=MID))

    assert fake.log == ["token", PROFILE, _get(MID)]
    assert _params(fake.api_requests[1]) == {"format": ["full"]}
    assert result.startswith(f"# Gmail message `{MID}`")
    assert f"- **threadId**: `{TID}`" in result
    assert "- **labels**: INBOX, Label_1" in result
    assert "- **received**: 2026-11-10 11:00 UTC" in result
    for line in (
        "- **From**: Ada <ada@example.com>",
        "- **To**: ops@example.com",
        "- **Date**: Tue, 10 Nov 2026 10:00:00 +0000",
        "- **Subject**: Quarterly numbers",
        f"- **Message-ID**: <{RFC822}>",
    ):
        assert line in result
    assert "## Body (text/plain)" in result
    assert "[body: complete, 24 characters]" in result
    assert "```text\nHello Ops,\n\nthe numbers.\n```" in result
    assert "## Attachments (1)" in result
    assert "- report.pdf · application/pdf · 12.1 KiB (12345 bytes) · partId `1`" in result
    assert "ANGjdJ_FAKE_attachment_0001" not in result  # ADR-0002: the rotating attachmentId is never shown
    _no_secrets(result)


async def test_get_message_pages_the_body_with_offset(monkeypatch: pytest.MonkeyPatch) -> None:
    text = "".join(chr(ord("a") + n % 26) for n in range(250))
    fake = FakeGoogle(routes={f"users/me/messages/{MID}": message(text_part(text))})
    install(fake, monkeypatch, GMAIL_BODY_MAX_CHARS="100")

    first = await gmail_get_message(GetMessageInput(message_id=MID))
    second = await gmail_get_message(GetMessageInput(message_id=MID, offset=100))
    last = await gmail_get_message(GetMessageInput(message_id=MID, offset=200))

    assert "[body: characters 0–100 of 250; pass offset=100 for the next part]" in first
    assert f"```text\n{text[:100]}\n```" in first
    assert "[body: characters 100–200 of 250; pass offset=200 for the next part]" in second
    assert f"```text\n{text[100:200]}\n```" in second
    assert "[body: characters 200–250 of 250; end of the body]" in last
    assert f"```text\n{text[200:]}\n```" in last
    # The attachments are listed on every page.
    assert all("## Attachments (0)" in page for page in (first, second, last))


_FENCED = re.compile(r"```text\n(.*?)\n```", re.DOTALL)


@pytest.mark.parametrize("kind", ["token-shape", "registered-shapeless"])
async def test_a_secret_straddling_a_page_boundary_never_shows_a_part(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    secret = fake_access_token(5) if kind == "token-shape" else SHAPELESS_SECRET
    # Cut first at 100, page 1 would end on the secret's first 5 characters and page 2 would
    # start with the rest: neither half matches the shape pattern or the registered value.
    body = "a" * 95 + secret + " and the rest of the mail " + "z" * 150
    install(
        FakeGoogle(routes={f"users/me/messages/{MID}": message(text_part(body))}),
        monkeypatch,
        GMAIL_BODY_MAX_CHARS="100",
    )
    register_secret(SHAPELESS_SECRET)

    pages: list[str] = []
    offset: int | None = 0
    while offset is not None:
        page = await gmail_get_message(GetMessageInput(message_id=MID, offset=offset))
        pages.append(page)
        found = re.search(r"pass offset=(\d+) for the next part", page)
        offset = int(found.group(1)) if found else None

    shown = "".join(window for page in pages for window in _FENCED.findall(page))
    assert shown == redact(body)  # the offsets walk the redacted body, without gap or overlap
    assert pages[0].count("***") == 1 and shown.startswith("a" * 95 + "***")
    for fragment in (secret[:5], secret[5:], secret[-10:]):
        assert all(fragment not in page for page in pages), fragment


async def test_get_message_turns_an_html_only_body_into_text(monkeypatch: pytest.MonkeyPatch) -> None:
    html_part = text_part("<html><body><p>Hello <b>Ops</b></p><script>x()</script></body></html>", mime="text/html")
    install(FakeGoogle(routes={f"users/me/messages/{MID}": message(html_part)}), monkeypatch)

    result = await gmail_get_message(GetMessageInput(message_id=MID))

    assert "## Body (text/html, converted to text)" in result
    assert "```text\nHello Ops\n```" in result
    assert "x()" not in result


async def test_get_message_fences_a_body_longer_than_its_backtick_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    body = "run ```rm -rf``` and ````more````"
    install(FakeGoogle(routes={f"users/me/messages/{MID}": message(text_part(body))}), monkeypatch)

    result = await gmail_get_message(GetMessageInput(message_id=MID))

    assert f"`````text\n{body}\n`````" in result


async def test_get_message_in_the_label_scope_is_shown(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(routes={f"users/me/messages/{MID}": message(labels=["INBOX", "Label_1"])})
    install(fake, monkeypatch, GMAIL_SCOPE_LABEL="Projects/Acme")

    result = await gmail_get_message(GetMessageInput(message_id=MID))

    assert fake.log == ["token", PROFILE, LABELS, _get(MID)]
    assert "- **Subject**: Quarterly numbers" in result


async def test_get_message_in_the_query_scope_is_checked_by_rfc822msgid(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(routes={f"users/me/messages/{MID}": message(), "users/me/messages": _lookup(MID)})
    install(fake, monkeypatch, GMAIL_SCOPE_QUERY=SCOPE_QUERY)

    result = await gmail_get_message(GetMessageInput(message_id=MID))

    assert fake.log == ["token", PROFILE, _get(MID), LIST]
    assert _list_params(fake) == {
        "q": [f"({SCOPE_QUERY}) rfc822msgid:{RFC822}"],
        "includeSpamTrash": ["false"],
        "maxResults": ["25"],
    }
    assert "- **Subject**: Quarterly numbers" in result


async def test_get_message_through_an_mcp_session(monkeypatch: pytest.MonkeyPatch) -> None:
    install(FakeGoogle(routes={f"users/me/messages/{MID}": message()}), monkeypatch)

    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool("gmail_get_message", {"params": {"message_id": MID}})

    assert result.isError is False
    [content] = result.content
    assert isinstance(content, TextContent)
    assert content.text.startswith(f"# Gmail message `{MID}`")


# --- gmail_get_message: out of scope, not found, refused ------------------------------------------


async def test_out_of_scope_label_missing_is_not_found_without_any_header(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(routes={f"users/me/messages/{MID}": message(labels=["INBOX"])})

    text = await _not_found_text(monkeypatch, fake, GMAIL_SCOPE_LABEL="Projects/Acme")

    assert text == (
        f"message {MID} was not found in this mailbox scope. Check the id (search for it first) and the active scope "
        "(gmail_health)."
    )
    _no_leak(text)


@pytest.mark.parametrize("excluded", ["SPAM", "TRASH"])
async def test_out_of_scope_in_spam_or_trash_even_with_the_label(
    monkeypatch: pytest.MonkeyPatch, excluded: str
) -> None:
    fake = FakeGoogle(routes={f"users/me/messages/{MID}": message(labels=["Label_1", excluded])})

    text = await _not_found_text(monkeypatch, fake, GMAIL_SCOPE_LABEL="Projects/Acme")

    assert "was not found in this mailbox scope" in text
    _no_leak(text)


@pytest.mark.parametrize("excluded", ["SPAM", "TRASH"])
async def test_not_found_in_spam_or_trash_even_without_a_scope(monkeypatch: pytest.MonkeyPatch, excluded: str) -> None:
    fake = FakeGoogle(routes={f"users/me/messages/{MID}": message(labels=[excluded])})

    text = await _not_found_text(monkeypatch, fake)

    assert text == describe_error(NotFoundInScopeError("message", MID))
    _no_leak(text)


async def test_out_of_scope_query_lookup_without_the_message_is_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(routes={f"users/me/messages/{MID}": message(), "users/me/messages": _lookup(MID2)})

    text = await _not_found_text(monkeypatch, fake, GMAIL_SCOPE_QUERY=SCOPE_QUERY)

    assert "was not found in this mailbox scope" in text
    _no_leak(text)


async def test_out_of_scope_query_without_a_message_id_header_sends_no_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    headers = [entry for entry in DEFAULT_HEADERS if entry["name"] != "Message-ID"]
    fake = FakeGoogle(routes={f"users/me/messages/{MID}": message(headers=headers), "users/me/messages": _lookup(MID)})

    text = await _not_found_text(monkeypatch, fake, GMAIL_SCOPE_QUERY=SCOPE_QUERY)

    assert "was not found in this mailbox scope" in text
    assert fake.log == ["token", PROFILE, _get(MID)]


async def test_out_of_scope_when_the_query_lookup_fails_and_nothing_leaks_to_the_log(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    fake = FakeGoogle(
        routes={f"users/me/messages/{MID}": message(), "users/me/messages": api_error(400, "invalidArgument", RFC822)}
    )
    caplog.set_level(logging.DEBUG)

    text = await _not_found_text(monkeypatch, fake, GMAIL_SCOPE_QUERY=SCOPE_QUERY)

    assert "was not found in this mailbox scope" in text
    _no_leak(text)
    _no_leak(caplog.text)


async def test_out_of_scope_with_both_scopes_when_only_the_label_matches(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(routes={f"users/me/messages/{MID}": message(labels=["Label_1"]), "users/me/messages": _lookup()})

    text = await _not_found_text(monkeypatch, fake, GMAIL_SCOPE_LABEL="Label_1", GMAIL_SCOPE_QUERY=SCOPE_QUERY)

    assert "was not found in this mailbox scope" in text


async def test_not_found_a_404_reads_exactly_like_out_of_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    missing = await _not_found_text(monkeypatch, FakeGoogle(), GMAIL_SCOPE_LABEL="Projects/Acme")
    out = await _not_found_text(
        monkeypatch,
        FakeGoogle(routes={f"users/me/messages/{MID}": message(labels=["INBOX"])}),
        GMAIL_SCOPE_LABEL="Projects/Acme",
    )

    assert missing == out
    assert "404" not in missing


async def test_not_found_a_404_without_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle()

    text = await _not_found_text(monkeypatch, fake)

    assert text.startswith(f"message {MID} was not found in this mailbox scope.")
    assert fake.log == ["token", PROFILE, _get(MID)]


async def test_not_found_an_id_gmail_cannot_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(routes={f"users/me/messages/{MID}": api_error(400, "invalidArgument", "Invalid id value")})

    text = await _not_found_text(monkeypatch, fake)

    assert "was not found in this mailbox scope" in text
    assert "Invalid id value" not in text


async def test_not_found_when_gmail_returns_another_message(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(routes={f"users/me/messages/{MID}": message(message_id=MID2)})

    text = await _not_found_text(monkeypatch, fake)

    assert "was not found in this mailbox scope" in text
    _no_leak(text)


async def test_not_found_through_an_mcp_session_is_an_is_error_result(monkeypatch: pytest.MonkeyPatch) -> None:
    install(
        FakeGoogle(routes={f"users/me/messages/{MID}": message(labels=["INBOX"])}),
        monkeypatch,
        GMAIL_SCOPE_LABEL="Label_1",
    )

    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool("gmail_get_message", {"params": {"message_id": MID}})

    assert result.isError is True
    [content] = result.content
    assert isinstance(content, TextContent)
    assert "was not found in this mailbox scope" in content.text
    _no_leak(content.text)


async def test_fails_with_a_one_line_cause_on_another_api_error(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(
        routes={f"users/me/messages/{MID}": api_error(403, "insufficientPermissions", "Insufficient Permission")}
    )
    install(fake, monkeypatch)

    with pytest.raises(ToolError) as info:
        await gmail_get_message(GetMessageInput(message_id=MID))

    message_text = str(info.value)
    assert "Gmail API error 403 (insufficientPermissions)" in message_text
    assert "not found" not in message_text
    assert "\n" not in message_text


async def test_fails_on_a_pin_mismatch_and_fetches_no_message(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(profile_email=OTHER_ACCOUNT, routes={f"users/me/messages/{MID}": message()})
    install(fake, monkeypatch)

    with pytest.raises(ToolError) as info:
        await gmail_get_message(GetMessageInput(message_id=MID))

    assert "every tool is disabled" in str(info.value)
    assert fake.log == ["token", PROFILE]
    _no_leak(str(info.value))


async def test_fails_with_an_unknown_scope_label_before_fetching_the_message(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(routes={f"users/me/messages/{MID}": message()})
    install(fake, monkeypatch, GMAIL_SCOPE_LABEL="Projects/Nope")

    with pytest.raises(ToolError, match="matches no label"):
        await gmail_get_message(GetMessageInput(message_id=MID))

    assert fake.log == ["token", PROFILE, LABELS]


@pytest.mark.parametrize(
    "value", ["", "short", "../profile", "18c2f0e9/a1b2", "18c2 f0e9a1b2", "a" * 65, "<msg-0001@mail.example.com>"]
)
def test_refuses_a_message_id_that_is_not_one(value: str) -> None:
    with pytest.raises(ValidationError, match="must be a Gmail message id"):
        GetMessageInput(message_id=value)


@pytest.mark.parametrize("value", [-1, True, "ten", 100_000_001, 2.5])
def test_refuses_an_offset_that_is_not_a_character_position(value: Any) -> None:
    with pytest.raises(ValidationError):
        GetMessageInput(message_id=MID, offset=value)


@pytest.mark.parametrize("extra", [{"format": "raw"}, {"thread_id": TID}, {"skip_scope": True}])
def test_refuses_fields_get_message_does_not_have(extra: dict[str, Any]) -> None:
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        GetMessageInput.model_validate({"message_id": MID, **extra})


async def test_refuses_a_path_id_through_an_mcp_session_and_sends_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle()
    install(fake, monkeypatch)

    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool("gmail_get_message", {"params": {"message_id": "../../profile"}})

    assert result.isError is True
    [content] = result.content
    assert isinstance(content, TextContent)
    assert "must be a Gmail message id" in content.text
    assert fake.requests == []


@pytest.mark.parametrize("offset", [250, 251, 99_999])
async def test_refuses_quietly_an_offset_past_the_end(monkeypatch: pytest.MonkeyPatch, offset: int) -> None:
    install(FakeGoogle(routes={f"users/me/messages/{MID}": message(text_part("x" * 250))}), monkeypatch)

    result = await gmail_get_message(GetMessageInput(message_id=MID, offset=offset))

    assert (
        f"[body: offset {offset} is past the end of the body (250 characters): pass an offset from 0 to 249]" in result
    )
    assert "```" not in result


async def test_empty_body_with_only_an_attachment(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = multipart("mixed", attachment_part("scan.png", "image/png", 2048))
    install(FakeGoogle(routes={f"users/me/messages/{MID}": message(payload)}), monkeypatch)

    result = await gmail_get_message(GetMessageInput(message_id=MID))
    past = await gmail_get_message(GetMessageInput(message_id=MID, offset=10))

    assert "## Body\n\n[body: empty]" in result
    assert "```" not in result
    assert "- scan.png · image/png · 2.0 KiB (2048 bytes) · partId `1`" in result
    assert "[body: empty]" in past


async def test_empty_inline_text_says_which_parts_gmail_kept_outside(monkeypatch: pytest.MonkeyPatch) -> None:
    external = text_part(attachment_id="ANGjdJ_FAKE_external_0001")
    install(FakeGoogle(routes={f"users/me/messages/{MID}": message(external)}), monkeypatch)

    result = await gmail_get_message(GetMessageInput(message_id=MID))

    assert "[Gmail stored 1 text part(s) outside the message, not shown]" in result
    assert "ANGjdJ_FAKE_external_0001" not in result


async def test_fails_redacting_a_token_pasted_in_a_body(monkeypatch: pytest.MonkeyPatch) -> None:
    body = f"access_token={fake_access_token(9)} and Bearer {fake_access_token(8)}"
    install(FakeGoogle(routes={f"users/me/messages/{MID}": message(text_part(body))}), monkeypatch)

    result = await gmail_get_message(GetMessageInput(message_id=MID))

    assert fake_access_token(9) not in result and fake_access_token(8) not in result
    assert "access_token=***" in result
    _no_secrets(result)


# --- bounded output: the maximum always fits, and the note and token survive -------------------


def _assert_unclipped(result: str) -> None:
    assert "[truncated: response exceeded" not in result
    assert len(result.encode()) <= MAX_RESPONSE_BYTES


async def test_get_message_at_the_maximum_fits_with_its_note_and_attachments(monkeypatch: pytest.MonkeyPatch) -> None:
    # Every field at or over its cap, in 4-byte characters, and a full page at the largest
    # GMAIL_BODY_MAX_CHARS: the whole window, its note and the attachment list must survive.
    total = MAX_BODY_MAX_CHARS + 500
    worst = worst_message(total, attachments=150, message_id=MID)
    install(
        FakeGoogle(routes={f"users/me/messages/{MID}": worst}),
        monkeypatch,
        GMAIL_BODY_MAX_CHARS=str(MAX_BODY_MAX_CHARS),
    )

    first = await gmail_get_message(GetMessageInput(message_id=MID))
    second = await gmail_get_message(GetMessageInput(message_id=MID, offset=MAX_BODY_MAX_CHARS))

    _assert_unclipped(first)
    assert len(first.encode()) > 4 * MAX_BODY_MAX_CHARS  # the worst case is real: ~766 KB of 900
    assert (
        f"[body: characters 0–{MAX_BODY_MAX_CHARS} of {total}; pass offset={MAX_BODY_MAX_CHARS} for the next part]"
        in first
    )
    assert _FENCED.findall(first) == [FOUR_BYTES * MAX_BODY_MAX_CHARS]  # the window is whole: nothing shrank
    assert "## Attachments (150)" in first and "- … and 50 more attachment(s), not listed" in first
    assert f"- **Subject**: {FOUR_BYTES * (MAX_HEADER_CHARS - 1)}…" in first
    _assert_unclipped(second)
    assert f"[body: characters {MAX_BODY_MAX_CHARS}–{total} of {total}; end of the body]" in second
    assert _FENCED.findall(second) == [FOUR_BYTES * 500]


async def test_get_message_shrinks_the_page_rather_than_lose_its_note(monkeypatch: pytest.MonkeyPatch) -> None:
    # The second rail: with a smaller response budget, the window shrinks and the note follows,
    # so reading on from the printed offset misses nothing.
    budget = 30_000
    monkeypatch.setattr(messages_module, "fit_page", lambda render, page: fit_page(render, page, budget))
    body = "".join(chr(0x1F600 + n % 50) for n in range(20_000))  # 4-byte characters, all different
    install(FakeGoogle(routes={f"users/me/messages/{MID}": message(text_part(body))}), monkeypatch)

    shown = ""
    offset: int | None = 0
    pages = 0
    while offset is not None:
        page = await gmail_get_message(GetMessageInput(message_id=MID, offset=offset))
        assert len(page.encode()) <= budget
        [window] = _FENCED.findall(page)
        shown += window
        pages += 1
        found = re.search(r"pass offset=(\d+) for the next part", page)
        offset = int(found.group(1)) if found else None
        if found:
            assert int(found.group(1)) == len(shown)  # the note points exactly past the window shown

    assert shown == body
    assert pages > 2  # 80 KB of body in pages of at most 30 KB


def _worst_meta(message_id: str) -> dict[str, Any]:
    meta = _meta(message_id, thread_id=FOUR_BYTES * OVERLONG, labels=worst_labels(), snippet=FOUR_BYTES * OVERLONG)
    meta["payload"]["headers"] = [header(name, FOUR_BYTES * OVERLONG) for name in ("From", "Subject", "Date")]
    del meta["internalDate"]  # the Date header is shown instead
    return meta


async def test_search_at_the_maximum_fits_with_its_page_token(monkeypatch: pytest.MonkeyPatch) -> None:
    ids = [f"18c2f0e9a1b2{n:04x}" for n in range(100)]
    token = "N" * 1024
    routes: dict[str, Any] = {"users/me/messages": _listing(*ids, next_token=token)}
    routes.update({f"users/me/messages/{ident}": _worst_meta(ident) for ident in ids[:90]})
    routes.update(
        {f"users/me/messages/{ident}": api_error(403, "forbidden", FOUR_BYTES * OVERLONG) for ident in ids[90:]}
    )
    routes["users/me/labels"] = {"labels": [{"id": "Label_9", "name": FOUR_BYTES * OVERLONG, "type": "user"}]}
    install(
        FakeGoogle(routes=routes),
        monkeypatch,
        GMAIL_SCOPE_LABEL="Label_9",
        GMAIL_SCOPE_QUERY=text_of_encoded_size(FOUR_BYTES, MAX_SCOPE_QUERY_ENCODED),  # the most bytes that load
    )

    query = text_of_encoded_size(FOUR_BYTES, MAX_QUERY_ENCODED)  # the most bytes a query can carry
    result = await gmail_search_messages(SearchMessagesInput(query=query, max_results=100))

    _assert_unclipped(result)
    assert len(result.encode()) > 500_000  # the worst case is real: ~597 KB of 900
    assert f"More available — pass `page_token` = `{token}` to get the next page." in result
    assert "\n90. **" in result and "\n100. _metadata unavailable_ — Gmail API error 403 (forbidden)" in result
    assert result.endswith("`gmail_list_labels` maps label ids to names.")  # the last line is there


async def test_search_never_prints_a_page_token_it_would_refuse(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _search_fake(MID)
    fake.routes["users/me/messages"] = _listing(MID, next_token="not a token\nwith a newline")
    install(fake, monkeypatch)

    result = await gmail_search_messages(SearchMessagesInput())

    assert "not a token" not in result
    assert "More available, but Gmail's page token is not one this server can pass back" in result
