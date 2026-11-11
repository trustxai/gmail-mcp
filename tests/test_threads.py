"""tools/threads.py: gmail_search_threads and gmail_get_thread against a MockTransport Google.

At least half of these tests are negative cases (`test_refuses_…`, `test_out_of_scope_…`,
`test_…_fails…`): a refused query, a thread outside the scope, a 404, invalid arguments, an
empty result, the pin and the token failing through the tool. The scope is a filter, and
the ways it can be skipped matter more than the ways it works.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest
from mcp.server.fastmcp.exceptions import ToolError
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import TextContent
from pydantic import ValidationError

from gmail_mcp.client import MAX_CONCURRENCY
from gmail_mcp.config import MAX_BODY_MAX_CHARS
from gmail_mcp.errors import NotFoundInScopeError, describe_error, redact, register_secret
from gmail_mcp.formatters import MAX_RESPONSE_BYTES
from gmail_mcp.scope import EXCLUDE_SPAM_TRASH
from gmail_mcp.server import mcp
from gmail_mcp.tools.messages import GetMessageInput, gmail_get_message
from gmail_mcp.tools.threads import (
    MESSAGE_MAX_CHARS,
    GetThreadInput,
    SearchThreadsInput,
    gmail_get_thread,
    gmail_search_threads,
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
    ACCOUNT,
    CJK,
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
    oauth_error,
    text_of_encoded_size,
    text_part,
    worst_message,
)

PROFILE = "GET users/me/profile"
LABELS = "GET users/me/labels"
LIST = "GET users/me/threads"
BASE_MS = 1_794_308_400_000  # 2026-11-10 11:00 UTC
SCOPE_QUERY = "from:example.com"


def _mid(n: int) -> str:
    """A Gmail-shaped (16 hex characters) id."""
    return f"18c2f0e9a1b2{n:04x}"


TID = _mid(0)
THREAD = f"users/me/threads/{TID}"
GET_THREAD = f"GET {THREAD}"


def _msg(
    n: int,
    *,
    thread_id: str = TID,
    body: str | None = None,
    payload: dict[str, Any] | None = None,
    labels: list[str] | None = None,
    sender: str = "Ada <ada@example.com>",
    to: str = ACCOUNT,
    cc: str | None = None,
    subject: str = "Quarterly numbers",
    with_message_id: bool = True,
) -> dict[str, Any]:
    headers = [
        header("From", sender),
        header("To", to),
        header("Subject", subject if n == 0 else f"Re: {subject}"),
        header("Date", "Tue, 10 Nov 2026 11:00:00 +0000"),
    ]
    if cc is not None:
        headers.append(header("Cc", cc))
    if with_message_id:
        headers.append(header("Message-ID", f"<msg-{n:04d}@mail.example.com>"))
    out = message(
        payload if payload is not None else text_part(f"Body of message {n}" if body is None else body),
        message_id=_mid(n),
        thread_id=thread_id,
        labels=labels,
        headers=headers,
    )
    out["internalDate"] = str(BASE_MS + n * 60_000)
    out["snippet"] = f"snippet {n}"
    return out


def _thread(*messages: dict[str, Any], thread_id: str = TID) -> dict[str, Any]:
    return {"id": thread_id, "historyId": "991", "messages": list(messages)}


def _listing(*ids: str, token: str | None = None, estimate: int | None = None) -> dict[str, Any]:
    body: dict[str, Any] = {
        "threads": [{"id": ident, "snippet": f"Snippet &amp; more for {ident}", "historyId": "1"} for ident in ids],
        "resultSizeEstimate": len(ids) if estimate is None else estimate,
    }
    if token is not None:
        body["nextPageToken"] = token
    return body


def _params(request: httpx.Request) -> dict[str, list[str]]:
    return parse_qs(request.url.query.decode(), keep_blank_values=True)


def _requests_to(fake: FakeGoogle, path: str) -> list[httpx.Request]:
    return [request for request in fake.api_requests if request.url.path.endswith("/" + path)]


def _not_found(thread_id: str = TID) -> str:
    return describe_error(NotFoundInScopeError("thread", thread_id))


# Everything a thread's headers or bodies could leak through an error message.
LEAKS = ("Quarterly numbers", "ada@example.com", "bob@example.com", "msg-0000@mail", "msg-0001@mail", "Body of message")


def _assert_no_leak(text: str) -> None:
    for fragment in LEAKS:
        assert fragment not in text, fragment


# --- registration -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "model"), [("gmail_search_threads", "SearchThreadsInput"), ("gmail_get_thread", "GetThreadInput")]
)
async def test_both_tools_are_registered_with_one_strict_params_model(name: str, model: str) -> None:
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    tool = tools[name]
    assert tool.annotations is not None
    assert tool.annotations.readOnlyHint is True
    assert tool.annotations.destructiveHint is False
    assert tool.annotations.openWorldHint is True
    schema = tool.inputSchema
    assert list(schema["properties"]) == ["params"]
    assert schema["required"] == ["params"]
    assert schema["$defs"][model]["additionalProperties"] is False
    description = tool.description or ""
    sections = ["When to Use:", "When NOT to Use:", "Returns:", "Examples:", "Error Handling:"]
    positions = [description.find(section) for section in sections]
    assert all(position > 0 for position in positions) and positions == sorted(positions)


async def test_the_get_thread_description_documents_both_caps() -> None:
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    description = tools["gmail_get_thread"].description or ""
    assert f"{MESSAGE_MAX_CHARS:,} characters" in description
    assert "GMAIL_BODY_MAX_CHARS body characters in total" in description
    assert "`offset` is the index of the first message" in description


# --- gmail_search_threads: positive -----------------------------------------------------------


async def test_search_summarizes_each_thread_and_prints_the_next_page_token(monkeypatch: pytest.MonkeyPatch) -> None:
    first, second = _mid(0x100), _mid(0x200)
    thread_a = _thread(
        _msg(0, thread_id=first),
        _msg(1, thread_id=first, sender="Bob <bob@example.com>", cc='"Perez, Ana" <ana@example.com>'),
        thread_id=first,
    )
    thread_b = _thread(_msg(0, thread_id=second, subject="Invoice 42"), thread_id=second)
    fake = FakeGoogle(
        routes={
            "users/me/threads": _listing(first, second, token="NEXT-page_123", estimate=57),
            f"users/me/threads/{first}": thread_a,
            f"users/me/threads/{second}": thread_b,
        }
    )
    install(fake, monkeypatch)

    result = await gmail_search_threads(SearchThreadsInput())

    assert result.startswith("# Gmail threads (no query: every thread in scope)")
    assert "Scope:" not in result
    assert "**2** thread(s) on this page (Gmail estimates about 57 in total)." in result
    assert "More available — pass `page_token` = `NEXT-page_123` for the next page." in result
    assert f"1. **Quarterly numbers** · threadId `{first}` · 2 messages · last 2026-11-10 11:01 UTC" in result
    people = f"Ada <ada@example.com>, {ACCOUNT}, Bob <bob@example.com>, Perez, Ana <ana@example.com>"
    assert f"   participants: {people}" in result
    assert f"   snippet: Snippet & more for {first}" in result
    assert f"2. **Invoice 42** · threadId `{second}` · 1 message · last 2026-11-10 11:00 UTC" in result
    assert fake.log[:3] == ["token", PROFILE, LIST]
    assert sorted(fake.log[3:]) == sorted([f"GET users/me/threads/{first}", f"GET users/me/threads/{second}"])
    listed = fake.params(1)
    assert listed == {"maxResults": ["20"], "q": [EXCLUDE_SPAM_TRASH], "includeSpamTrash": ["false"]}
    for request in fake.api_requests[2:]:
        assert _params(request) == {"format": ["metadata"], "metadataHeaders": ["From", "To", "Cc", "Subject", "Date"]}
    assert "Body of message" not in result  # metadata only: no body is read


async def test_search_forwards_the_query_page_size_and_page_token(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(routes={"users/me/threads": _listing(TID), THREAD: _thread(_msg(0))})
    install(fake, monkeypatch)

    result = await gmail_search_threads(
        SearchThreadsInput(query="  invoice   from:ada@example.com ", max_results=5, page_token="tok_123")
    )

    assert fake.params(1) == {
        "maxResults": ["5"],
        "pageToken": ["tok_123"],
        "q": [f"(invoice from:ada@example.com) {EXCLUDE_SPAM_TRASH}"],
        "includeSpamTrash": ["false"],
    }
    assert result.startswith("# Gmail threads: `invoice from:ada@example.com`")
    assert "More available" not in result


async def test_search_with_a_label_scope_filters_by_label_id(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(routes={"users/me/threads": _listing(TID), THREAD: _thread(_msg(0, labels=["Label_1"]))})
    install(fake, monkeypatch, GMAIL_SCOPE_LABEL="Projects/Acme")

    result = await gmail_search_threads(SearchThreadsInput(query="invoice"))

    assert fake.log[:4] == ["token", PROFILE, LABELS, LIST]
    assert fake.params(2) == {
        "maxResults": ["20"],
        "q": [f"(invoice) {EXCLUDE_SPAM_TRASH}"],
        "includeSpamTrash": ["false"],
        "labelIds": ["Label_1"],
    }
    assert "Scope: label `Projects/Acme` (id `Label_1`)" in result
    assert "a filter, not a security boundary" in result


async def test_search_with_a_query_scope_parenthesises_both_queries(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(routes={"users/me/threads": _listing(TID), THREAD: _thread(_msg(0))})
    install(fake, monkeypatch, GMAIL_SCOPE_QUERY=SCOPE_QUERY)

    result = await gmail_search_threads(SearchThreadsInput(query="invoice OR receipt"))

    assert fake.params(1)["q"] == [f"({SCOPE_QUERY}) (invoice OR receipt) {EXCLUDE_SPAM_TRASH}"]
    assert "labelIds" not in fake.params(1)
    assert f"Scope: query `({SCOPE_QUERY})`" in result


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
    fake = FakeGoogle(
        routes={"users/me/threads": _listing(TID), THREAD: _thread(_msg(0))},
        max_request_target=GMAIL_REQUEST_TARGET_LIMIT,
    )
    install(fake, monkeypatch, GMAIL_SCOPE_QUERY=scope)

    result = await gmail_search_threads(SearchThreadsInput(query=query, page_token="=" * 1024))

    assert fake.log == ["token", PROFILE, LIST, GET_THREAD]
    [listed] = _requests_to(fake, "users/me/threads")
    assert _params(listed)["q"] == [f"({scope}) ({query}) {EXCLUDE_SPAM_TRASH}"]
    assert longest_request_target(fake) <= MAX_REQUEST_TARGET
    assert f"1. **Quarterly numbers** · threadId `{TID}`" in result


@pytest.mark.parametrize("char", CAP_CHARS, ids=CAP_IDS)
async def test_get_thread_in_a_query_scope_at_the_cap_is_found_by_its_lookups(
    monkeypatch: pytest.MonkeyPatch, char: str
) -> None:
    scope, _ = _at_caps(char)
    fake = FakeGoogle(
        routes={THREAD: _thread(_msg(0), _msg(1)), "users/me/messages": {"messages": [{"id": _mid(1)}]}},
        max_request_target=GMAIL_REQUEST_TARGET_LIMIT,
    )
    install(fake, monkeypatch, GMAIL_SCOPE_QUERY=scope)

    result = await gmail_get_thread(GetThreadInput(thread_id=TID))

    assert longest_request_target(fake) <= MAX_REQUEST_TARGET
    assert "## Message 2 of 2" in result


async def test_search_with_both_scopes_and_no_query(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(routes={"users/me/threads": _listing(TID), THREAD: _thread(_msg(0))})
    install(fake, monkeypatch, GMAIL_SCOPE_LABEL="Label_2", GMAIL_SCOPE_QUERY=SCOPE_QUERY)

    result = await gmail_search_threads(SearchThreadsInput())

    listed = fake.params(2)
    assert listed["q"] == [f"({SCOPE_QUERY}) {EXCLUDE_SPAM_TRASH}"]
    assert listed["labelIds"] == ["Label_2"]
    assert listed["includeSpamTrash"] == ["false"]
    assert "label `Receipts` (id `Label_2`) and query" in result


async def test_search_fetches_summaries_at_most_ten_at_a_time(monkeypatch: pytest.MonkeyPatch) -> None:
    in_flight = 0
    peak = 0
    ids = [_mid(0x300 + n) for n in range(25)]

    async def slow(request: httpx.Request) -> httpx.Response:
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.005)
        in_flight -= 1
        ident = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(200, json=_thread(_msg(0, thread_id=ident), thread_id=ident))

    routes: dict[str, Any] = {f"users/me/threads/{ident}": slow for ident in ids}
    routes["users/me/threads"] = _listing(*ids)
    fake = FakeGoogle(routes=routes)
    install(fake, monkeypatch)

    result = await gmail_search_threads(SearchThreadsInput(max_results=25))

    assert peak == MAX_CONCURRENCY == 10
    for index, ident in enumerate(ids, start=1):  # rendered in the list's order
        assert f"{index}. **Quarterly numbers** · threadId `{ident}`" in result


async def test_search_caps_participants_and_snippets(monkeypatch: pytest.MonkeyPatch) -> None:
    to = ", ".join(f"user{n}@example.com" for n in range(14))
    thread = _thread(_msg(0, to=to))
    listing = _listing(TID)
    listing["threads"][0]["snippet"] = "x" * 500
    install(FakeGoogle(routes={"users/me/threads": listing, THREAD: thread}), monkeypatch)

    result = await gmail_search_threads(SearchThreadsInput())

    assert "user8@example.com (+5 more)" in result  # 15 people: the sender and 14 recipients
    assert "user9@example.com" not in result
    assert "   snippet: " + "x" * 199 + "…" in result


async def test_search_redacts_a_token_shaped_subject(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = fake_access_token(9)
    thread = _thread(_msg(0, subject=f"pasted {secret}"))
    install(FakeGoogle(routes={"users/me/threads": _listing(TID), THREAD: thread}), monkeypatch)

    result = await gmail_search_threads(SearchThreadsInput())

    assert secret not in result
    assert "**pasted ***" in result


# --- gmail_search_threads: negative -----------------------------------------------------------

ESCAPES = [
    ") OR from:bank (",
    "invoice) OR (in:anywhere",
    "(unclosed",
    "from:x}",
    '"unterminated ) OR from:x (',
    "( { ) OR from:bank ( } )",
    "({)}",
]


@pytest.mark.parametrize("query", ESCAPES)
@pytest.mark.parametrize(
    "scope", [{}, {"GMAIL_SCOPE_LABEL": "Label_1"}, {"GMAIL_SCOPE_QUERY": SCOPE_QUERY}], ids=["none", "label", "query"]
)
async def test_refuses_a_query_the_scope_refuses_without_sending_anything(
    query: str, scope: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # The tool's own layer: params that skipped validation still meet scope.apply().
    fake = FakeGoogle()
    install(fake, monkeypatch, **scope)

    with pytest.raises(ToolError) as info:
        await gmail_search_threads(SearchThreadsInput.model_construct(query=query, max_results=20, page_token=None))

    problem = query_problem(query)
    assert problem is not None
    assert str(info.value) == f"the search query is refused: {problem}"
    assert fake.requests == []  # not even a token refresh


@pytest.mark.parametrize("query", ESCAPES)
async def test_refuses_an_escaping_query_through_an_mcp_session(query: str, monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle()
    install(fake, monkeypatch, GMAIL_SCOPE_QUERY=SCOPE_QUERY)

    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool("gmail_search_threads", {"params": {"query": query}})

    assert result.isError is True
    [content] = result.content
    assert isinstance(content, TextContent)
    problem = query_problem(query)
    assert problem is not None and problem in content.text  # the scope's reason, word for word
    assert "Traceback" not in content.text
    assert fake.requests == []


@pytest.mark.parametrize(
    "raw",
    [
        {"max_results": 0},
        {"max_results": 101},
        {"max_results": True},
        {"max_results": "lots"},
        {"max_results": None},
        {"page_token": "has space"},
        {"page_token": "a/../b"},
        {"query": "x" * 1_501},
        {"query": FOUR_BYTES * 1_501},
        {"query": "a\x00b"},
        {"query": 42},
        {"q": "invoice"},
        {"include_spam_trash": True},
    ],
    ids=lambda raw: next(iter(raw)) + "=" + repr(next(iter(raw.values())))[:20],
)
def test_refuses_invalid_search_params(raw: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        SearchThreadsInput.model_validate(raw)


async def test_refuses_invalid_search_params_through_an_mcp_session_without_a_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeGoogle()
    install(fake, monkeypatch)

    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool("gmail_search_threads", {"params": {"max_results": 500, "labelIds": ["X"]}})

    assert result.isError is True
    [content] = result.content
    assert isinstance(content, TextContent)
    assert "max_results" in content.text and "labelIds" in content.text
    assert fake.requests == []


def test_a_blank_page_token_or_query_means_none() -> None:
    params = SearchThreadsInput.model_validate({"query": "   ", "page_token": " "})
    assert params.query is None and params.page_token is None


async def test_search_with_no_hits_says_so_and_fetches_no_summary(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(routes={"users/me/threads": {"resultSizeEstimate": 0}})
    install(fake, monkeypatch, GMAIL_SCOPE_QUERY=SCOPE_QUERY)

    result = await gmail_search_threads(SearchThreadsInput(query="nothing-like-this"))

    assert "**0** thread(s) on this page" in result
    assert "_No threads matched._ Check the query syntax and the scope above." in result
    assert fake.log == ["token", PROFILE, LIST]


async def test_search_skips_an_id_it_will_not_put_in_a_path(monkeypatch: pytest.MonkeyPatch) -> None:
    listing = _listing(TID)
    listing["threads"].insert(0, {"id": "../../profile", "snippet": "evil"})
    listing["threads"].append({"snippet": "no id at all"})
    fake = FakeGoogle(routes={"users/me/threads": listing, THREAD: _thread(_msg(0))})
    install(fake, monkeypatch)

    result = await gmail_search_threads(SearchThreadsInput())

    assert fake.log == ["token", PROFILE, LIST, GET_THREAD]
    assert "2 result(s) with an id this server will not use were skipped." in result
    assert "**1** thread(s) on this page" in result
    assert "evil" not in result


async def test_search_keeps_a_hit_whose_summary_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    gone = _mid(0x999)
    fake = FakeGoogle(routes={"users/me/threads": _listing(TID, gone), THREAD: _thread(_msg(0))})
    install(fake, monkeypatch)

    result = await gmail_search_threads(SearchThreadsInput())

    assert f"1. **Quarterly numbers** · threadId `{TID}`" in result
    assert f"2. threadId `{gone}` — summary unavailable: Gmail API error 404 (notFound)" in result
    assert f"Snippet & more for {gone}" not in result  # LR-1: the row keeps the id and the cause only


@pytest.mark.parametrize(
    "failure",
    [
        api_error(404, "notFound", "Requested entity was not found."),
        api_error(400, "failedPrecondition", "Precondition check failed."),
        api_error(403, "forbidden", "Forbidden"),
    ],
    ids=["404", "400", "403"],
)
async def test_refuses_to_show_the_snippet_of_a_hit_whose_summary_failed(
    monkeypatch: pytest.MonkeyPatch, failure: httpx.Response
) -> None:
    # LR-1: Gmail's thread snippet may be a trashed or spam message's text, and without the
    # thread's metadata the server cannot tell, so the error row must not print it.
    failed = _mid(0x998)
    listing = _listing(TID, failed)
    listing["threads"][1]["snippet"] = "words of a trashed message"
    fake = FakeGoogle(
        routes={"users/me/threads": listing, THREAD: _thread(_msg(0)), f"users/me/threads/{failed}": failure}
    )
    install(fake, monkeypatch)

    result = await gmail_search_threads(SearchThreadsInput())

    [row] = [line for line in result.splitlines() if line.startswith("2. ")]
    assert row.startswith(f"2. threadId `{failed}` — summary unavailable: Gmail API error {failure.status_code}")
    assert "trashed message" not in result
    assert result.count("snippet:") == 1  # the summarized hit's own, nothing for the failed one
    assert f"   snippet: Snippet & more for {TID}" in result


async def test_search_fails_when_no_summary_can_be_read(monkeypatch: pytest.MonkeyPatch) -> None:
    denied = api_error(403, "insufficientPermissions", "Request had insufficient authentication scopes.")
    fake = FakeGoogle(
        routes={"users/me/threads": _listing(TID, _mid(1)), THREAD: denied, f"users/me/threads/{_mid(1)}": denied}
    )
    install(fake, monkeypatch)

    with pytest.raises(ToolError) as info:
        await gmail_search_threads(SearchThreadsInput())

    assert "Gmail API error 403 (insufficientPermissions)" in str(info.value)
    assert "the token does not carry gmail.readonly" in str(info.value)


async def test_search_fails_on_a_list_error_with_one_line(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(routes={"users/me/threads": api_error(400, "invalidArgument", "Invalid pageToken")})
    install(fake, monkeypatch)

    with pytest.raises(ToolError) as info:
        await gmail_search_threads(SearchThreadsInput(page_token="stale_token"))

    message = str(info.value)
    assert message.startswith("Gmail API error 400 (invalidArgument): Invalid pageToken.")
    assert "check the ids, the page token and the query syntax" in message
    assert "\n" not in message
    assert fake.log == ["token", PROFILE, LIST]


async def test_search_fails_on_a_pin_mismatch_and_lists_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(profile_email=OTHER_ACCOUNT, routes={"users/me/threads": _listing(TID)})
    install(fake, monkeypatch)

    with pytest.raises(ToolError, match="every tool is disabled"):
        await gmail_search_threads(SearchThreadsInput(query="invoice"))

    assert fake.log == ["token", PROFILE]


async def test_search_fails_on_an_unknown_scope_label_before_listing(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(routes={"users/me/threads": _listing(TID)})
    install(fake, monkeypatch, GMAIL_SCOPE_LABEL="Projects/Nope")

    with pytest.raises(ToolError, match="GMAIL_SCOPE_LABEL=Projects/Nope matches no label"):
        await gmail_search_threads(SearchThreadsInput())

    assert LIST not in fake.log


async def test_search_fails_on_a_dead_refresh_token(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(token_responses=[oauth_error("invalid_grant")])
    install(fake, monkeypatch)

    with pytest.raises(ToolError, match=f"the refresh token for {ACCOUNT} is no longer valid"):
        await gmail_search_threads(SearchThreadsInput())

    assert fake.log == ["token"]


# --- gmail_get_thread: positive -------------------------------------------------------------


async def test_get_thread_renders_every_message_in_order_with_headers_and_bodies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    thread = _thread(
        _msg(0),
        _msg(1, sender="Bob <bob@example.com>", cc="Carol <carol@example.com>", labels=["INBOX", "IMPORTANT"]),
        _msg(2),
    )
    fake = FakeGoogle(routes={THREAD: thread})
    install(fake, monkeypatch)

    result = await gmail_get_thread(GetThreadInput(thread_id=TID))

    assert result.startswith(f"# Gmail thread `{TID}`: Quarterly numbers")
    assert "**3** message(s) in this thread, oldest first; showing 1–3." in result
    positions = [result.find(f"## Message {n} of 3 · id `{_mid(n - 1)}`") for n in (1, 2, 3)]
    assert all(position > 0 for position in positions) and positions == sorted(positions)
    assert "## Message 1 of 3 · id `18c2f0e9a1b20000` · 2026-11-10 11:00 UTC" in result
    assert "- **From**: Bob <bob@example.com>" in result
    assert "- **Cc**: Carol <carol@example.com>" in result
    assert "- **Subject**: Re: Quarterly numbers" in result
    assert "- **Message-ID**: <msg-0001@mail.example.com>" in result
    assert "- **Labels**: INBOX, IMPORTANT" in result
    assert "> Body of message 0\n\n[body: complete, 17 characters]" in result
    assert "Shown: messages 1–3 of 3 (51 body characters)." in result
    assert result.rstrip().endswith("End of the thread.")
    assert "earlier message" not in result
    assert fake.log == ["token", PROFILE, GET_THREAD]
    assert fake.params(1) == {"format": ["full"]}


async def test_get_thread_quotes_bodies_so_a_mail_cannot_pose_as_a_message_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = "line one\n\n## Message 9 of 9 · id `ffffffffffffffff`\nline four"
    install(FakeGoogle(routes={THREAD: _thread(_msg(0, body=body))}), monkeypatch)

    result = await gmail_get_thread(GetThreadInput(thread_id=TID))

    assert "> line one\n>\n> ## Message 9 of 9 · id `ffffffffffffffff`\n> line four" in result
    assert "\n## Message 9 of 9" not in result


async def test_get_thread_cuts_a_long_body_at_the_per_message_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    long_body = "".join(chr(ord("a") + n % 26) for n in range(12_000))
    install(FakeGoogle(routes={THREAD: _thread(_msg(0, body=long_body), _msg(1))}), monkeypatch)

    result = await gmail_get_thread(GetThreadInput(thread_id=TID))

    assert long_body[:MESSAGE_MAX_CHARS] in result
    assert long_body[: MESSAGE_MAX_CHARS + 1] not in result
    assert (
        f"[body: characters 0–{MESSAGE_MAX_CHARS} of 12000, cut at {MESSAGE_MAX_CHARS} per message in a thread; read on "
        f'with gmail_get_thread, params {{"thread_id": "{TID}", "message_id": "{_mid(0)}", "body_offset": '
        f"{MESSAGE_MAX_CHARS}}}]"
    ) in result
    assert "gmail_get_message" not in result  # it checks that one message, not the thread
    assert "## Message 2 of 2" in result  # 5,000 + 17 fit in the default 20,000 per call
    assert "End of the thread." in result


async def test_get_thread_stops_at_the_total_cap_and_counts_the_rest(monkeypatch: pytest.MonkeyPatch) -> None:
    thread = _thread(*(_msg(n, body=str(n) * 400) for n in range(5)))
    install(FakeGoogle(routes={THREAD: thread}), monkeypatch, GMAIL_BODY_MAX_CHARS="1000")

    result = await gmail_get_thread(GetThreadInput(thread_id=TID))

    assert "Body caps: 1000 characters per message, 1000 per call (GMAIL_BODY_MAX_CHARS)." in result
    assert "## Message 2 of 5" in result
    assert "## Message 3 of 5" not in result
    assert "Shown: messages 1–2 of 5 (800 body characters)." in result
    assert (
        "3 more message(s) after these, not shown (the body cap of 1000 characters per call) — pass offset=2 to read on."
        in result
    )


async def test_the_first_message_of_a_page_always_shows_so_paging_moves(monkeypatch: pytest.MonkeyPatch) -> None:
    thread = _thread(_msg(0, body="z" * 3_000), _msg(1, body="tiny"))
    install(FakeGoogle(routes={THREAD: thread}), monkeypatch, GMAIL_BODY_MAX_CHARS="1000")

    first = await gmail_get_thread(GetThreadInput(thread_id=TID))
    second = await gmail_get_thread(GetThreadInput(thread_id=TID, offset=1))

    assert "characters 0–1000 of 3000, cut at 1000 per message" in first
    assert (
        "1 more message(s) after these, not shown (the body cap of 1000 characters per call) — pass offset=1" in first
    )
    assert "## Message 2 of 2" in second and "> tiny" in second
    assert "1 earlier message(s) not shown — pass offset=0 to start from the first." in second


async def test_get_thread_pages_by_message_with_max_messages_and_offset(monkeypatch: pytest.MonkeyPatch) -> None:
    install(FakeGoogle(routes={THREAD: _thread(*(_msg(n) for n in range(5)))}), monkeypatch)

    page1 = await gmail_get_thread(GetThreadInput(thread_id=TID, max_messages=2))
    page2 = await gmail_get_thread(GetThreadInput(thread_id=TID, offset=2, max_messages=2))
    page3 = await gmail_get_thread(GetThreadInput(thread_id=TID, offset=4, max_messages=2))

    assert "showing 1–2." in page1 and "## Message 3 of 5" not in page1
    assert "3 more message(s) after these, not shown (max_messages=2) — pass offset=2 to read on." in page1
    assert "showing 3–4." in page2 and "## Message 2 of 5" not in page2 and "## Message 5 of 5" not in page2
    assert "1 more message(s) after these, not shown (max_messages=2) — pass offset=4 to read on." in page2
    assert "2 earlier message(s) not shown — pass offset=0 to start from the first." in page2
    assert "showing 5–5." in page3 and "End of the thread." in page3
    assert "4 earlier message(s) not shown" in page3


async def test_get_thread_turns_html_into_text_and_lists_attachments(monkeypatch: pytest.MonkeyPatch) -> None:
    html_message = _msg(0, payload=text_part("<p>Hi <b>there</b></p><script>x()</script>", mime="text/html"))
    with_file = _msg(
        1,
        payload=multipart(
            "mixed", text_part("see attached", part_id="0"), attachment_part("q3.pdf", "application/pdf", 12_345)
        ),
    )
    install(FakeGoogle(routes={THREAD: _thread(html_message, with_file)}), monkeypatch)

    result = await gmail_get_thread(GetThreadInput(thread_id=TID))

    assert "> Hi there\n\n[body (converted from HTML): complete, 8 characters]" in result
    assert "x()" not in result
    assert "- **Attachments** (1; save one with gmail_get_attachment):" in result
    assert "  - q3.pdf · application/pdf · 12.1 KiB (12345 bytes) · partId `1`" in result
    assert "ANGjdJ_FAKE_attachment_0001" not in result  # ADR-0002: the rotating attachmentId is never shown
    assert "> see attached" in result


async def test_get_thread_names_a_body_gmail_did_not_inline(monkeypatch: pytest.MonkeyPatch) -> None:
    external = _msg(0, payload=text_part("", attachment_id="ANGjdJ_FAKE_textpart_0001"))
    empty = _msg(1, payload=multipart("mixed", attachment_part("a.bin", "application/octet-stream", 3)))
    install(FakeGoogle(routes={THREAD: _thread(external, empty)}), monkeypatch)

    result = await gmail_get_thread(GetThreadInput(thread_id=TID))

    assert "[body: Gmail stored the text as a separate part (not inlined), which this server does not show]" in result
    assert "[body: no text part]" in result


async def test_get_thread_redacts_a_token_pasted_in_a_body(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = fake_access_token(7)
    install(FakeGoogle(routes={THREAD: _thread(_msg(0, body=f"use {secret} to log in"))}), monkeypatch)

    result = await gmail_get_thread(GetThreadInput(thread_id=TID))

    assert secret not in result
    assert "> use *** to log in" in result


@pytest.mark.parametrize("kind", ["token-shape", "registered-shapeless"])
async def test_a_secret_straddling_the_cut_of_a_thread_body_never_shows_a_part(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    secret = fake_access_token(6) if kind == "token-shape" else SHAPELESS_SECRET
    body = "a" * 95 + secret + " and the rest of the reply " + "z" * 150
    install(FakeGoogle(routes={THREAD: _thread(_msg(0, body=body))}), monkeypatch, GMAIL_BODY_MAX_CHARS="100")
    register_secret(SHAPELESS_SECRET)

    pages = [await gmail_get_thread(GetThreadInput(thread_id=TID))]
    while (found := re.search(r'"body_offset": (\d+)\}', pages[-1])) is not None:
        params = GetThreadInput(thread_id=TID, message_id=_mid(0), body_offset=int(found.group(1)))
        pages.append(await gmail_get_thread(params))

    shown = "".join(re.findall(r"\n> (.*)\n\n\[body", "\n".join(pages)))
    assert shown == redact(body)  # the per-message cut and the read-on walk the redacted body
    assert pages[0].count("***") == 1
    for fragment in (secret[:5], secret[5:], secret[-10:]):
        assert all(fragment not in page for page in pages), fragment


# --- spam and trash: never shown --------------------------------------------------------------

SCOPES = [{}, {"GMAIL_SCOPE_LABEL": "Projects/Acme"}, {"GMAIL_SCOPE_QUERY": SCOPE_QUERY}]
SCOPE_IDS = ["none", "label", "query"]


@pytest.mark.parametrize("scope", SCOPES, ids=SCOPE_IDS)
async def test_a_thread_entirely_in_trash_is_not_found(monkeypatch: pytest.MonkeyPatch, scope: dict[str, str]) -> None:
    thread = _thread(_msg(0, labels=["Label_1", "TRASH"]), _msg(1, labels=["Label_1", "SPAM"]))
    lookups = {"messages": [{"id": _mid(0)}, {"id": _mid(1)}]}  # a query lookup would say yes
    fake = FakeGoogle(routes={THREAD: thread, "users/me/messages": lookups})
    install(fake, monkeypatch, **scope)

    with pytest.raises(ToolError) as info:
        await gmail_get_thread(GetThreadInput(thread_id=TID))

    assert str(info.value) == _not_found()
    _assert_no_leak(str(info.value))
    assert "GET users/me/messages" not in fake.log  # nothing left to look up


@pytest.mark.parametrize("scope", SCOPES, ids=SCOPE_IDS)
async def test_an_in_scope_thread_leaves_out_its_spam_and_trash_and_counts_them(
    monkeypatch: pytest.MonkeyPatch, scope: dict[str, str]
) -> None:
    thread = _thread(
        _msg(0, labels=["Label_1"]),
        _msg(1, labels=["TRASH"], body="deleted secret plan"),
        _msg(2, labels=["Label_1", "SPAM"], body="spammy offer"),
        _msg(3, labels=["Label_1"]),
    )
    fake = FakeGoogle(routes={THREAD: thread, "users/me/messages": {"messages": [{"id": _mid(0)}]}})
    install(fake, monkeypatch, **scope)

    result = await gmail_get_thread(GetThreadInput(thread_id=TID))

    assert "2 message(s) of this thread in spam or trash are never shown and not counted here." in result
    assert "**2** message(s) in this thread, oldest first; showing 1–2." in result
    assert f"## Message 1 of 2 · id `{_mid(0)}`" in result and f"## Message 2 of 2 · id `{_mid(3)}`" in result
    assert "deleted secret plan" not in result and "spammy offer" not in result
    assert _mid(1) not in result and _mid(2) not in result


async def test_reading_on_a_message_in_trash_is_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    thread = _thread(_msg(0), _msg(1, labels=["TRASH"], body="deleted secret plan"))
    install(FakeGoogle(routes={THREAD: thread}), monkeypatch)

    with pytest.raises(ToolError) as info:
        await gmail_get_thread(GetThreadInput(thread_id=TID, message_id=_mid(1)))

    assert str(info.value) == describe_error(NotFoundInScopeError("message", _mid(1)))
    assert "deleted secret plan" not in str(info.value)


async def test_reading_on_says_how_many_were_left_out(monkeypatch: pytest.MonkeyPatch) -> None:
    thread = _thread(_msg(0, labels=["SPAM"]), _msg(1, body="kept reply"))
    install(FakeGoogle(routes={THREAD: thread}), monkeypatch)

    result = await gmail_get_thread(GetThreadInput(thread_id=TID, message_id=_mid(1)))

    assert "1 message(s) of this thread in spam or trash are never shown" in result
    assert "**1** message(s) in this thread; showing message 1 alone" in result
    assert "> kept reply" in result


async def test_search_summaries_leave_out_spam_and_trash(monkeypatch: pytest.MonkeyPatch) -> None:
    trashed = _msg(1, sender="Mallory <mallory@example.com>", labels=["TRASH"])
    trashed["snippet"] = "trashed words"
    thread = _thread(_msg(0), trashed)
    listing = _listing(TID)
    listing["threads"][0]["snippet"] = "trashed words"  # Gmail's thread snippet may be the trashed one
    other = _mid(0x500)
    gone = _thread(_msg(0, thread_id=other, labels=["SPAM"]), thread_id=other)
    listing["threads"].append({"id": other, "snippet": "spam words"})
    install(
        FakeGoogle(routes={"users/me/threads": listing, THREAD: thread, f"users/me/threads/{other}": gone}), monkeypatch
    )

    result = await gmail_search_threads(SearchThreadsInput())

    assert f"1. **Quarterly numbers** · threadId `{TID}` · 1 message (+1 in spam or trash, not shown)" in result
    assert "mallory@example.com" not in result and "trashed words" not in result
    assert "   snippet: snippet 0" in result  # the last message that is shown
    assert f"2. threadId `{other}` — every message of this thread is in spam or trash (never shown)" in result
    assert "spam words" not in result


async def test_get_thread_in_a_label_scope_shows_the_whole_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    thread = _thread(_msg(0, labels=["INBOX"]), _msg(1, labels=["INBOX", "Label_1"]))
    fake = FakeGoogle(routes={THREAD: thread})
    install(fake, monkeypatch, GMAIL_SCOPE_LABEL="Projects/Acme")

    result = await gmail_get_thread(GetThreadInput(thread_id=TID))

    assert "## Message 1 of 2" in result and "## Message 2 of 2" in result  # in scope if ANY message is
    assert fake.log == ["token", PROFILE, LABELS, GET_THREAD]


async def test_get_thread_in_a_query_scope_looks_up_each_message_id_in_one_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lookups: list[str] = []

    def lookup(request: httpx.Request) -> dict[str, Any]:
        [query] = _params(request)["q"]
        lookups.append(query)
        return {"messages": [{"id": _mid(1), "threadId": TID}]} if "msg-0001@" in query else {"resultSizeEstimate": 0}

    fake = FakeGoogle(routes={THREAD: _thread(_msg(0), _msg(1), _msg(2)), "users/me/messages": lookup})
    install(fake, monkeypatch, GMAIL_SCOPE_QUERY=SCOPE_QUERY)

    result = await gmail_get_thread(GetThreadInput(thread_id=TID))

    # Three messages fit one batch (at most MAX_CONCURRENCY): all three go at once.
    assert sorted(lookups) == [f"({SCOPE_QUERY}) rfc822msgid:msg-{n:04d}@mail.example.com" for n in range(3)]
    assert "## Message 3 of 3" in result
    assert fake.log.index(GET_THREAD) < fake.log.index("GET users/me/messages")


def _slow_lookup(matching: set[int], stats: dict[str, int]) -> Any:
    """A query-scope lookup that takes a moment, counts what is in flight, and matches `matching`."""

    async def lookup(request: httpx.Request) -> dict[str, Any]:
        stats["in_flight"] += 1
        stats["peak"] = max(stats["peak"], stats["in_flight"])
        stats["calls"] += 1
        await asyncio.sleep(0.002)
        stats["in_flight"] -= 1
        n = int(_params(request)["q"][0].split("msg-", 1)[1][:4])
        return {"messages": [{"id": _mid(n), "threadId": TID}]} if n in matching else {"resultSizeEstimate": 0}

    return lookup


async def test_a_long_query_scope_thread_is_checked_in_bounded_batches_that_stop_at_the_first_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stats = {"in_flight": 0, "peak": 0, "calls": 0}
    thread = _thread(*(_msg(n) for n in range(100)))
    fake = FakeGoogle(routes={THREAD: thread, "users/me/messages": _slow_lookup({3}, stats)})
    install(fake, monkeypatch, GMAIL_SCOPE_QUERY=SCOPE_QUERY)

    result = await gmail_get_thread(GetThreadInput(thread_id=TID, max_messages=1))

    assert "## Message 1 of 100" in result
    assert stats["calls"] == MAX_CONCURRENCY == 10  # the first batch matched: 10 lookups, not 100
    assert stats["peak"] <= MAX_CONCURRENCY


async def test_a_late_match_still_never_exceeds_the_concurrency_bound(monkeypatch: pytest.MonkeyPatch) -> None:
    stats = {"in_flight": 0, "peak": 0, "calls": 0}
    thread = _thread(*(_msg(n) for n in range(100)))
    fake = FakeGoogle(routes={THREAD: thread, "users/me/messages": _slow_lookup({97}, stats)})
    install(fake, monkeypatch, GMAIL_SCOPE_QUERY=SCOPE_QUERY)

    await gmail_get_thread(GetThreadInput(thread_id=TID, max_messages=1))

    assert stats["calls"] == 100
    assert stats["peak"] == MAX_CONCURRENCY  # batches of 10, never more in flight


async def test_out_of_scope_a_failed_batch_without_a_match_stops_the_check(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def lookup(request: httpx.Request) -> Any:
        n = int(_params(request)["q"][0].split("msg-", 1)[1][:4])
        calls.append(n)
        if n == 4:
            return api_error(403, "forbidden", "Forbidden")
        return {"messages": [{"id": _mid(n)}]} if n == 50 else {"resultSizeEstimate": 0}

    thread = _thread(*(_msg(n) for n in range(60)))
    fake = FakeGoogle(routes={THREAD: thread, "users/me/messages": lookup})
    install(fake, monkeypatch, GMAIL_SCOPE_QUERY=SCOPE_QUERY)

    with pytest.raises(ToolError) as info:
        await gmail_get_thread(GetThreadInput(thread_id=TID))

    assert str(info.value) == _not_found()  # fail closed, although message 50 would have matched
    assert sorted(calls) == list(range(10))  # the first batch only


async def test_copies_of_one_message_are_looked_up_once(monkeypatch: pytest.MonkeyPatch) -> None:
    lookups: list[str] = []

    def lookup(request: httpx.Request) -> dict[str, Any]:
        lookups.append(_params(request)["q"][0])
        return {"messages": [{"id": _mid(1)}]}  # Gmail returns the second copy

    sent = _msg(0)
    received = _msg(1)
    received["payload"]["headers"] = sent["payload"]["headers"]  # the same Message-ID
    fake = FakeGoogle(routes={THREAD: _thread(sent, received), "users/me/messages": lookup})
    install(fake, monkeypatch, GMAIL_SCOPE_QUERY=SCOPE_QUERY)

    result = await gmail_get_thread(GetThreadInput(thread_id=TID))

    assert lookups == [f"({SCOPE_QUERY}) rfc822msgid:msg-0000@mail.example.com"]
    assert "## Message 2 of 2" in result


async def test_get_thread_through_an_mcp_session(monkeypatch: pytest.MonkeyPatch) -> None:
    install(FakeGoogle(routes={THREAD: _thread(_msg(0))}), monkeypatch)

    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool("gmail_get_thread", {"params": {"thread_id": TID, "max_messages": 1}})

    assert result.isError is False
    [content] = result.content
    assert isinstance(content, TextContent)
    assert content.text.startswith(f"# Gmail thread `{TID}`")


# --- gmail_get_thread: reading on a cut body (message_id + body_offset) ---------------------

# A reply long enough to be cut at the per-message cap, with text that must never leak.
REST = "".join(f"rest-{n:05d}|" for n in range(1_100))  # 12,100 characters
LABELLED_FIRST = ["INBOX", "Label_1"]


def _scoped_thread(first_labels: list[str]) -> dict[str, Any]:
    """A label-scope thread: the first message carries `first_labels`, the long reply only INBOX."""
    return _thread(_msg(0, labels=first_labels), _msg(1, labels=["INBOX"], sender="Bob <bob@example.com>", body=REST))


async def test_a_cut_reply_outside_the_label_scope_is_read_to_its_end_through_the_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The reply has no scope label: in scope only as part of the thread (ADR D5).
    reply = _scoped_thread(LABELLED_FIRST)["messages"][1]
    fake = FakeGoogle(routes={THREAD: _scoped_thread(LABELLED_FIRST), f"users/me/messages/{_mid(1)}": reply})
    install(fake, monkeypatch, GMAIL_SCOPE_LABEL="Projects/Acme")

    page = await gmail_get_thread(GetThreadInput(thread_id=TID))
    way_on = f'params {{"thread_id": "{TID}", "message_id": "{_mid(1)}", "body_offset": {MESSAGE_MAX_CHARS}}}'
    rest = await gmail_get_thread(GetThreadInput(thread_id=TID, message_id=_mid(1), body_offset=MESSAGE_MAX_CHARS))

    assert f"read on with gmail_get_thread, {way_on}]" in page
    assert "gmail_get_message" not in page
    assert "showing message 2 alone, its body from character 5000" in rest
    assert REST[MESSAGE_MAX_CHARS:].replace("\n", "") in rest.replace("> ", "")
    assert REST[MESSAGE_MAX_CHARS - 10 : MESSAGE_MAX_CHARS] not in rest  # starts where the page stopped
    assert f"[body: characters {MESSAGE_MAX_CHARS}–{len(REST)} of {len(REST)}; end of the body]" in rest
    assert "## Message 2 of 2 · id `18c2f0e9a1b20001`" in rest and "## Message 1 of 2" not in rest
    assert fake.log == ["token", PROFILE, LABELS, GET_THREAD, GET_THREAD]  # no per-message check
    # The dead end this avoids: the same reply alone is out of the label scope.
    with pytest.raises(ToolError, match="was not found in this mailbox scope"):
        await gmail_get_message(GetMessageInput(message_id=_mid(1), offset=MESSAGE_MAX_CHARS))


async def test_a_cut_reply_in_a_query_scope_thread_is_read_on_through_the_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def lookup(request: httpx.Request) -> dict[str, Any]:  # only the FIRST message matches the scope query
        return {"messages": [{"id": _mid(0)}]} if "msg-0000@" in _params(request)["q"][0] else {}

    fake = FakeGoogle(routes={THREAD: _scoped_thread(["INBOX"]), "users/me/messages": lookup})
    install(fake, monkeypatch, GMAIL_SCOPE_QUERY=SCOPE_QUERY)

    rest = await gmail_get_thread(GetThreadInput(thread_id=TID, message_id=_mid(1), body_offset=MESSAGE_MAX_CHARS))

    assert "; end of the body]" in rest
    # The thread-level check (one lookup per Message-ID, in one batch), then nothing for the read-on.
    assert fake.log.count("GET users/me/messages") == 2


async def test_reading_on_one_message_pages_it_at_the_per_call_cap(monkeypatch: pytest.MonkeyPatch) -> None:
    body = "".join(chr(ord("a") + n % 26) for n in range(2_500))
    install(FakeGoogle(routes={THREAD: _thread(_msg(0), _msg(1, body=body))}), monkeypatch, GMAIL_BODY_MAX_CHARS="1000")

    result = await gmail_get_thread(GetThreadInput(thread_id=TID, message_id=_mid(1), body_offset=1000))

    assert f"\n> {body[1000:2000]}\n\n[body:" in result  # exactly the window [1000, 2000)
    assert (
        "[body: characters 1000–2000 of 2500, cut at 1000 per call (GMAIL_BODY_MAX_CHARS); read on with "
        f'gmail_get_thread, params {{"thread_id": "{TID}", "message_id": "{_mid(1)}", "body_offset": 2000}}]'
    ) in result


async def test_reading_on_from_offset_zero_shows_the_whole_message_when_it_fits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install(FakeGoogle(routes={THREAD: _thread(_msg(0), _msg(1, body="short reply"))}), monkeypatch)

    result = await gmail_get_thread(GetThreadInput(thread_id=TID, message_id=_mid(1)))

    assert "> short reply\n\n[body: complete, 11 characters]" in result


async def test_out_of_scope_thread_refuses_the_read_on_like_a_missing_one(monkeypatch: pytest.MonkeyPatch) -> None:
    # Negative of the label-scope case: no message of the thread carries the label.
    fake = FakeGoogle(routes={THREAD: _scoped_thread(["INBOX"])})
    install(fake, monkeypatch, GMAIL_SCOPE_LABEL="Projects/Acme")

    with pytest.raises(ToolError) as info:
        await gmail_get_thread(GetThreadInput(thread_id=TID, message_id=_mid(1), body_offset=MESSAGE_MAX_CHARS))

    assert str(info.value) == _not_found()
    _assert_no_leak(str(info.value))
    assert "rest-" not in str(info.value)


async def test_refuses_to_read_on_a_message_that_is_not_in_the_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    stranger = _mid(0x4242)
    install(FakeGoogle(routes={THREAD: _scoped_thread(LABELLED_FIRST)}), monkeypatch, GMAIL_SCOPE_LABEL="Label_1")

    with pytest.raises(ToolError) as info:
        await gmail_get_thread(GetThreadInput(thread_id=TID, message_id=stranger, body_offset=10))

    assert str(info.value) == describe_error(NotFoundInScopeError("message", stranger))
    _assert_no_leak(str(info.value))
    assert "rest-" not in str(info.value)


async def test_a_body_offset_past_the_end_says_how_far_the_body_goes(monkeypatch: pytest.MonkeyPatch) -> None:
    install(FakeGoogle(routes={THREAD: _thread(_msg(0), _msg(1, body="short reply"))}), monkeypatch)

    result = await gmail_get_thread(GetThreadInput(thread_id=TID, message_id=_mid(1), body_offset=500))

    assert "[body: body_offset=500 is past the end of message `18c2f0e9a1b20001` (11 characters)" in result
    assert "short reply" not in result


@pytest.mark.parametrize(
    "raw",
    [
        {"thread_id": TID, "body_offset": 5000},  # no message_id: offset into what?
        {"thread_id": TID, "message_id": _mid(1), "offset": 2},  # two pagings at once
        {"thread_id": TID, "message_id": _mid(1), "body_offset": -1},
        {"thread_id": TID, "message_id": _mid(1), "body_offset": True},
        {"thread_id": TID, "message_id": "../../profile"},
        {"thread_id": TID, "message_id": "abc"},
    ],
    ids=["body-offset-alone", "offset-and-message", "negative", "bool", "path", "short"],
)
def test_refuses_invalid_read_on_params(raw: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        GetThreadInput.model_validate(raw)


# --- gmail_get_thread: negative -------------------------------------------------------------


async def test_get_thread_reports_a_missing_id_as_not_found_in_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle()  # no route: Gmail's 404
    install(fake, monkeypatch)

    with pytest.raises(ToolError) as info:
        await gmail_get_thread(GetThreadInput(thread_id=TID))

    assert str(info.value) == _not_found()
    assert f"thread {TID} was not found in this mailbox scope" in str(info.value)
    assert fake.log == ["token", PROFILE, GET_THREAD]


@pytest.mark.parametrize(
    "labels",
    [
        [["INBOX"], ["INBOX", "IMPORTANT"]],
        [["Label_1", "TRASH"], ["INBOX"]],
        [["Label_1", "SPAM"], ["Label_2"]],
        [[], []],
    ],
    ids=["no-message-has-the-label", "the-labelled-one-is-in-trash", "the-labelled-one-is-spam", "no-labels"],
)
async def test_out_of_scope_label_thread_looks_exactly_like_a_missing_one(
    labels: list[list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    thread = _thread(_msg(0, labels=labels[0]), _msg(1, labels=labels[1], sender="Bob <bob@example.com>"))
    fake = FakeGoogle(routes={THREAD: thread})
    install(fake, monkeypatch, GMAIL_SCOPE_LABEL="Projects/Acme")

    with pytest.raises(ToolError) as info:
        await gmail_get_thread(GetThreadInput(thread_id=TID))

    assert str(info.value) == _not_found()
    _assert_no_leak(str(info.value))


@pytest.mark.parametrize(
    "lookup",
    [
        {"resultSizeEstimate": 0},
        {"messages": [{"id": _mid(0x77), "threadId": _mid(0x77)}]},  # the Message-ID matches another message
        {"messages": "not-a-list"},
        api_error(403, "forbidden", "Forbidden"),  # the check itself fails: fail closed
        api_error(400, "invalidArgument", "Invalid query"),
    ],
    ids=["no-match", "another-message", "malformed", "check-403", "check-400"],
)
async def test_out_of_scope_query_thread_looks_exactly_like_a_missing_one(
    lookup: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeGoogle(routes={THREAD: _thread(_msg(0), _msg(1)), "users/me/messages": lookup})
    install(fake, monkeypatch, GMAIL_SCOPE_QUERY=SCOPE_QUERY)

    with pytest.raises(ToolError) as info:
        await gmail_get_thread(GetThreadInput(thread_id=TID))

    assert str(info.value) == _not_found()
    _assert_no_leak(str(info.value))
    assert fake.log.count("GET users/me/messages") >= 1  # the check ran on the fetched thread


async def test_out_of_scope_a_query_thread_without_message_ids_is_not_looked_up(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    thread = _thread(_msg(0, with_message_id=False), _msg(1, with_message_id=False))
    fake = FakeGoogle(routes={THREAD: thread, "users/me/messages": {"messages": [{"id": _mid(0)}]}})
    install(fake, monkeypatch, GMAIL_SCOPE_QUERY=SCOPE_QUERY)

    with pytest.raises(ToolError) as info:
        await gmail_get_thread(GetThreadInput(thread_id=TID))

    assert str(info.value) == _not_found()
    assert fake.log == ["token", PROFILE, GET_THREAD]


async def test_out_of_scope_threads_also_fail_through_an_mcp_session(monkeypatch: pytest.MonkeyPatch) -> None:
    install(FakeGoogle(routes={THREAD: _thread(_msg(0, labels=["INBOX"]))}), monkeypatch, GMAIL_SCOPE_LABEL="Label_1")

    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool("gmail_get_thread", {"params": {"thread_id": TID}})

    assert result.isError is True
    [content] = result.content
    assert isinstance(content, TextContent)
    assert content.text == f"Error executing tool gmail_get_thread: {_not_found()}"
    _assert_no_leak(content.text)


@pytest.mark.parametrize("body", [{"id": TID, "messages": []}, {"id": TID}, {"id": TID, "messages": ["junk", 3]}])
async def test_a_thread_with_no_readable_message_is_not_found(
    body: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    install(FakeGoogle(routes={THREAD: body}), monkeypatch)

    with pytest.raises(ToolError) as info:
        await gmail_get_thread(GetThreadInput(thread_id=TID))

    assert str(info.value) == _not_found()


async def test_get_thread_with_an_offset_past_the_end_says_how_far_it_goes(monkeypatch: pytest.MonkeyPatch) -> None:
    install(FakeGoogle(routes={THREAD: _thread(_msg(0), _msg(1))}), monkeypatch)

    result = await gmail_get_thread(GetThreadInput(thread_id=TID, offset=9))

    assert "**2** message(s) in this thread; offset=9 is past the last one. Pass an offset from 0 to 1." in result
    assert "## Message" not in result and "Body of message" not in result


async def test_get_thread_reports_an_id_gmail_cannot_parse_as_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    # The same answer gmail_get_message gives an id that passes validation but that Gmail
    # cannot parse (found in the v0.1 review): before, this tool showed the raw "Gmail API error 400".
    fake = FakeGoogle(routes={THREAD: api_error(400, "invalidArgument", "Invalid id value")})
    install(fake, monkeypatch)

    with pytest.raises(ToolError) as info:
        await gmail_get_thread(GetThreadInput(thread_id=TID))

    assert str(info.value) == _not_found()


async def test_get_thread_fails_on_another_api_error_with_one_line(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(routes={THREAD: api_error(400, "failedPrecondition", "Mail service not enabled")})
    install(fake, monkeypatch)

    with pytest.raises(ToolError) as info:
        await gmail_get_thread(GetThreadInput(thread_id=TID))

    assert str(info.value).startswith("Gmail API error 400 (failedPrecondition): Mail service not enabled.")
    assert "\n" not in str(info.value)


async def test_get_thread_fails_on_a_pin_mismatch_and_fetches_no_thread(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(profile_email=OTHER_ACCOUNT, routes={THREAD: _thread(_msg(0))})
    install(fake, monkeypatch)

    with pytest.raises(ToolError, match=f"belongs to {OTHER_ACCOUNT}"):
        await gmail_get_thread(GetThreadInput(thread_id=TID))

    assert fake.log == ["token", PROFILE]


async def test_get_thread_fails_on_an_unknown_scope_label_before_fetching(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(routes={THREAD: _thread(_msg(0, labels=["Label_1"]))})
    install(fake, monkeypatch, GMAIL_SCOPE_LABEL="Projects/Nope")

    with pytest.raises(ToolError, match="GMAIL_SCOPE_LABEL=Projects/Nope matches no label"):
        await gmail_get_thread(GetThreadInput(thread_id=TID))

    assert fake.log == ["token", PROFILE, LABELS]


async def test_get_thread_fails_on_a_dead_refresh_token(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeGoogle(token_responses=[oauth_error("invalid_grant")])
    install(fake, monkeypatch)

    with pytest.raises(ToolError, match="run amazing-gmail-mcp-login on the Mac"):
        await gmail_get_thread(GetThreadInput(thread_id=TID))

    assert fake.log == ["token"]


@pytest.mark.parametrize(
    "raw",
    [
        {},
        {"thread_id": ""},
        {"thread_id": "abc"},
        {"thread_id": "../../profile"},
        {"thread_id": "18c2f0e9a1b2c3d4/messages"},
        {"thread_id": 1234567890},
        {"thread_id": TID, "offset": -1},
        {"thread_id": TID, "offset": True},
        {"thread_id": TID, "offset": 100_000_001},
        {"thread_id": TID, "max_messages": 0},
        {"thread_id": TID, "max_messages": 101},
        {"thread_id": TID, "max_messages": "all"},
        {"thread_id": TID, "format": "raw"},
    ],
    ids=lambda raw: ",".join(f"{key}={value!r}"[:30] for key, value in raw.items()) or "empty",
)
def test_refuses_invalid_get_thread_params(raw: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        GetThreadInput.model_validate(raw)


async def test_refuses_a_path_as_thread_id_through_an_mcp_session_without_a_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeGoogle()
    install(fake, monkeypatch)

    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool("gmail_get_thread", {"params": {"thread_id": "../../profile"}})

    assert result.isError is True
    [content] = result.content
    assert isinstance(content, TextContent)
    assert "thread_id must be a Gmail thread id" in content.text
    assert "../../profile" not in content.text  # the raw input is never echoed
    assert fake.requests == []


def test_get_thread_params_accept_numeric_strings_and_default_sensibly() -> None:
    params = GetThreadInput.model_validate({"thread_id": f" {TID} ", "offset": "3", "max_messages": "7"})
    assert (params.thread_id, params.offset, params.max_messages) == (TID, 3, 7)
    assert GetThreadInput(thread_id=TID).max_messages == 20


# --- bounded output: the maximum always fits, and the notes and token survive ------------------


def _assert_unclipped(result: str) -> None:
    assert "[truncated: response exceeded" not in result
    assert len(result.encode()) <= MAX_RESPONSE_BYTES


async def test_search_threads_at_the_maximum_fits_with_its_page_token(monkeypatch: pytest.MonkeyPatch) -> None:
    ids = [_mid(0x600 + n) for n in range(100)]
    token = "T" * 1024
    listing = _listing(*ids, token=token)
    for hit in listing["threads"]:
        hit["snippet"] = FOUR_BYTES * OVERLONG
    crowd = ", ".join(f"{FOUR_BYTES * 300} <p{n}@example.com>" for n in range(30))
    routes: dict[str, Any] = {"users/me/threads": listing}
    for n, ident in enumerate(ids):
        if n >= 90:
            routes[f"users/me/threads/{ident}"] = api_error(403, "forbidden", FOUR_BYTES * OVERLONG)
            continue
        first = _msg(0, thread_id=ident, subject=FOUR_BYTES * OVERLONG, sender=crowd, to=crowd, cc=crowd)
        routes[f"users/me/threads/{ident}"] = _thread(first, _msg(1, thread_id=ident), thread_id=ident)
    # The most bytes a scope and a query can carry (4-byte characters at the encoded caps).
    install(
        FakeGoogle(routes=routes),
        monkeypatch,
        GMAIL_SCOPE_QUERY=text_of_encoded_size(FOUR_BYTES, MAX_SCOPE_QUERY_ENCODED),
    )

    query = text_of_encoded_size(FOUR_BYTES, MAX_QUERY_ENCODED)
    result = await gmail_search_threads(SearchThreadsInput(query=query, max_results=100))

    _assert_unclipped(result)
    assert len(result.encode()) > 450_000  # the worst case is real
    assert f"More available — pass `page_token` = `{token}` for the next page." in result
    assert "\n90. **" in result and "\n100. threadId" in result
    assert result.endswith('params {"thread_id": "<threadId>"}.')


def _worst_thread(count: int, body_chars: int, attachments: int) -> dict[str, Any]:
    return _thread(
        *(
            worst_message(body_chars, attachments=attachments, message_id=_mid(n), thread_id=TID, n=n)
            for n in range(count)
        )
    )


async def test_a_thread_page_stops_at_the_byte_budget_and_says_where_to_read_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 100 messages, each with every header at its cap: by characters the page would hold many
    # more than fit in one response, so it stops at the byte budget, with a footer that survives.
    install(
        FakeGoogle(routes={THREAD: _worst_thread(100, 6_000, 20)}),
        monkeypatch,
        GMAIL_BODY_MAX_CHARS=str(MAX_BODY_MAX_CHARS),
    )

    first = await gmail_get_thread(GetThreadInput(thread_id=TID, max_messages=100))

    _assert_unclipped(first)
    found = re.search(
        r"(\d+) more message\(s\) after these, not shown \(the response size limit of 900,000 bytes per call\) — "
        r"pass offset=(\d+) to read on\.",
        first,
    )
    assert found is not None, first[-500:]
    end = int(found.group(2))
    assert 1 < end < 100 and int(found.group(1)) == 100 - end
    assert f"## Message {end} of 100" in first and f"## Message {end + 1} of 100" not in first
    assert first.count(f'"body_offset": {MESSAGE_MAX_CHARS}}}]') == end  # every cut body's read-on survived

    second = await gmail_get_thread(GetThreadInput(thread_id=TID, offset=end, max_messages=100))
    _assert_unclipped(second)
    assert f"## Message {end + 1} of 100" in second


async def test_reading_on_one_message_at_the_maximum_fits_with_its_note(monkeypatch: pytest.MonkeyPatch) -> None:
    total = MAX_BODY_MAX_CHARS + 500
    install(
        FakeGoogle(routes={THREAD: _worst_thread(1, total, 150)}),
        monkeypatch,
        GMAIL_BODY_MAX_CHARS=str(MAX_BODY_MAX_CHARS),
    )

    result = await gmail_get_thread(GetThreadInput(thread_id=TID, message_id=_mid(0)))

    _assert_unclipped(result)
    assert len(result.encode()) > 4 * MAX_BODY_MAX_CHARS
    assert (
        f"[body: characters 0–{MAX_BODY_MAX_CHARS} of {total}, cut at {MAX_BODY_MAX_CHARS} per call "
        f'(GMAIL_BODY_MAX_CHARS); read on with gmail_get_thread, params {{"thread_id": "{TID}", '
        f'"message_id": "{_mid(0)}", "body_offset": {MAX_BODY_MAX_CHARS}}}]'
    ) in result
    assert "- … and 50 more attachment(s), not listed" in result
    assert result.endswith("Pass only thread_id (and offset) to page the whole thread by message again.")
