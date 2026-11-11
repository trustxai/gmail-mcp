"""scope.py (ADR D5): apply() for list calls, check_message()/check_thread() after a fetch.

At least half of these tests are negative cases (`test_refuses_…`, `test_out_of_scope_…`):
the scope is a filter, and the ways it can be skipped matter more than the ways it works.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from gmail_mcp.client import API_BASE, _wire_params
from gmail_mcp.errors import QueryRejectedError, ScopeConfigError
from gmail_mcp.scope import (
    EXCLUDE_SPAM_TRASH,
    LIST_PATH,
    ScopeGuard,
    _lookup_params,
    check_user_query,
    in_spam_or_trash,
    message_id_header,
    request_target,
    visible_messages,
)
from gmail_mcp.validators import (
    GMAIL_MAX_REQUEST_TARGET,
    MAX_QUERY_CHARS,
    MAX_QUERY_ENCODED,
    MAX_REQUEST_TARGET,
    MAX_SCOPE_QUERY_ENCODED,
    encoded_length,
)

from .fakes import (
    CJK,
    FOUR_BYTES,
    GMAIL_REQUEST_TARGET_LIMIT,
    FakeGoogle,
    api_error,
    header,
    longest_request_target,
    make_client,
    make_settings,
    message,
    text_of_encoded_size,
)

MID = "18c2f0e9a1b2c3d4"
RFC822 = "msg-0001@mail.example.com"
SCOPE_QUERY = "from:example.com"


def _guard(fake: FakeGoogle, **scope: Any) -> ScopeGuard:
    settings = make_settings(**scope)
    return ScopeGuard(settings, make_client(fake, settings))


def _lookup(*ids: str) -> dict[str, Any]:
    return {"messages": [{"id": ident, "threadId": ident} for ident in ids], "resultSizeEstimate": len(ids)}


ESCAPES = [
    ") OR from:x (",
    ") OR (from:bank",
    "invoice) OR (in:anywhere",
    "(unclosed",
    "closed)",
    "a) (b",
    "{from:x",
    "from:x}",
    "} OR {",
    '"unterminated ) OR from:x (',
    'subject:"x" ") OR from:x (',
    '\\") OR from:x (\\"',
    "“(” ) OR from:x ( “)”",
    "＂) OR from:x (＂",
    # Crossed groups: each kind balances on its own, so only one stack over both refuses them.
    "( { ) OR from:bank ( } )",
    "({)}",
    "{ ( } ) OR from:x",
]


# --- apply(): positive ----------------------------------------------------------------------


async def test_apply_without_scope_passes_the_query_and_forces_include_spam_trash_false() -> None:
    fake = FakeGoogle()
    params = await _guard(fake).apply({"maxResults": 20}, query="  invoice   from:ada@example.com ")

    assert params == {
        "maxResults": 20,
        "q": f"(invoice from:ada@example.com) {EXCLUDE_SPAM_TRASH}",
        "includeSpamTrash": False,
    }
    assert fake.requests == []  # nothing to resolve


async def test_apply_with_a_label_scope_adds_its_id_as_label_ids() -> None:
    fake = FakeGoogle()
    guard = _guard(fake, scope_label="Projects/Acme")

    params = await guard.apply({"maxResults": 5}, query="invoice")

    assert params == {
        "maxResults": 5,
        "q": f"(invoice) {EXCLUDE_SPAM_TRASH}",
        "labelIds": ["Label_1"],
        "includeSpamTrash": False,
    }


@pytest.mark.parametrize("configured", ["Label_1", "Projects/Acme", "projects/acme"])
async def test_the_scope_label_resolves_by_id_name_or_unique_casefold_name(configured: str) -> None:
    guard = _guard(FakeGoogle(), scope_label=configured)
    resolved = await guard.resolve()
    assert (resolved.label_id, resolved.label_name) == ("Label_1", "Projects/Acme")


async def test_the_label_is_resolved_once() -> None:
    fake = FakeGoogle()
    guard = _guard(fake, scope_label="Projects/Acme")

    for _ in range(3):
        await guard.apply(query="x")

    assert fake.log.count("GET users/me/labels") == 1


async def test_apply_with_a_query_scope_parenthesises_both_sides() -> None:
    guard = _guard(FakeGoogle(), scope_query=SCOPE_QUERY)

    assert (await guard.apply(query="invoice OR receipt"))["q"] == (
        f"({SCOPE_QUERY}) (invoice OR receipt) {EXCLUDE_SPAM_TRASH}"
    )
    assert (await guard.apply(query=None))["q"] == f"({SCOPE_QUERY}) {EXCLUDE_SPAM_TRASH}"
    assert (await guard.apply(query="   "))["q"] == f"({SCOPE_QUERY}) {EXCLUDE_SPAM_TRASH}"


async def test_apply_with_both_scopes_sets_label_ids_and_the_composed_query() -> None:
    guard = _guard(FakeGoogle(), scope_label="Label_1", scope_query=SCOPE_QUERY)

    params = await guard.apply({"labelIds": ["INBOX"]}, query='subject:"q3 (draft)"')

    assert params["labelIds"] == ["INBOX", "Label_1"]
    assert params["q"] == f'({SCOPE_QUERY}) (subject:"q3 (draft)") {EXCLUDE_SPAM_TRASH}'
    assert params["includeSpamTrash"] is False


async def test_balanced_queries_with_quoted_parentheses_are_accepted() -> None:
    guard = _guard(FakeGoogle(), scope_query=SCOPE_QUERY)
    for query in ['"a ) b"', "(a OR b) -c", "{from:a from:b}", 'subject:"(x"']:
        assert (await guard.apply(query=query))["q"] == f"({SCOPE_QUERY}) ({query}) {EXCLUDE_SPAM_TRASH}"


# --- spam and trash: never shown, in every mode ------------------------------------------------

MODES = [
    {},
    {"scope_label": "Label_1"},
    {"scope_query": SCOPE_QUERY},
    {"scope_label": "Label_1", "scope_query": SCOPE_QUERY},
]
MODE_IDS = ["none", "label", "query", "both"]


@pytest.mark.parametrize("query", ["in:anywhere", "in:spam", "in:trash", "in:anywhere OR in:trash", None])
@pytest.mark.parametrize("scope", MODES, ids=MODE_IDS)
async def test_every_list_query_excludes_spam_and_trash(query: str | None, scope: dict[str, str]) -> None:
    params = await _guard(FakeGoogle(), **scope).apply({"maxResults": 5}, query=query)

    assert params["q"].endswith(f" {EXCLUDE_SPAM_TRASH}") or params["q"] == EXCLUDE_SPAM_TRASH
    assert params["includeSpamTrash"] is False
    if query:
        assert f"({query}) {EXCLUDE_SPAM_TRASH}" in params["q"]  # grouped: the exclusion binds to all of it


async def test_with_no_scope_and_no_query_the_exclusion_is_the_whole_query() -> None:
    assert (await _guard(FakeGoogle()).apply())["q"] == EXCLUDE_SPAM_TRASH


@pytest.mark.parametrize("excluded", ["SPAM", "TRASH"])
@pytest.mark.parametrize("scope", MODES, ids=MODE_IDS)
async def test_out_of_scope_in_spam_or_trash_in_every_mode(excluded: str, scope: dict[str, str]) -> None:
    fake = FakeGoogle(routes={"users/me/messages": _lookup(MID)})  # the query lookup would say yes
    guard = _guard(fake, **scope)

    assert await guard.check_message(message(message_id=MID, labels=["Label_1", excluded])) is False
    assert "GET users/me/messages" not in fake.log  # refused before any lookup


@pytest.mark.parametrize("scope", MODES, ids=MODE_IDS)
async def test_out_of_scope_a_thread_entirely_in_spam_or_trash(scope: dict[str, str]) -> None:
    fake = FakeGoogle(routes={"users/me/messages": _lookup(MID, "aaaa000000000001")})
    guard = _guard(fake, **scope)
    thread = {
        "id": MID,
        "messages": [
            message(message_id=MID, labels=["Label_1", "TRASH"]),
            message(message_id="aaaa000000000001", labels=["Label_1", "SPAM"]),
        ],
    }

    assert await guard.check_thread(thread) is False
    assert "GET users/me/messages" not in fake.log


@pytest.mark.parametrize("scope", MODES, ids=MODE_IDS)
async def test_a_thread_is_judged_by_its_messages_outside_spam_and_trash(scope: dict[str, str]) -> None:
    # Only the trashed message would match the scope: the thread is out of scope.
    lookups = {"users/me/messages": _lookup(MID)}
    guard = _guard(FakeGoogle(routes=lookups), **scope)
    thread = {
        "id": MID,
        "messages": [
            message(message_id=MID, labels=["Label_1", "TRASH"]),
            message(
                message_id="aaaa000000000001", labels=["INBOX"], headers=[header("Message-ID", "<b@x.example.com>")]
            ),
        ],
    }

    expected = not scope  # with no scope, the other message alone is enough
    assert await guard.check_thread(thread) is expected


def test_visible_messages_leaves_out_spam_and_trash_and_counts_them() -> None:
    thread = {"messages": [message(labels=["INBOX"]), message(labels=["SPAM"]), message(labels=["TRASH"]), 3]}
    shown, hidden = visible_messages(thread)
    assert [m["labelIds"] for m in shown] == [["INBOX"]]
    assert hidden == 2
    assert visible_messages({}) == ([], 0)


@pytest.mark.parametrize(
    ("labels", "expected"), [(["INBOX"], False), (["SPAM"], True), (["TRASH", "INBOX"], True), ("TRASH", True)]
)
def test_in_spam_or_trash(labels: object, expected: bool) -> None:
    assert in_spam_or_trash({"labelIds": labels}) is expected
    assert in_spam_or_trash({}) is False  # no labels at all: in no folder


# --- apply(): negative ----------------------------------------------------------------------


@pytest.mark.parametrize("query", ESCAPES)
@pytest.mark.parametrize(
    "scope", [{}, {"scope_label": "Label_1"}, {"scope_query": SCOPE_QUERY}], ids=["none", "label", "query"]
)
async def test_refuses_queries_that_could_escape_the_scope(query: str, scope: dict[str, str]) -> None:
    fake = FakeGoogle()
    with pytest.raises(QueryRejectedError, match="the search query is refused"):
        await _guard(fake, **scope).apply(query=query)
    assert fake.requests == []


@pytest.mark.parametrize("query", ESCAPES)
def test_refuses_escapes_in_check_user_query(query: str) -> None:
    with pytest.raises(QueryRejectedError):
        check_user_query(query)


async def test_refuses_include_spam_trash_from_the_caller() -> None:
    params = await _guard(FakeGoogle()).apply({"includeSpamTrash": True})
    assert params["includeSpamTrash"] is False


async def test_refuses_a_query_smuggled_in_params() -> None:
    with pytest.raises(ValueError, match="apply\\(query="):
        await _guard(FakeGoogle(), scope_query=SCOPE_QUERY).apply({"q": ") OR (in:anywhere"})


async def test_refuses_to_run_with_an_unknown_scope_label() -> None:
    fake = FakeGoogle()
    guard = _guard(fake, scope_label="Projects/Nope")

    with pytest.raises(ScopeConfigError, match="GMAIL_SCOPE_LABEL=Projects/Nope matches no label") as info:
        await guard.apply(query="x")
    assert "refuses to run" in str(info.value)
    # Remembered: apply, resolve and the checks all refuse, without another labels.list.
    for call in (guard.apply(query="x"), guard.resolve(), guard.check_message(message()), guard.check_thread({})):
        with pytest.raises(ScopeConfigError):
            await call
    assert fake.log.count("GET users/me/labels") == 1


async def test_refuses_an_ambiguous_casefold_label_name() -> None:
    labels = {"labels": [{"id": "Label_1", "name": "Acme"}, {"id": "Label_2", "name": "ACME"}]}
    guard = _guard(FakeGoogle(routes={"users/me/labels": labels}), scope_label="acme")
    with pytest.raises(ScopeConfigError):
        await guard.resolve()


# --- check_message(): positive --------------------------------------------------------------


async def test_without_scope_every_message_outside_spam_and_trash_is_in_scope_and_nothing_is_fetched() -> None:
    fake = FakeGoogle()
    guard = _guard(fake)
    assert await guard.check_message(message(labels=["INBOX"])) is True
    unlabelled = message()
    del unlabelled["labelIds"]  # archived with no label: in no folder, so not in spam or trash
    assert await guard.check_message(unlabelled) is True
    assert await guard.check_thread({"messages": [message(labels=["TRASH"]), message(labels=["INBOX"])]}) is True
    assert fake.requests == []


async def test_label_scope_message_with_the_label_is_in_scope() -> None:
    guard = _guard(FakeGoogle(), scope_label="Label_1")
    assert await guard.check_message(message(labels=["INBOX", "Label_1"])) is True


async def test_query_scope_message_found_by_rfc822msgid_is_in_scope() -> None:
    fake = FakeGoogle(routes={"users/me/messages": _lookup("ffff000011112222", MID)})
    guard = _guard(fake, scope_query=SCOPE_QUERY)

    assert await guard.check_message(message(message_id=MID)) is True

    assert fake.params(-1)["q"] == [f"({SCOPE_QUERY}) rfc822msgid:{RFC822}"]
    assert fake.params(-1)["includeSpamTrash"] == ["false"]


async def test_both_scopes_need_both_checks() -> None:
    fake = FakeGoogle(routes={"users/me/messages": _lookup(MID)})
    guard = _guard(fake, scope_label="Label_1", scope_query=SCOPE_QUERY)
    assert await guard.check_message(message(message_id=MID, labels=["Label_1"])) is True


async def test_a_thread_is_in_scope_when_any_message_is() -> None:
    guard = _guard(FakeGoogle(), scope_label="Label_1")
    thread = {"id": MID, "messages": [message(message_id="aaaa000000000001"), message(labels=["Label_1"])]}
    assert await guard.check_thread(thread) is True


def test_message_id_header_strips_angle_brackets() -> None:
    assert message_id_header(message()) == RFC822


# --- check_message(): negative --------------------------------------------------------------


async def test_out_of_scope_label_missing() -> None:
    guard = _guard(FakeGoogle(), scope_label="Label_1")
    assert await guard.check_message(message(labels=["INBOX", "Label_2"])) is False


@pytest.mark.parametrize("excluded", ["SPAM", "TRASH"])
async def test_out_of_scope_in_spam_or_trash_even_with_the_label(excluded: str) -> None:
    guard = _guard(FakeGoogle(), scope_label="Label_1")
    assert await guard.check_message(message(labels=["Label_1", excluded])) is False


async def test_out_of_scope_label_ids_absent() -> None:
    guard = _guard(FakeGoogle(), scope_label="Label_1")
    msg = message()
    del msg["labelIds"]
    assert await guard.check_message(msg) is False


async def test_out_of_scope_without_a_message_id_and_nothing_is_fetched() -> None:
    fake = FakeGoogle()
    guard = _guard(fake, scope_query=SCOPE_QUERY)
    no_header = message(headers=[header("From", "ada@example.com"), header("Subject", "x")])

    assert await guard.check_message(no_header) is False
    assert fake.log == []


@pytest.mark.parametrize(
    "value",
    [
        "<a) OR (in:inbox@example.com>",
        "<x@example.com> OR in:inbox",
        '<"quoted"@example.com>',
        "<x{y}@example.com>",
        "<x:y@example.com>",
        "",
        "<>",
    ],
)
async def test_out_of_scope_with_an_unusable_message_id_and_nothing_is_fetched(value: str) -> None:
    fake = FakeGoogle()
    guard = _guard(fake, scope_query=SCOPE_QUERY)
    crafted = message(headers=[header("Message-ID", value)])

    assert await guard.check_message(crafted) is False
    assert fake.log == []


async def test_out_of_scope_when_the_lookup_returns_other_ids() -> None:
    guard = _guard(FakeGoogle(routes={"users/me/messages": _lookup("ffff000011112222")}), scope_query=SCOPE_QUERY)
    assert await guard.check_message(message(message_id=MID)) is False


async def test_out_of_scope_when_the_lookup_is_empty() -> None:
    guard = _guard(FakeGoogle(routes={"users/me/messages": {"resultSizeEstimate": 0}}), scope_query=SCOPE_QUERY)
    assert await guard.check_message(message(message_id=MID)) is False


@pytest.mark.parametrize(
    "failure",
    [api_error(400, "invalidArgument"), api_error(403, "insufficientPermissions"), httpx.Response(200, text="<html>")],
    ids=["400", "403", "non-json"],
)
async def test_out_of_scope_when_the_lookup_fails(failure: httpx.Response) -> None:
    guard = _guard(FakeGoogle(routes={"users/me/messages": failure}), scope_query=SCOPE_QUERY)
    assert await guard.check_message(message(message_id=MID)) is False


async def test_out_of_scope_when_the_lookup_cannot_connect() -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    guard = _guard(FakeGoogle(routes={"users/me/messages": down}), scope_query=SCOPE_QUERY)
    assert await guard.check_message(message(message_id=MID)) is False


async def test_out_of_scope_both_label_ok_query_fails() -> None:
    fake = FakeGoogle(routes={"users/me/messages": _lookup()})
    guard = _guard(fake, scope_label="Label_1", scope_query=SCOPE_QUERY)
    assert await guard.check_message(message(message_id=MID, labels=["Label_1"])) is False


async def test_out_of_scope_both_query_ok_label_fails_and_the_query_is_not_even_sent() -> None:
    fake = FakeGoogle(routes={"users/me/messages": _lookup(MID)})
    guard = _guard(fake, scope_label="Label_1", scope_query=SCOPE_QUERY)
    assert await guard.check_message(message(message_id=MID, labels=["INBOX"])) is False
    assert "GET users/me/messages" not in fake.log


async def test_out_of_scope_a_message_without_an_id() -> None:
    guard = _guard(FakeGoogle(), scope_label="Label_1")
    msg = message(labels=["Label_1"])
    del msg["id"]
    assert await guard.check_message(msg) is False


async def test_out_of_scope_a_thread_where_no_message_is() -> None:
    guard = _guard(FakeGoogle(), scope_label="Label_1")
    thread = {"messages": [message(labels=["INBOX"]), message(labels=["Label_1", "TRASH"])]}
    assert await guard.check_thread(thread) is False


@pytest.mark.parametrize("thread", [{}, {"messages": []}, {"messages": "nope"}, {"messages": [None, 3]}])
async def test_out_of_scope_an_empty_or_malformed_thread(thread: dict[str, Any]) -> None:
    guard = _guard(FakeGoogle(), scope_label="Label_1")
    assert await guard.check_thread(thread) is False


async def test_out_of_scope_a_thread_whose_lookup_fails() -> None:
    guard = _guard(FakeGoogle(routes={"users/me/messages": api_error(400)}), scope_query=SCOPE_QUERY)
    assert await guard.check_thread({"messages": [message(message_id=MID)]}) is False


# --- query size: every list call and lookup fits Gmail's URL limit (validators.py) -------------

WORST_PAGE_TOKEN = "=" * 1024  # the longest page_token validators accept, every character `%3D`
LONG_LABEL_ID = "Label_" + "9" * 122  # 128 characters, the longest label id validators accept
# Every character _MESSAGE_ID_RE lets into a lookup that httpx percent-encodes, 995 of them.
WORST_RFC822 = ("!#$%&'*+/=?^" * 83)[:995]
CHARS = [FOUR_BYTES, CJK, "é"]
CHAR_IDS = ["4-byte", "CJK", "accented"]


@pytest.mark.parametrize(
    ("char", "encoded"),
    [("a", 1), (" ", 1), ("(", 3), (":", 3), ('"', 3), ("=", 3), ("é", 6), ("€", 9), (CJK, 9), (FOUR_BYTES, 12)],
)
def test_encoded_length_is_what_httpx_puts_in_the_url(char: str, encoded: int) -> None:
    text = char * 100
    request = httpx.Request("GET", f"{API_BASE}/{LIST_PATH}", params={"q": text})
    assert encoded_length(text) == len(request.url.query) - len("q=") == 100 * encoded


def test_request_target_is_what_the_client_sends() -> None:
    params = {"maxResults": 100, "pageToken": WORST_PAGE_TOKEN, "includeSpamTrash": False, "labelIds": ["A", "B"]}
    request = httpx.Request("GET", f"{API_BASE}/{LIST_PATH}", params=_wire_params(params))
    assert request_target(LIST_PATH, {**params, "skipped": None}) == len(request.url.raw_path)


def test_the_bound_keeps_a_margin_under_gmails_measured_limit() -> None:
    assert GMAIL_MAX_REQUEST_TARGET == GMAIL_REQUEST_TARGET_LIMIT
    assert MAX_REQUEST_TARGET == GMAIL_MAX_REQUEST_TARGET - 1_024


@pytest.mark.parametrize("char", CHARS, ids=CHAR_IDS)
async def test_the_worst_list_call_at_both_encoded_caps_reaches_the_wire_under_the_bound(char: str) -> None:
    scope = text_of_encoded_size(char, MAX_SCOPE_QUERY_ENCODED)
    query = text_of_encoded_size(char, MAX_QUERY_ENCODED)
    labels = {"labels": [{"id": LONG_LABEL_ID, "name": "Projects/Long", "type": "user"}]}
    fake = FakeGoogle(routes={"users/me/labels": labels, "users/me/messages": {}, "users/me/threads": {}})
    settings = make_settings(scope_query=scope, scope_label=LONG_LABEL_ID)
    client = make_client(fake, settings)
    params = await ScopeGuard(settings, client).apply({"maxResults": 100, "pageToken": WORST_PAGE_TOKEN}, query=query)

    for path in ("users/me/messages", "users/me/threads"):
        await client.get(path, params)

    listed = [request for request in fake.api_requests if request.url.path.endswith(("/messages", "/threads"))]
    assert len(listed) == 2
    for request in listed:
        sent = parse_qs(request.url.query.decode(), keep_blank_values=True)
        assert sent["q"] == [f"({scope}) ({query}) {EXCLUDE_SPAM_TRASH}"]
        assert sent["pageToken"] == [WORST_PAGE_TOKEN] and sent["labelIds"] == [LONG_LABEL_ID]
    # The figure validators.py records (update both together): the messages path is the longer.
    assert [len(request.url.raw_path) for request in listed] == [15_325, 15_324]
    assert longest_request_target(fake) <= MAX_REQUEST_TARGET < GMAIL_REQUEST_TARGET_LIMIT


@pytest.mark.parametrize("char", CHARS, ids=CHAR_IDS)
async def test_the_worst_scope_lookup_at_the_scope_cap_reaches_the_wire_under_the_bound(char: str) -> None:
    scope = text_of_encoded_size(char, MAX_SCOPE_QUERY_ENCODED)
    fake = FakeGoogle(routes={"users/me/messages": _lookup(MID)})
    guard = _guard(fake, scope_query=scope)
    found = message(message_id=MID, headers=[header("Message-ID", f"<{WORST_RFC822}>")])
    assert message_id_header(found) == WORST_RFC822

    assert await guard.check_message(found) is True

    [lookup] = [request for request in fake.api_requests if request.url.path.endswith("/users/me/messages")]
    assert parse_qs(lookup.url.query.decode())["q"] == [f"({scope}) rfc822msgid:{WORST_RFC822}"]
    assert len(lookup.url.raw_path) == 9_073  # the figure validators.py records
    assert request_target(LIST_PATH, _lookup_params(scope, WORST_RFC822)) == 9_073


@pytest.mark.parametrize("char", CHARS, ids=CHAR_IDS)
async def test_refuses_a_query_one_past_the_encoded_cap_even_when_a_caller_skips_the_params_model(
    char: str,
) -> None:
    fake = FakeGoogle()
    guard = _guard(fake, scope_query=text_of_encoded_size(char, MAX_SCOPE_QUERY_ENCODED))
    at = text_of_encoded_size(char, MAX_QUERY_ENCODED)
    assert (await guard.apply(query=at))["q"].startswith("(")

    with pytest.raises(
        QueryRejectedError, match=f"once percent-encoded for the URL, the most is {MAX_QUERY_ENCODED:,}"
    ):
        await guard.apply(query=at + "a")
    assert [r for r in fake.requests if r.url.path.endswith("/messages")] == []


async def test_refuses_an_ascii_query_one_past_the_character_cap_when_a_caller_skips_the_params_model() -> None:
    fake = FakeGoogle()
    guard = _guard(fake)
    assert (await guard.apply(query="x" * MAX_QUERY_CHARS))["q"] == f"({'x' * MAX_QUERY_CHARS}) {EXCLUDE_SPAM_TRASH}"
    with pytest.raises(QueryRejectedError, match=f"the most is {MAX_QUERY_CHARS:,}"):
        await guard.apply(query="x" * (MAX_QUERY_CHARS + 1))
    assert fake.requests == []


async def test_refuses_a_query_that_is_not_utf8_when_a_caller_skips_the_params_model() -> None:
    fake = FakeGoogle()
    with pytest.raises(QueryRejectedError, match="not valid UTF-8 text"):
        await _guard(fake).apply(query="invoice \udcff")
    assert fake.requests == []


@pytest.mark.parametrize(
    "extra",
    [{"pageToken": "a" * 20_000}, {"labelIds": ["L" * 20_000]}, {"pageToken": "\udcff"}],
    ids=["page-token", "label-ids", "not-utf8"],
)
async def test_refuses_a_list_call_whose_measured_url_would_be_too_long_and_sends_nothing(
    extra: dict[str, Any],
) -> None:
    # A caller that puts something long in params: apply() measures what it composed.
    fake = FakeGoogle()
    with pytest.raises(QueryRejectedError, match=f"the most is {MAX_REQUEST_TARGET:,} \\(Gmail refuses"):
        await _guard(fake).apply(extra, query="invoice")
    assert fake.requests == []


async def test_refuses_a_list_call_when_gmail_resolves_the_scope_label_to_an_overlong_id() -> None:
    labels = {"labels": [{"id": "L" * 20_000, "name": "Projects/Odd", "type": "user"}]}
    fake = FakeGoogle(routes={"users/me/labels": labels})
    with pytest.raises(QueryRejectedError, match="the search is refused: its URL would be"):
        await _guard(fake, scope_label="Projects/Odd").apply(query="invoice")
    assert [r for r in fake.requests if r.url.path.endswith("/messages")] == []


async def test_a_query_at_the_cap_counts_characters_after_whitespace_is_collapsed() -> None:
    guard = _guard(FakeGoogle())
    padded = "  " + FOUR_BYTES * 250 + "   \n\t  " + FOUR_BYTES * 249 + " \n"  # longer raw, 5,989 encoded collapsed
    assert encoded_length(padded) > MAX_QUERY_ENCODED
    params = await guard.apply(query=padded)
    assert params["q"] == f"({FOUR_BYTES * 250} {FOUR_BYTES * 249}) {EXCLUDE_SPAM_TRASH}"
