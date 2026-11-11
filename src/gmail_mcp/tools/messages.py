"""Message tools — `gmail_search_messages` and `gmail_get_message`.

- **Search.** `messages.list` runs with the project scope applied by `scope.apply()`
  (`labelIds[]`, the query as `(<scope>) (<query>)`, `includeSpamTrash=false`). Each hit's
  metadata (From, Subject, Date, labels, snippet) comes from one `messages.get` with
  `format=metadata`, fanned out with `client.batch_get` (at most 10 in flight). A hit
  whose metadata cannot be read is listed with the reason; when every one fails, the call
  fails with the first error. A hit whose metadata `labelIds` carry SPAM or TRASH is left
  out and counted in a note: `-in:spam -in:trash` keeps them out of the list already, and
  the labels are checked too, as gmail_get_message, gmail_get_thread and the thread
  summaries do, so no surface relies on Gmail's query parsing alone.
- **Read.** `scope.fetch_message()` (the spine's one fetch-by-id helper) with `format=full`
  (it carries `labelIds` and the Message-ID header): the account pin first, then the GET,
  the returned id compared, and `scope.check_message()` BEFORE anything is rendered. Out of
  scope, a 404 and a 400 for an id Gmail cannot parse all give the same
  `NotFoundInScopeError`, which names only the id; any other error keeps its cause. The
  body goes through `formatters.extract_body` and is paged by characters
  (`GMAIL_BODY_MAX_CHARS`, `offset`); attachments are listed, never inlined.

Everything mail-derived is collapsed to one line (headers, snippets, filenames) or fenced
(the body), and every result passes through `clip_response` (token redaction, size cap).
Every field is bounded (formatters' MAX_* caps), so clip_response never cuts a search's
`page_token` or the body note: a full page at the largest GMAIL_BODY_MAX_CHARS fits, and
`fit_page` shrinks the window (the note follows) if a response ever would not.
"""

from __future__ import annotations

import html
import re
from collections.abc import Mapping
from typing import Any

from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, field_validator

from gmail_mcp import validators
from gmail_mcp.client import get_client
from gmail_mcp.config import get_settings
from gmail_mcp.errors import describe_error, tool_error
from gmail_mcp.formatters import (
    MAX_ID_CHARS,
    MAX_SNIPPET_CHARS,
    MAX_SUMMARY_CHARS,
    Body,
    TextPage,
    clip_response,
    decode_header_value,
    extract_body,
    fit_page,
    fmt_internal_date,
    header_values,
    headers_subset,
    labels_line,
    list_attachments,
    one_line,
    page_note,
    page_text,
    render_attachments,
    render_headers,
    shorten,
)
from gmail_mcp.scope import ResolvedScope, get_scope, in_spam_or_trash
from gmail_mcp.server import mcp

# `format=metadata` keeps a search hit cheap (5 quota units instead of 20 for `full`).
SEARCH_HEADERS: tuple[str, ...] = ("From", "Subject", "Date")
METADATA_PARAMS: dict[str, Any] = {"format": "metadata", "metadataHeaders": list(SEARCH_HEADERS)}
# `format=full` is the one that carries both `labelIds` and the Message-ID header the
# query-scope check needs, plus the body.
FULL_PARAMS: dict[str, Any] = {"format": "full"}


class SearchMessagesInput(BaseModel):
    """Arguments for `gmail_search_messages`."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    query: str | None = Field(
        default=None,
        max_length=validators.MAX_QUERY_CHARS,
        description=(
            "Gmail search query, as in the Gmail search box: `from:ada@example.com`, `subject:invoice`, "
            '`"exact phrase"`, `has:attachment`, `after:2026/10/01 before:2026/11/01`, `newer_than:7d`, '
            "`is:unread`, `label:receipts`, `-word`, `{a b}` (either), `(a b)` (group). Parentheses and braces must "
            "balance outside double quotes. Omit it to list the newest messages in scope. " + validators.QUERY_SIZE_HELP
        ),
    )
    max_results: int = Field(
        default=validators.DEFAULT_MAX_RESULTS,
        ge=1,
        le=validators.MAX_MAX_RESULTS,
        description=f"Messages per page, 1–{validators.MAX_MAX_RESULTS} (default {validators.DEFAULT_MAX_RESULTS}).",
    )
    page_token: str | None = Field(
        default=None,
        description="The `page_token` a previous call printed, to get the next page of the same search.",
    )

    @field_validator("query", mode="before")
    @classmethod
    def _query(cls, value: object) -> str | None:
        if value is None:
            return None
        return validators.search_query(value) or None

    @field_validator("max_results", mode="before")
    @classmethod
    def _max_results(cls, value: object) -> int:
        return validators.max_results(value)

    @field_validator("page_token", mode="before")
    @classmethod
    def _page_token(cls, value: object) -> str | None:
        if value is None or (isinstance(value, str) and not value.strip()):
            return None  # a blank token is the first page, as an omitted one
        return validators.page_token(value)


class GetMessageInput(BaseModel):
    """Arguments for `gmail_get_message`."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    message_id: str = Field(
        description="The message `id` a search printed (e.g. `18c2f0e9a1b2c3d4`), not the Message-ID header.",
    )
    offset: int = Field(
        default=0,
        ge=0,
        le=validators.MAX_OFFSET,
        description="Character offset into the body (default 0). Pass the `offset` the previous call printed.",
    )

    @field_validator("message_id", mode="before")
    @classmethod
    def _message_id(cls, value: object) -> str:
        return validators.message_id(value)

    @field_validator("offset", mode="before")
    @classmethod
    def _offset(cls, value: object) -> int:
        return validators.offset(value)


# --- rendering ---------------------------------------------------------------------------


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _usable_id(value: Any) -> str | None:
    """`value` when it is a message id this server may put in a path, else `None`."""
    try:
        return validators.message_id(value) if isinstance(value, str) else None
    except ValueError:
        return None


def _first_header(payload: Mapping[str, Any], name: str) -> str:
    for value in header_values(payload, name):
        decoded = decode_header_value(value)
        if decoded:
            return decoded
    return ""


def _date(message: Mapping[str, Any]) -> str:
    """`internalDate` (when Gmail received it, UTC), else the Date header, else `N/A`."""
    received = fmt_internal_date(message.get("internalDate"))
    if received != "N/A":
        return received
    return shorten(_first_header(_mapping(message.get("payload")), "Date"), MAX_SUMMARY_CHARS) or "N/A"


def _short_id(value: Any) -> str:
    """An id Gmail sent, on one line and bounded (never validated: it is only shown)."""
    return shorten(one_line(str(value or "N/A")), MAX_ID_CHARS)


def _scope_line(scope: ResolvedScope) -> str | None:
    if scope.mode == "none":
        return None
    parts = []
    if scope.label_id is not None:
        parts.append(f"label `{shorten(one_line(scope.label_name or scope.label_id), MAX_SUMMARY_CHARS)}`")
    if scope.query is not None:
        parts.append(f"query `({shorten(one_line(scope.query), validators.MAX_SCOPE_QUERY_CHARS)})`")
    return f"Scope: {' + '.join(parts)} — results are limited to it (a filter; see gmail_health)."


def _render_hit(index: int, hit: Mapping[str, Any], meta: Mapping[str, Any] | Exception) -> str:
    """One search hit; every field is bounded, so 100 hits always fit one response."""
    message_id = str(hit.get("id"))  # validated by the caller (_usable_id)
    if isinstance(meta, Exception):
        thread = _short_id(hit.get("threadId"))
        error = shorten(describe_error(meta), MAX_SUMMARY_CHARS)
        return f"{index}. _metadata unavailable_ — {error}\n   id `{message_id}` · threadId `{thread}`"
    payload = _mapping(meta.get("payload"))
    subject = shorten(_first_header(payload, "Subject"), MAX_SUMMARY_CHARS) or "(no subject)"
    sender = shorten(_first_header(payload, "From"), MAX_SUMMARY_CHARS) or "(unknown sender)"
    thread = _short_id(meta.get("threadId") or hit.get("threadId"))
    snippet = shorten(one_line(html.unescape(str(meta.get("snippet") or ""))), MAX_SNIPPET_CHARS)
    lines = [
        f"{index}. **{subject}** — from {sender} · {_date(meta)}",
        f"   id `{message_id}` · threadId `{thread}` · labels: {labels_line(meta.get('labelIds'))}",
    ]
    if snippet:
        lines.append(f"   snippet: {snippet}")
    return "\n".join(lines)


def _visible_hits(
    hits: list[Mapping[str, Any]], metas: list[Mapping[str, Any] | Exception]
) -> tuple[list[Mapping[str, Any]], list[Mapping[str, Any] | Exception], int]:
    """The hits that may be shown, their metadata, and how many were left out for SPAM or TRASH.

    A hit whose metadata could not be read stays (it shows only its id and the cause, nothing of
    the message): its labels are unknown, and the list already ran with `-in:spam -in:trash`.
    """
    shown = [
        (hit, meta)
        for hit, meta in zip(hits, metas, strict=True)
        if isinstance(meta, Exception) or not in_spam_or_trash(meta)
    ]
    return [hit for hit, _ in shown], [meta for _, meta in shown], len(hits) - len(shown)


def _render_search(
    params: SearchMessagesInput,
    scope: ResolvedScope,
    body: Mapping[str, Any],
    hits: list[Mapping[str, Any]],
    metas: list[Mapping[str, Any] | Exception],
    skipped: int,
    hidden: int = 0,
) -> str:
    query = shorten(params.query, validators.MAX_QUERY_CHARS) if params.query else None
    title = f"# Gmail search: `{query}`" if query else "# Gmail search (no query: newest first)"
    lines = [title, ""]
    scope_line = _scope_line(scope)
    if scope_line:
        lines.append(scope_line)
    next_token = body.get("nextPageToken")
    estimate = body.get("resultSizeEstimate")
    summary = f"**{len(hits)}** message(s) on this page"
    if isinstance(estimate, int) and not isinstance(estimate, bool):
        summary += f" (Gmail estimates about {estimate} in total)"
    lines.append(summary + ".")
    if hidden:
        lines.append(
            f"{hidden} message(s) Gmail listed on this page are in spam or trash: never shown, not counted above."
        )
    if skipped:
        lines.append(f"{skipped} hit(s) with an id this server cannot use were skipped.")
    if isinstance(next_token, str) and next_token:
        token = _usable_token(next_token)
        lines.append(
            f"More available — pass `page_token` = `{token}` to get the next page."
            if token
            else "More available, but Gmail's page token is not one this server can pass back: narrow the query."
        )
    lines.append("")
    if not hits:
        if hidden:
            lines.append("_Nothing on this page can be shown: every message Gmail listed is in spam or trash._")
        elif params.page_token:
            lines.append("_No more messages: this page is past the last one._")
        else:
            hint = "Check the query syntax (from:, subject:, after:YYYY/MM/DD, has:attachment)"
            if scope.mode != "none":
                hint += "; only messages inside the scope above are searched"
            lines.append(f"_No messages matched._ {hint}.")
        return "\n".join(lines)
    for index, (hit, meta) in enumerate(zip(hits, metas, strict=True), start=1):
        lines.append(_render_hit(index, hit, meta))
    lines.append("")
    lines.append("Read one with `gmail_get_message` (its `id`); `gmail_list_labels` maps label ids to names.")
    return "\n".join(lines)


def _usable_token(value: str) -> str | None:
    """Gmail's `nextPageToken` when `page_token` would accept it back (bounded, one line), else None."""
    try:
        return validators.page_token(value)
    except ValueError:
        return None


def _fenced(text: str) -> str:
    """`text` in a code fence longer than any backtick run inside it (mail content stays inside)."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}text\n{text}\n{fence}"


def _render_message(message: Mapping[str, Any], offset: int, max_chars: int) -> str:
    """The message with the body window `[offset, offset + max_chars)`, shrunk if the response would not fit."""
    payload = _mapping(message.get("payload"))
    body = extract_body(payload)
    page = page_text(body.text, offset, max_chars)
    rendered, _ = fit_page(lambda window: _render_page(message, body, offset, window), page)
    return rendered


def _render_page(message: Mapping[str, Any], body: Body, offset: int, page: TextPage) -> str:
    payload = _mapping(message.get("payload"))
    message_id = _short_id(message.get("id"))
    lines = [
        f"# Gmail message `{message_id}`",
        "",
        f"- **threadId**: `{_short_id(message.get('threadId'))}`",
        f"- **labels**: {labels_line(message.get('labelIds'))}",
        f"- **received**: {fmt_internal_date(message.get('internalDate'))}",
    ]
    headers = render_headers(headers_subset(payload))
    if headers:
        lines.append(headers)

    source = {"text/plain": "text/plain", "text/html": "text/html, converted to text"}.get(body.source)
    lines.extend(["", f"## Body ({source})" if source else "## Body", ""])
    if offset > 0 and offset >= page.total:
        if page.total:
            lines.append(
                f"[body: offset {offset} is past the end of the body ({page.total} characters): pass an offset "
                f"from 0 to {page.total - 1}]"
            )
        else:
            lines.append("[body: empty]")
    else:
        lines.append(page_note(page))
        if page.text:
            lines.append(_fenced(page.text))
    if body.external_parts:
        # Their attachmentIds are not printed (ADR-0002: they rotate on every read, and are not parts
        # gmail_get_attachment saves).
        lines.append(f"[Gmail stored {len(body.external_parts)} text part(s) outside the message, not shown]")

    attachments = list_attachments(payload)
    lines.extend(["", f"## Attachments ({len(attachments)})", "", render_attachments(attachments)])
    return "\n".join(lines)


# --- tools -------------------------------------------------------------------------------


@mcp.tool(
    name="gmail_search_messages",
    annotations=ToolAnnotations(
        title="Search Gmail Messages",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def gmail_search_messages(params: SearchMessagesInput) -> str:
    """Search messages with Gmail's query syntax and list each hit's metadata (the project scope applied).

    Calls `messages.list` with the active project scope added by the server
    (GMAIL_SCOPE_LABEL as a label filter, GMAIL_SCOPE_QUERY ANDed as `(<scope>) (<query>)`),
    spam and trash always excluded, then reads each hit's From, Subject and Date headers,
    labels and snippet (`format=metadata`, at most 10 requests in flight). Newest first.

    Query syntax (as in the Gmail search box, combine freely):
    - `from:ada@example.com`, `to:`, `cc:`, `subject:invoice`, `"exact phrase"`, `-word`
    - `after:2026/10/01`, `before:2026/11/01`, `newer_than:7d`, `older_than:1y`
    - `has:attachment`, `filename:pdf`, `is:unread`, `is:starred`, `label:receipts`
    - `{a b}` = a OR b; `(a b)` groups. Parentheses and braces must balance outside
      double quotes (a query that could break out of the scope is refused).

    When to Use:
    - To find messages and get their `id` for `gmail_get_message`.
    - To skim what arrived (omit `query`: the newest messages in scope).
    - To get a message's `threadId` for `gmail_get_thread`.

    When NOT to Use:
    - To read a body (use `gmail_get_message`) or a whole conversation (use
      `gmail_search_threads` / `gmail_get_thread`).
    - To list labels (use `gmail_list_labels`).

    Returns:
    Markdown: the active scope (if any), how many messages are on the page (and Gmail's
    estimate of the total), the next `page_token` when there are more, then per message
    the subject, the sender, the date (UTC), the `id`, the `threadId`, the label ids and
    the snippet. A hit labelled SPAM or TRASH is never shown: a one-line note counts it.

    Pagination:
    Pass the printed `page_token` with the same `query` to get the next page.

    Examples:
    - params = {"query": "from:ada@example.com has:attachment newer_than:30d"}
    - params = {"query": "subject:invoice", "max_results": 50}
    - params = {"query": "subject:invoice", "page_token": "<the page_token printed before>"}
    - params = {} (the newest 20 messages in scope)

    Error Handling:
    A query that could escape the scope (unbalanced parentheses or braces, an unclosed
    quote) is refused before anything is sent. A dead token, a token for another mailbox
    (pin mismatch) or an unknown GMAIL_SCOPE_LABEL fail with one line naming the fix; a
    400 means Gmail rejected the query or the page token.
    """
    try:
        scope = get_scope()
        # First: the scope refuses an escaping query before any request is sent.
        list_params = await scope.apply(
            {"maxResults": params.max_results, "pageToken": params.page_token}, query=params.query
        )
        resolved = await scope.resolve()
        client = get_client()
        body = await client.get("users/me/messages", list_params)
        raw = body.get("messages")
        listed = [hit for hit in raw if isinstance(hit, Mapping)] if isinstance(raw, list) else []
        hits = [hit for hit in listed if _usable_id(hit.get("id")) is not None]
        metas: list[Mapping[str, Any] | Exception] = []
        if hits:
            results = await client.batch_get(
                [(f"users/me/messages/{hit['id']}", METADATA_PARAMS) for hit in hits], return_exceptions=True
            )
            failures = [result for result in results if isinstance(result, Exception)]
            if len(failures) == len(results):
                raise failures[0]  # nothing readable: the cause, not a page of identical errors
            metas = list(results)
        skipped = len(listed) - len(hits)
        # Spam and trash are never shown, here as in get_message, get_thread and the thread
        # summaries: by the labels each hit carries, not only by the query's `-in:spam -in:trash`.
        shown, shown_metas, hidden = _visible_hits(hits, metas)
        return clip_response(_render_search(params, resolved, body, shown, shown_metas, skipped, hidden))
    except Exception as exc:
        raise tool_error(exc) from None


@mcp.tool(
    name="gmail_get_message",
    annotations=ToolAnnotations(
        title="Get Gmail Message",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def gmail_get_message(params: GetMessageInput) -> str:
    """Read one message: its headers, the text body (capped, paged with `offset`) and its attachment list.

    Calls `messages.get` with `format=full`, then checks the message against the project
    scope BEFORE showing anything: a message outside the scope is reported exactly like an
    id that does not exist. The body is the message's text/plain part (or its HTML turned
    into text), at most GMAIL_BODY_MAX_CHARS characters per call. Attachments are listed
    with their `partId`, never inlined.

    When to Use:
    - To read a message a search found (pass its `id`).
    - To get the rest of a long body (pass the `offset` the previous call printed).
    - To see a message's attachments and their partIds for `gmail_get_attachment`.

    When NOT to Use:
    - To find messages (use `gmail_search_messages`).
    - To read a whole conversation in order (use `gmail_get_thread`).
    - To download an attachment (use `gmail_get_attachment`).

    Returns:
    Markdown: the `id`, `threadId`, label ids and received date; the From, To, Cc, Date,
    Subject and Message-ID headers; the body window with a line saying which characters
    it holds and the `offset` for the next part; then the attachments (filename,
    mimeType, size, partId).

    Pagination:
    The body is paged by characters: pass `offset` = the number the body line prints until
    it says "end of the body" or "complete".

    Examples:
    - params = {"message_id": "18c2f0e9a1b2c3d4"}
    - params = {"message_id": "18c2f0e9a1b2c3d4", "offset": 20000}

    Error Handling:
    "was not found in this mailbox scope" = the id does not exist, or the message is
    outside GMAIL_SCOPE_LABEL / GMAIL_SCOPE_QUERY (the two look the same on purpose): search
    for it first and check the scope with `gmail_health`. A dead token or a token for
    another mailbox fail with one line naming the fix.
    """
    try:
        settings = get_settings()
        # Pin, scope, GET, id compare and scope check: one helper, so no step can be dropped.
        message = await get_scope().fetch_message(params.message_id, FULL_PARAMS)
        return clip_response(_render_message(message, params.offset, settings.body_max_chars))
    except Exception as exc:
        raise tool_error(exc) from None
