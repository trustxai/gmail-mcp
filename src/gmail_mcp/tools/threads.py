"""Thread tools — `gmail_search_threads` and `gmail_get_thread`: whole conversations.

- **Search.** `threads.list` with the project scope applied by `scope.apply()` (the scope
  label as `labelIds[]`, the scope query parenthesised, spam and trash excluded), then one
  `threads.get?format=metadata` per hit through `client.batch_get` (at most 10 in flight)
  for the summary: subject, participants, message count, last date and snippet. A hit
  whose summary cannot be fetched still shows its id, with the cause — never Gmail's thread
  snippet, which may come from a message in spam or trash.
- **Read.** `scope.fetch_thread()` (the spine's one fetch-by-id helper) with `format=full`:
  the account pin first, then the GET, the returned id compared, and `scope.check_thread()`
  BEFORE anything is rendered. A thread outside the scope, a 404 and a 400 for an id Gmail
  cannot parse get the same `NotFoundInScopeError`, so not even its subject leaks (ADR D5:
  a thread is in scope if any of its messages is); any other error keeps its cause.
  Messages in spam or trash are never shown: they are left out of the thread (and of its
  scope check), counted in a note, and a thread with nothing else is "not found". Messages
  are rendered in Gmail's order (oldest first), each with the
  header subset and its text body from `formatters`, inside two caps: `MESSAGE_MAX_CHARS`
  body characters per message (or GMAIL_BODY_MAX_CHARS if smaller) and GMAIL_BODY_MAX_CHARS
  body characters per call across the thread. `offset` is a MESSAGE index; every message
  not shown — before the page, after it, or past the cap — is counted, with the offset that
  reaches it. A message cut at the per-message cap is read on with `gmail_get_thread` itself
  (`message_id` + `body_offset`), under the THREAD's scope check: a reply that is out of scope
  on its own (a label scope and a reply without the label) is still part of an in-scope
  thread, and `gmail_get_message` — which checks that one message — would refuse it.

Every field is bounded (formatters' MAX_* caps), so `clip_response` never cuts a search's
`page_token` or a paging note: a page of threads stops adding messages at a byte budget
(the footer says so, with the offset that reads on), and the one-message view shrinks its
window with `fit_page` if a response would not fit.
"""

from __future__ import annotations

import email.utils
import functools
import html
from collections.abc import Mapping, Sequence
from typing import Any

from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from gmail_mcp import validators
from gmail_mcp.client import get_client
from gmail_mcp.config import get_settings
from gmail_mcp.errors import NotFoundInScopeError, describe_error, tool_error
from gmail_mcp.formatters import (
    MAX_ID_CHARS,
    MAX_RESPONSE_BYTES,
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
    page_text,
    render_attachments,
    render_headers,
    response_bytes,
    shorten,
)
from gmail_mcp.scope import ResolvedScope, get_scope, visible_messages
from gmail_mcp.server import mcp

# Gmail keeps at most 100 messages in one thread.
MAX_THREAD_MESSAGES = 100
DEFAULT_MAX_MESSAGES = 20
# Body characters per message in a thread page (GMAIL_BODY_MAX_CHARS lowers it, never raises it).
MESSAGE_MAX_CHARS = 5_000
# Summary bounds for a search hit (MAX_SNIPPET_CHARS, the 200-character snippet, is formatters').
MAX_PARTICIPANTS = 10
MAX_PARTICIPANT_CHARS = 100
# Room kept outside the message blocks of a thread page: the title (a subject of up to
# MAX_HEADER_CHARS 4-byte characters), the count line, the spam/trash note and the footer.
THREAD_PAGE_RESERVE_BYTES = 16_000
SUMMARY_HEADERS: tuple[str, ...] = ("From", "To", "Cc", "Subject", "Date")
_PARTICIPANT_HEADERS: tuple[str, ...] = ("From", "To", "Cc")

_QUERY_HELP = (
    "Gmail search query (the same syntax as the Gmail search box), e.g. `from:ada@example.com`, "
    '`subject:invoice`, `after:2026/10/01 before:2026/11/01`, `has:attachment`, `is:unread`, `"exact phrase"`, '
    "`-word`, `a OR b`, `{a b}`. Parentheses and braces must balance outside double quotes. Omit it to list every "
    "thread in the scope, newest first. " + validators.QUERY_SIZE_HELP
)


# --- arguments ------------------------------------------------------------------------------


class SearchThreadsInput(BaseModel):
    """Arguments for gmail_search_threads."""

    model_config = ConfigDict(extra="forbid")

    query: str | None = Field(default=None, description=_QUERY_HELP)
    max_results: int = Field(
        default=validators.DEFAULT_MAX_RESULTS,
        ge=1,
        le=validators.MAX_MAX_RESULTS,
        description=f"Threads per page, 1–{validators.MAX_MAX_RESULTS} (default {validators.DEFAULT_MAX_RESULTS}).",
    )
    page_token: str | None = Field(
        default=None,
        description="The `page_token` a previous gmail_search_threads call printed, to get its next page.",
    )

    @field_validator("query")
    @classmethod
    def _check_query(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validators.search_query(value) or None

    @field_validator("max_results", mode="before")
    @classmethod
    def _check_max_results(cls, value: object) -> int:
        return validators.max_results(value)

    @field_validator("page_token")
    @classmethod
    def _check_page_token(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        return validators.page_token(value)


class GetThreadInput(BaseModel):
    """Arguments for gmail_get_thread."""

    model_config = ConfigDict(extra="forbid")

    thread_id: str = Field(
        description="The threadId a search printed (gmail_search_threads or gmail_search_messages), e.g. "
        "`18c2f0e9a1b2c3d4`."
    )
    offset: int = Field(
        default=0,
        ge=0,
        le=validators.MAX_OFFSET,
        description="Index of the first MESSAGE to show (0 = the oldest). Pass the offset the previous page printed "
        "to read on.",
    )
    max_messages: int = Field(
        default=DEFAULT_MAX_MESSAGES,
        ge=1,
        le=MAX_THREAD_MESSAGES,
        description=f"Messages per page, 1–{MAX_THREAD_MESSAGES} (default {DEFAULT_MAX_MESSAGES}). The body cap per "
        "call can end a page earlier; the output then says which offset continues.",
    )

    message_id: str | None = Field(
        default=None,
        description="Read on ONE message of this thread: the id a cut body names. The page is then that message "
        "alone, from `body_offset`, with up to GMAIL_BODY_MAX_CHARS body characters.",
    )
    body_offset: int = Field(
        default=0,
        ge=0,
        le=validators.MAX_OFFSET,
        description="Character offset into the body of `message_id` (only with `message_id`). Pass the "
        "`body_offset` a cut body printed.",
    )

    @field_validator("thread_id")
    @classmethod
    def _check_thread_id(cls, value: str) -> str:
        return validators.thread_id(value)

    @field_validator("message_id")
    @classmethod
    def _check_message_id(cls, value: str | None) -> str | None:
        return None if value is None else validators.message_id(value)

    @field_validator("body_offset", mode="before")
    @classmethod
    def _check_body_offset(cls, value: object) -> int:
        return validators.offset(value, field="body_offset")

    @model_validator(mode="after")
    def _one_paging_at_a_time(self) -> GetThreadInput:
        if self.message_id is None and self.body_offset:
            raise ValueError("body_offset reads on one message: pass the message_id the cut body names too")
        if self.message_id is not None and self.offset:
            raise ValueError("offset pages the thread by message; with message_id the page is that one message")
        return self

    @field_validator("offset", mode="before")
    @classmethod
    def _check_offset(cls, value: object) -> int:
        return validators.offset(value)

    @field_validator("max_messages", mode="before")
    @classmethod
    def _check_max_messages(cls, value: object) -> int:
        return validators.max_results(value, field="max_messages", high=MAX_THREAD_MESSAGES)


# --- small readers ----------------------------------------------------------------------------


def _mapping(value: Any) -> Mapping[str, Any]:
    return value if isinstance(value, Mapping) else {}


def _mappings(value: Any) -> list[Mapping[str, Any]]:
    return [item for item in value if isinstance(item, Mapping)] if isinstance(value, list) else []


def _usable_id(value: Any) -> str | None:
    """A thread id from Gmail that is safe to put in a path, else `None`."""
    try:
        return validators.thread_id(value) if isinstance(value, str) else None
    except ValueError:
        return None


def _usable_token(value: str) -> str | None:
    """Gmail's `nextPageToken` when `page_token` would accept it back (bounded, one line), else None."""
    try:
        return validators.page_token(value)
    except ValueError:
        return None


def _internal_date(message: Mapping[str, Any]) -> int | None:
    try:
        return int(str(message.get("internalDate")).strip())
    except (TypeError, ValueError):
        return None


def _snippet(value: Any) -> str:
    """Gmail's snippet (HTML entities decoded) on one line, redacted, then at most `MAX_SNIPPET_CHARS`."""
    return shorten(one_line(html.unescape(str(value or ""))), MAX_SNIPPET_CHARS)


def _subject(messages: Sequence[Mapping[str, Any]]) -> str:
    """The first subject in the thread (normally the one the conversation started with)."""
    for message in messages:
        subject = headers_subset(_mapping(message.get("payload"))).get("Subject")
        if subject:
            return subject
    return "(no subject)"


def _participants(messages: Sequence[Mapping[str, Any]]) -> list[str]:
    """Everyone on From / To / Cc, in order of first appearance, one entry per address."""
    seen: set[str] = set()
    out: list[str] = []
    for message in messages:
        payload = _mapping(message.get("payload"))
        raw = [value for name in _PARTICIPANT_HEADERS for value in header_values(payload, name)]
        for name, address in email.utils.getaddresses(raw):
            label = decode_header_value(name)
            address = one_line(address)
            key = address.lower() or label.lower()
            if not key or key in seen:
                continue
            seen.add(key)
            out.append(
                shorten(f"{label} <{address}>" if label and address else address or label, MAX_PARTICIPANT_CHARS)
            )
    return out


def _scope_line(scope: ResolvedScope) -> str | None:
    if scope.mode == "none":
        return None
    parts = []
    if scope.label_id is not None:
        name = shorten(one_line(scope.label_name or scope.label_id), MAX_SUMMARY_CHARS)
        parts.append(f"label `{name}` (id `{shorten(scope.label_id, MAX_SUMMARY_CHARS)}`)")
    if scope.query is not None:
        parts.append(f"query `({shorten(one_line(scope.query), validators.MAX_SCOPE_QUERY_CHARS)})`")
    return f"Scope: {' and '.join(parts)} — every search is limited to it (a filter, not a security boundary)."


# --- gmail_search_threads ----------------------------------------------------------------------


def _spam_trash_note(hidden: int) -> str:
    return f"{hidden} message(s) of this thread in spam or trash are never shown and not counted here."


def _render_summary(index: int, thread_id: str, hit: Mapping[str, Any], thread: Mapping[str, Any]) -> list[str]:
    # Spam and trash are never shown: the summary is built from the other messages only.
    messages, hidden = visible_messages(thread)
    if not messages:
        return [f"{index}. threadId `{thread_id}` — every message of this thread is in spam or trash (never shown)"]
    dates = [date for date in (_internal_date(message) for message in messages) if date is not None]
    last = fmt_internal_date(max(dates)) if dates else "N/A"
    count = len(messages)
    people = _participants(messages)
    shown = ", ".join(people[:MAX_PARTICIPANTS]) or "N/A"
    if len(people) > MAX_PARTICIPANTS:
        shown += f" (+{len(people) - MAX_PARTICIPANTS} more)"
    # Gmail's thread snippet may come from a message in spam or trash: then the last shown one's.
    snippet = _snippet((hit.get("snippet") if not hidden else None) or messages[-1].get("snippet") or "")
    hidden_text = f" (+{hidden} in spam or trash, not shown)" if hidden else ""
    subject = shorten(_subject(messages), MAX_SUMMARY_CHARS)
    lines = [
        f"{index}. **{subject}** · threadId `{thread_id}` · {count} message{'s' if count != 1 else ''}"
        f"{hidden_text} · last {last}",
        f"   participants: {shown}",
    ]
    if snippet:
        lines.append(f"   snippet: {snippet}")
    return lines


def _render_search(
    params: SearchThreadsInput,
    body: Mapping[str, Any],
    ids: list[str],
    hits: list[Mapping[str, Any]],
    results: list[dict[str, Any] | Exception],
    skipped: int,
    scope: ResolvedScope,
) -> str:
    query = shorten(params.query, validators.MAX_QUERY_CHARS) if params.query else None
    title = f"# Gmail threads: `{query}`" if query else "# Gmail threads (no query: every thread in scope)"
    lines = [title, ""]
    scope_line = _scope_line(scope)
    if scope_line:
        lines.append(scope_line)
    estimate = body.get("resultSizeEstimate")
    count = f"**{len(ids)}** thread(s) on this page"
    if isinstance(estimate, int) and not isinstance(estimate, bool):
        count += f" (Gmail estimates about {estimate} in total)"
    lines.append(count + ".")
    token = body.get("nextPageToken")
    if isinstance(token, str) and token:
        usable = _usable_token(token)
        lines.append(
            f"More available — pass `page_token` = `{usable}` for the next page."
            if usable
            else "More available, but Gmail's page token is not one this server can pass back: narrow the query."
        )
    if skipped:
        lines.append(f"{skipped} result(s) with an id this server will not use were skipped.")
    lines.append("")
    if not ids:
        lines.append("_No threads matched._ Check the query syntax" + (" and the scope above." if scope_line else "."))
        return "\n".join(lines)
    for index, (thread_id, hit, result) in enumerate(zip(ids, hits, results, strict=True), start=1):
        if isinstance(result, Exception):
            # The id and the cause, never the hit's snippet: Gmail's thread snippet may come from a
            # message in spam or trash, and without the thread's messages there is no telling
            # (_render_summary drops it when it can tell).
            error = shorten(describe_error(result), MAX_SUMMARY_CHARS)
            lines.append(f"{index}. threadId `{thread_id}` — summary unavailable: {error}")
            continue
        lines.extend(_render_summary(index, thread_id, hit, result))
    lines.append("")
    lines.append('Read a whole conversation with gmail_get_thread, params {"thread_id": "<threadId>"}.')
    return "\n".join(lines)


@mcp.tool(
    name="gmail_search_threads",
    annotations=ToolAnnotations(
        title="Search Gmail Threads",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def gmail_search_threads(params: SearchThreadsInput) -> str:
    """Search whole conversations (threads) in the mailbox scope and summarize each one.

    Calls `threads.list` with the project scope applied (GMAIL_SCOPE_LABEL as a label filter,
    GMAIL_SCOPE_QUERY ANDed with the query, spam and trash always excluded), then reads each
    hit's headers (`threads.get`, metadata only, at most 10 at a time) to summarize it. No
    message body is read. Threads come newest first, as in Gmail.

    When to Use:
    - To find a conversation and see who took part, how long it is and when it last moved.
    - To get a threadId for gmail_get_thread.

    When NOT to Use:
    - To find single messages (use gmail_search_messages) or read one (gmail_get_message).
    - To read a conversation you already have the threadId of (use gmail_get_thread).

    Returns:
    Markdown: the active scope, the number of threads on the page (and Gmail's estimate of
    the total), the `page_token` for the next page when there is one, and per thread its
    subject, threadId, message count, last date (UTC), participants (From/To/Cc, the first
    10) and Gmail's snippet. A thread whose summary could not be read shows its id and the
    cause, without a snippet (it could be a message in spam or trash).

    Pagination:
    Pass the printed `page_token` with the same `query` to get the next page.

    Examples:
    - params = {"query": "from:ada@example.com after:2026/10/01"}
    - params = {"query": 'subject:"quarterly numbers" has:attachment', "max_results": 50}
    - params = {"query": "invoice", "page_token": "<page_token from the previous call>"}

    Error Handling:
    A query whose parentheses or braces do not balance outside double quotes is refused
    before anything is sent (it could escape the scope). A bad `page_token` is a 400 from
    Gmail. A dead token, a token for another mailbox (the pin) or an unknown
    GMAIL_SCOPE_LABEL fail the call with one line naming the cause and the fix.
    """
    try:
        client = get_client()
        scope = get_scope()
        list_params = await scope.apply(
            {"maxResults": params.max_results, "pageToken": params.page_token}, query=params.query
        )
        body = await client.get("users/me/threads", list_params)
        ids: list[str] = []
        hits: list[Mapping[str, Any]] = []
        skipped = 0
        for hit in _mappings(body.get("threads")):
            thread_id = _usable_id(hit.get("id"))
            if thread_id is None:
                skipped += 1
                continue
            ids.append(thread_id)
            hits.append(hit)
        metadata = {"format": "metadata", "metadataHeaders": list(SUMMARY_HEADERS)}
        results = (
            await client.batch_get([(f"users/me/threads/{ident}", metadata) for ident in ids], return_exceptions=True)
            if ids
            else []
        )
        failures = [result for result in results if isinstance(result, Exception)]
        if results and len(failures) == len(results):
            raise failures[0]  # nothing could be summarized: a systemic failure, not a page
        return clip_response(_render_search(params, body, ids, hits, results, skipped, await scope.resolve()))
    except Exception as exc:
        raise tool_error(exc) from None


# --- gmail_get_thread ------------------------------------------------------------------------


def _quote(text: str) -> str:
    """The body as a blockquote, so no line of a mail can pose as this tool's own structure."""
    return "\n".join(f"> {line}" if line else ">" for line in text.split("\n"))


def _body_note(thread_id: str, message_id: str, body: Body, page: TextPage, cap: int, *, alone: bool) -> str:
    """Where the shown window sits in the body, and — when it was cut — the call that reads on.

    The way on is always `gmail_get_thread` with `message_id` + `body_offset`, never
    `gmail_get_message`: the thread passed the scope check as a whole (ADR D5), while that
    message alone may not (a label scope and a reply without the label), and then
    gmail_get_message would answer "not found" for text this tool already started showing.
    """
    if body.source == "none":
        if body.external_parts:
            return "[body: Gmail stored the text as a separate part (not inlined), which this server does not show]"
        return "[body: no text part]"
    origin = " (converted from HTML)" if body.source == "text/html" else ""
    if page.total == 0:
        return f"[body{origin}: empty]"
    where = f"characters {page.offset}–{page.end} of {page.total}"
    if page.next_offset is not None:
        if len(page.text) < cap:  # narrowed by fit_page: the response size, not the cap, cut it
            why = f"cut at {len(page.text)} characters to fit the response size limit"
        elif alone:
            why = f"cut at {cap} per call (GMAIL_BODY_MAX_CHARS)"
        else:
            why = f"cut at {cap} per message in a thread"
        return (
            f"[body{origin}: {where}, {why}; read on with gmail_get_thread, params "
            f'{{"thread_id": "{thread_id}", "message_id": "{message_id}", "body_offset": {page.next_offset}}}]'
        )
    if page.offset == 0:
        return f"[body{origin}: complete, {page.total} characters]"
    return f"[body{origin}: {where}; end of the body]"


def _render_message(
    thread_id: str,
    index: int,
    total: int,
    message: Mapping[str, Any],
    body: Body,
    page: TextPage,
    cap: int,
    *,
    alone: bool = False,
) -> str:
    payload = _mapping(message.get("payload"))
    message_id = shorten(one_line(str(message.get("id") or "?")), MAX_ID_CHARS)
    lines = [
        f"## Message {index + 1} of {total} · id `{message_id}` · {fmt_internal_date(message.get('internalDate'))}"
    ]
    headers = headers_subset(payload)
    if headers:
        lines.append(render_headers(headers))
    raw_labels = message.get("labelIds")
    labels = [label for label in raw_labels if isinstance(label, str)] if isinstance(raw_labels, list) else []
    if labels:
        lines.append(f"- **Labels**: {labels_line(labels)}")
    attachments = list_attachments(payload)
    if attachments:
        lines.append(f"- **Attachments** ({len(attachments)}; save one with gmail_get_attachment):")
        lines.extend(f"  {line}" for line in render_attachments(attachments).split("\n"))
    lines.append("")
    if page.text:
        lines.extend([_quote(page.text), ""])  # a blank line ends the quote before the note
    lines.append(_body_note(thread_id, message_id, body, page, cap, alone=alone))
    return "\n".join(lines)


def _render_thread(
    thread_id: str, messages: list[Mapping[str, Any]], offset: int, max_messages: int, total_cap: int, hidden: int = 0
) -> str:
    total = len(messages)
    per_message = min(MESSAGE_MAX_CHARS, total_cap)
    lines = [f"# Gmail thread `{thread_id}`: {_subject(messages)}", ""]
    if hidden:
        lines.extend([_spam_trash_note(hidden), ""])
    if offset >= total:
        lines.append(
            f"**{total}** message(s) in this thread; offset={offset} is past the last one. Pass an offset from 0 to "
            f"{total - 1}."
        )
        return "\n".join(lines)
    blocks: list[str] = []
    used = 0  # body characters shown
    used_bytes = 0  # bytes of the blocks, as clip_response will measure them
    byte_budget = MAX_RESPONSE_BYTES - THREAD_PAGE_RESERVE_BYTES - response_bytes("\n".join(lines))
    end = offset
    stopped_by: str | None = None
    for index in range(offset, min(total, offset + max_messages)):
        message = messages[index]
        body = extract_body(_mapping(message.get("payload")))
        page = page_text(body.text, 0, per_message)
        # The first message of a page always shows (per_message <= total_cap), so a page always moves.
        if blocks and used + len(page.text) > total_cap:
            stopped_by = f"the body cap of {total_cap} characters per call"
            break
        block = _render_message(thread_id, index, total, message, body, page, per_message)
        size = response_bytes(block) + 2  # and the blank line that joins it
        if blocks and used_bytes + size > byte_budget:
            stopped_by = f"the response size limit of {MAX_RESPONSE_BYTES:,} bytes per call"
            break
        if not blocks and size > byte_budget:
            # Bounded fields make this unreachable today; if it ever happens, the window shrinks.
            render = functools.partial(_render_message, thread_id, index, total, message, body, cap=per_message)
            block, page = fit_page(render, page, byte_budget)
            size = response_bytes(block) + 2
        blocks.append(block)
        used += len(page.text)
        used_bytes += size
        end = index + 1
    lines.append(
        f"**{total}** message(s) in this thread, oldest first; showing {offset + 1}–{end}. Body caps: {per_message} "
        f"characters per message, {total_cap} per call (GMAIL_BODY_MAX_CHARS)."
    )
    lines.append("")
    lines.append("\n\n".join(blocks))
    lines.extend(["", "---", f"Shown: messages {offset + 1}–{end} of {total} ({used} body characters)."])
    after = total - end
    if after:
        why = stopped_by or f"max_messages={max_messages}"
        lines.append(f"{after} more message(s) after these, not shown ({why}) — pass offset={end} to read on.")
    else:
        lines.append("End of the thread.")
    if offset:
        lines.append(f"{offset} earlier message(s) not shown — pass offset=0 to start from the first.")
    return "\n".join(lines)


def _render_one_message(
    thread_id: str,
    messages: list[Mapping[str, Any]],
    message_id: str,
    body_offset: int,
    total_cap: int,
    hidden: int = 0,
) -> str:
    """One message of an in-scope thread, its body from `body_offset` (the way on from a cut body)."""
    index = next((i for i, message in enumerate(messages) if message.get("id") == message_id), None)
    if index is None:
        # Not a message of this thread: the same answer a missing id gets.
        raise NotFoundInScopeError("message", message_id)
    total = len(messages)
    message = messages[index]
    body = extract_body(_mapping(message.get("payload")))
    lines = [f"# Gmail thread `{thread_id}`: {_subject(messages)}", ""]
    if hidden:
        lines.extend([_spam_trash_note(hidden), ""])
    lines.extend(
        [
            f"**{total}** message(s) in this thread; showing message {index + 1} alone, its body from character "
            f"{body_offset}. Body cap: {total_cap} characters per call (GMAIL_BODY_MAX_CHARS).",
            "",
        ]
    )
    # Offsets count the REDACTED body (page_text redacts it whole before cutting).
    page = page_text(body.text, body_offset, total_cap)
    if page.total and body_offset >= page.total:
        lines.append(
            f"[body: body_offset={body_offset} is past the end of message `{message_id}` ({page.total} "
            f"characters): pass a body_offset from 0 to {page.total - 1}]"
        )
        return "\n".join(lines)

    def render(window: TextPage) -> str:
        block = _render_message(thread_id, index, total, message, body, window, total_cap, alone=True)
        footer = ["", "---", "Pass only thread_id (and offset) to page the whole thread by message again."]
        return "\n".join([*lines, block, *footer])

    rendered, _ = fit_page(render, page)
    return rendered


@mcp.tool(
    name="gmail_get_thread",
    annotations=ToolAnnotations(
        title="Read a Gmail Thread",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def gmail_get_thread(params: GetThreadInput) -> str:
    """Read a whole conversation: every message in order, with headers and capped text bodies.

    Calls `threads.get` (full format), checks the thread against the project scope before
    showing anything (a thread is in scope if any of its messages is), then renders its
    messages oldest first: per message the id, date, From/To/Cc/Date/Subject/Message-ID,
    labels, the attachment list and the text body (text/plain preferred, else HTML turned
    into text).

    Caps: each message's body is cut at 5,000 characters (or GMAIL_BODY_MAX_CHARS if that is
    smaller), and a page holds at most GMAIL_BODY_MAX_CHARS body characters in total
    (default 20,000) and at most `max_messages` messages (default 20). A page stops before
    the message that would cross the total cap, or push the response past its size limit
    (900,000 bytes); the footer says which, and the first message of a page always shows.
    `offset` is the index of the first message to show (0 = the oldest).

    Messages in spam or trash are never shown: they are left out (offsets and counts skip
    them) and a note says how many; a thread with nothing else reads as not found.

    A body cut at a cap is read on with this same tool: pass the `message_id` and the
    `body_offset` the cut body prints, and the page is that one message alone, from that
    character, with up to GMAIL_BODY_MAX_CHARS characters. It runs under the thread's scope
    check, so every message of a thread you can open can be read to its end.

    When to Use:
    - To read a conversation from a threadId (gmail_search_threads or gmail_search_messages).
    - To see who said what, in order, across replies.

    When NOT to Use:
    - To read a single message found by gmail_search_messages, without its conversation
      (use gmail_get_message).
    - To find threads (use gmail_search_threads).
    - To download an attachment (use gmail_get_attachment with the message id and the listed partId).

    Returns:
    Markdown: the thread's subject and message count, then one section per message shown
    (the body as a blockquote, with a note saying whether it is complete or where it was
    cut), then a footer counting the messages not shown before and after the page, with the
    `offset` that reads on.

    Pagination:
    By message: pass the `offset` the footer prints (and the same `max_messages`). Within a
    cut body: pass the printed `message_id` and `body_offset` (no `offset`).

    Examples:
    - params = {"thread_id": "18c2f0e9a1b2c3d4"}
    - params = {"thread_id": "18c2f0e9a1b2c3d4", "offset": 20}
    - params = {"thread_id": "18c2f0e9a1b2c3d4", "max_messages": 5}
    - params = {"thread_id": "18c2f0e9a1b2c3d4", "message_id": "18c2f0e9a1b2c3e5", "body_offset": 5000}

    Error Handling:
    A missing thread id and a thread outside the project scope return the same "not found
    in this mailbox scope" error, without any of the thread's headers; a `message_id` that is
    not in the thread gets the same error for the message. A dead token, a token
    for another mailbox (the pin) or an unknown GMAIL_SCOPE_LABEL fail the call with one
    line naming the cause and the fix.
    """
    try:
        settings = get_settings()
        # Pin, scope, GET, id compare and scope check (on the fetched thread, before a single
        # header is rendered): one helper, the same steps gmail_get_message runs.
        thread = await get_scope().fetch_thread(params.thread_id, {"format": "full"})
        # Spam and trash are never shown: left out (and counted), here as in the scope check.
        messages, hidden = visible_messages(thread)
        if not messages:
            raise NotFoundInScopeError("thread", params.thread_id)
        if params.message_id is not None:
            rendered = _render_one_message(
                params.thread_id, messages, params.message_id, params.body_offset, settings.body_max_chars, hidden
            )
        else:
            rendered = _render_thread(
                params.thread_id, messages, params.offset, params.max_messages, settings.body_max_chars, hidden
            )
        return clip_response(rendered)
    except Exception as exc:
        raise tool_error(exc) from None
