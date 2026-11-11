"""What the live tests share, and how to run them.

Run them (the conductor, in a supervised session; never CI, never an unattended agent):

    uv run pytest -m live -rP

They need GMAIL_REFRESH_TOKEN (shell or `.env`) with GMAIL_ACCOUNT and the OAuth client;
without the token every one is skipped (tests/conftest.py). Every request is a GET: the
client cannot send anything else, so a run reads the mailbox and never changes it. A test
that needs data the mailbox lacks (no message with an attachment in the newest 50, an empty
scope) skips and names what was missing. Every test runs inside `bounded()`, so a request
that never answers fails the test with that reason instead of hanging the run.

Privacy, because a run's output is read in a terminal and pasted into reports:

- No test prints, logs or asserts on mail content (subjects, senders, bodies, snippets,
  filenames, addresses). Assertions compare ids, label ids, counts, sizes and hashes.
- Tool output is parsed HERE into ids, counts and booleans, so a test function's frame never
  holds it, and every assertion is on ids, counts, booleans or hashes, so pytest's failure
  introspection has nothing else to quote (a saved file's path is kept out of every repr).
  Do not run with `--showlocals` (-l) anyway: a helper's frame would show its locals.
- A failed tool call is reported by `error_kind`, a fixed vocabulary, never by its text.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import stat
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from mcp.client.session import ClientSession
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import TextContent

from gmail_mcp.client import get_client
from gmail_mcp.config import get_settings
from gmail_mcp.formatters import list_attachments
from gmail_mcp.scope import EXCLUDED_LABELS, get_scope
from gmail_mcp.server import mcp
from gmail_mcp.tools.messages import SearchMessagesInput, gmail_search_messages

# `live_record(label, value)`, the fixture tests/live/conftest.py provides.
LiveRecord = Callable[[str, str], None]

# A whole test, Gmail and the token endpoint included (the client's own timeout is 30 s
# per request, with at most 3 retries).
LIVE_TIMEOUT_SECONDS = 180.0
# One tools/call through the in-process MCP session.
MCP_READ_TIMEOUT = timedelta(seconds=90)
# "No message with an attachment in the newest 50" is the skip.
ATTACHMENT_SCAN = 50
# The download test keeps to small attachments (it saves the bytes, then deletes them).
MAX_TEST_ATTACHMENT_BYTES = 5 * 1024 * 1024
# `format=metadata` carries labelIds; asking for one harmless header keeps the reply small.
LABELS_ONLY: dict[str, Any] = {"format": "metadata", "metadataHeaders": ["Message-ID"]}
_IN_THE_SCAN = f"in the newest {ATTACHMENT_SCAN} `has:attachment` messages in scope"
NO_ATTACHMENT = f"no attachment with an attachmentId {_IN_THE_SCAN}"
NO_SMALL_ATTACHMENT = (
    f"no attachment with an attachmentId and at most {MAX_TEST_ATTACHMENT_BYTES // (1024 * 1024)} MiB (and "
    f"GMAIL_ATTACHMENT_MAX_BYTES) {_IN_THE_SCAN}"
)


# --- bounds -------------------------------------------------------------------------------


@asynccontextmanager
async def bounded(seconds: float | None = None) -> AsyncIterator[None]:
    """Fail (never hang) when what runs inside takes longer than `seconds` (default LIVE_TIMEOUT_SECONDS)."""
    seconds = LIVE_TIMEOUT_SECONDS if seconds is None else seconds
    try:
        async with asyncio.timeout(seconds):
            yield
    except TimeoutError:
        # `from None`: the cancellation chain (anyio's, inside an MCP session) says nothing more.
        raise pytest.fail.Exception(
            f"no answer within {seconds:g} s from Gmail, the token endpoint or the MCP session: the test gave up",
            pytrace=False,
        ) from None


def mcp_session() -> AbstractAsyncContextManager[ClientSession]:
    """An MCP client session connected in-process to this server (every tools/call bounded)."""
    return create_connected_server_and_client_session(mcp, read_timeout_seconds=MCP_READ_TIMEOUT)


# --- error text → a fixed vocabulary ------------------------------------------------------

_API_ERROR_RE = re.compile(r"Gmail API error ([0-9]{3})(?: \(([A-Za-z_]{1,64})\))?")
_KNOWN_ERRORS: tuple[tuple[str, str], ...] = (
    ("was not found in this mailbox scope", "not found in this mailbox scope"),
    ("every tool is disabled", "account pin mismatch"),
    ("is no longer valid", "dead refresh token"),
    ("its token can do more", "token wider than gmail.readonly"),
    ("matches no label", "unknown GMAIL_SCOPE_LABEL"),
    ("over GMAIL_ATTACHMENT_MAX_BYTES", "attachment over the cap"),
    ("no usable size", "attachment of unknown size"),
    ("could not save the attachment", "attachment not saved"),
    ("invalid arguments", "invalid arguments"),
    ("configuration error", "configuration error"),
    ("timed out", "timeout"),
    ("could not connect", "connection failure"),
)


def error_kind(text: str) -> str:
    """What a tool error is about, from a fixed vocabulary: never the error's own text."""
    match = _API_ERROR_RE.search(text)
    if match:
        status, reason = match.groups()
        return f"Gmail API error {status}" + (f" ({reason})" if reason else "")
    for needle, kind in _KNOWN_ERRORS:
        if needle in text:
            return kind
    return "unclassified error (run the tool by hand to read it)"


def status_and_reason(status: int, reason: str) -> str:
    """`404 notFound`: what Gmail answered, safe to record (a reason of an unexpected shape is not)."""
    if not reason:
        return f"{status} noReason"
    return f"{status} {reason}" if re.fullmatch(r"[A-Za-z_]{1,64}", reason) else f"{status} unexpectedReason"


# --- attachments --------------------------------------------------------------------------


@dataclass(frozen=True)
class AttachmentRef:
    """One attachment part of a message in scope, as a `messages.get` describes it."""

    message_id: str
    part_id: str
    size: int  # the part's body.size


async def _full_message(message_id: str) -> dict[str, Any]:
    return await get_client().get(f"users/me/messages/{message_id}", {"format": "full"})


def _payload(message: Mapping[str, Any]) -> Mapping[str, Any]:
    payload = message.get("payload")
    return payload if isinstance(payload, Mapping) else {}


async def find_attachment(max_bytes: int | None = MAX_TEST_ATTACHMENT_BYTES) -> AttachmentRef | None:
    """The first attachment with an attachmentId (and at most `max_bytes`, if given) in the newest scan, or None.

    The search goes through the scope (`scope.apply`), so the message is one the tools may read.
    """
    if max_bytes is not None:
        max_bytes = min(max_bytes, get_settings().attachment_max_bytes)
    params = await get_scope().apply({"maxResults": ATTACHMENT_SCAN}, query="has:attachment")
    listed = await get_client().get("users/me/messages", params)
    for hit in listed.get("messages") or []:
        message_id = hit.get("id") if isinstance(hit, Mapping) else None
        if not isinstance(message_id, str) or not re.fullmatch(r"[A-Za-z0-9]{6,64}", message_id):
            continue
        for item in list_attachments(_payload(await _full_message(message_id))):
            if item.part_id is None or not item.attachment_id or item.size <= 0:
                continue
            if max_bytes is None or item.size <= max_bytes:
                return AttachmentRef(message_id, item.part_id, item.size)
    return None


async def _attachment_id(ref: AttachmentRef) -> str | None:
    for item in list_attachments(_payload(await _full_message(ref.message_id))):
        if item.part_id == ref.part_id:
            return item.attachment_id
    return None


async def attachment_id_between_two_reads(ref: AttachmentRef) -> str | None:
    """Two `messages.get` of the message: "rotates" or "stable" for the part's attachmentId (None if one lacks it).

    The ids themselves never leave this function: Material Security (2023) found an
    attachmentId "functionally equivalent to the data".
    """
    first = await _attachment_id(ref)
    second = await _attachment_id(ref)
    if first is None or second is None:
        return None
    return "stable" if first == second else "rotates"


@dataclass(frozen=True)
class FileFacts:
    """What the test checks about a saved attachment, without its name or its bytes."""

    is_file: bool
    in_message_dir: bool  # directly under <GMAIL_ATTACHMENT_DIR>/<message_id>/
    mode: int | None
    size: int | None
    sha256: str | None


def file_facts(path: Path | None, base: Path, message_id: str) -> FileFacts:
    """Never raises: a failing frame would print `path`, and the path ends in the attachment's name."""
    missing = FileFacts(False, False, None, None, None)
    if path is None:
        return missing
    try:
        if not path.is_file():
            return missing
        resolved = path.resolve()
        in_message_dir = resolved.parent.name == message_id and resolved.parent.parent == base.resolve()
        data = resolved.read_bytes()
        mode = stat.S_IMODE(resolved.stat().st_mode)
    except OSError:
        return missing
    return FileFacts(
        is_file=True,
        in_message_dir=in_message_dir,
        mode=mode,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )


# --- labels -------------------------------------------------------------------------------


async def label_sets(message_ids: Sequence[str]) -> list[frozenset[str]]:
    """Each message's labelIds, read with `format=metadata` (at most 10 requests in flight)."""
    if not message_ids:
        return []
    results = await get_client().batch_get([(f"users/me/messages/{ident}", LABELS_ONLY) for ident in message_ids])
    out = []
    for result in results:
        labels = result.get("labelIds") if isinstance(result, Mapping) else None
        out.append(frozenset(str(label) for label in labels) if isinstance(labels, list) else frozenset())
    return out


def spam_or_trash(labels: frozenset[str]) -> bool:
    return bool(labels & EXCLUDED_LABELS)


def _ids(body: Mapping[str, Any]) -> list[str]:
    raw = body.get("messages")
    hits = raw if isinstance(raw, list) else []
    return [str(hit["id"]) for hit in hits if isinstance(hit, Mapping) and isinstance(hit.get("id"), str)]


@dataclass(frozen=True)
class ListCheck:
    listed: int  # hits on the page
    spam_or_trash: int  # of those, labelled SPAM or TRASH (by their metadata)


async def unexcluded_list(query: str, max_results: int) -> ListCheck:
    """The CONTROL: `messages.list` with `query` and includeSpamTrash, without the server's exclusion."""
    body = await get_client().get(
        "users/me/messages", {"q": query, "maxResults": max_results, "includeSpamTrash": True}
    )
    ids = _ids(body)
    return ListCheck(len(ids), sum(spam_or_trash(labels) for labels in await label_sets(ids)))


async def scoped_list(query: str, max_results: int) -> ListCheck:
    """`messages.list` with the params the server sends (`scope.apply`: the exclusion included)."""
    params = await get_scope().apply({"maxResults": max_results}, query=query)
    ids = _ids(await get_client().get("users/me/messages", params))
    return ListCheck(len(ids), sum(spam_or_trash(labels) for labels in await label_sets(ids)))


# --- tool output → ids and counts ---------------------------------------------------------

# gmail_search_messages: every hit has the line `   id `<id>` · threadId `<id>` · labels: <ids>`
# (or, when its metadata failed, `   id `<id>` · threadId `<id>``).
_HIT_ID_RE = re.compile(r"^   id `([A-Za-z0-9]{6,64})` · threadId `[^`\n]*`(?: · labels: (.*))?$", re.MULTILINE)
_HIT_COUNT_RE = re.compile(r"^\*\*([0-9]+)\*\* message\(s\) on this page", re.MULTILINE)
# gmail_search_threads: `<n>. **<subject>** · threadId `<id>` · …`, or `<n>. threadId `<id>` — …`.
# Greedy on the subject: the real `** · threadId` is the last one on the line.
_THREAD_ID_RE = re.compile(r"^[0-9]+\. (?:\*\*.*\*\* · )?threadId `([A-Za-z0-9]{6,64})`", re.MULTILINE)
# gmail_get_attachment
_SAVED_PATH_RE = re.compile(r"^- \*\*path\*\*: `(.+)`$", re.MULTILINE)
_SAVED_SIZE_RE = re.compile(r"^- \*\*size\*\*: .*\(([0-9]+) bytes\)$", re.MULTILINE)
_SAVED_SHA_RE = re.compile(r"^- \*\*sha256\*\*: `([0-9a-f]{64})`$", re.MULTILINE)


@dataclass(frozen=True)
class SearchPage:
    """A gmail_search_messages page, reduced to what the tests check."""

    stated: int | None  # the "**N** message(s) on this page" count
    ids: tuple[str, ...]
    listed_spam_or_trash: int  # hit lines whose `labels:` name SPAM or TRASH


def parse_message_search(text: str) -> SearchPage:
    count = _HIT_COUNT_RE.search(text)
    ids: list[str] = []
    flagged = 0
    for match in _HIT_ID_RE.finditer(text):
        ids.append(match.group(1))
        labels = {part.strip() for part in (match.group(2) or "").split(",")}
        flagged += bool(labels & EXCLUDED_LABELS)
    return SearchPage(int(count.group(1)) if count else None, tuple(ids), flagged)


def parse_thread_search(text: str) -> tuple[str, ...]:
    return tuple(_THREAD_ID_RE.findall(text))


@dataclass(frozen=True)
class SavedAttachment:
    """The gmail_get_attachment result, reduced to what the tests check (the path is never shown)."""

    path: Path | None = field(repr=False)
    size: int | None
    sha256: str | None


def parse_saved_attachment(text: str) -> SavedAttachment:
    path = _SAVED_PATH_RE.search(text)
    size = _SAVED_SIZE_RE.search(text)
    sha = _SAVED_SHA_RE.search(text)
    return SavedAttachment(
        Path(path.group(1)) if path else None,
        int(size.group(1)) if size else None,
        sha.group(1) if sha else None,
    )


@dataclass(frozen=True)
class SearchCheck:
    page: SearchPage
    spam_or_trash: int  # hits labelled SPAM or TRASH, by their metadata


async def search_messages_check(query: str, max_results: int) -> SearchCheck:
    """gmail_search_messages for `query`, then each hit's labelIds read back through metadata."""
    page = parse_message_search(await gmail_search_messages(SearchMessagesInput(query=query, max_results=max_results)))
    return SearchCheck(page, sum(spam_or_trash(labels) for labels in await label_sets(page.ids)))


@dataclass(frozen=True)
class ToolOutcome:
    """One tools/call through the MCP session, reduced to what the tests check."""

    tool: str
    is_error: bool
    error: str  # error_kind(); "" when the call succeeded
    starts_as_expected: bool  # the result starts with the tool's own heading
    message_ids: tuple[str, ...]  # gmail_search_messages
    thread_ids: tuple[str, ...]  # gmail_search_threads
    saved: SavedAttachment | None  # gmail_get_attachment


async def call_tool(session: ClientSession, tool: str, arguments: dict[str, Any], heading: str) -> ToolOutcome:
    result = await session.call_tool(tool, arguments)
    text = "\n".join(block.text for block in result.content if isinstance(block, TextContent))
    is_error = bool(result.isError)
    return ToolOutcome(
        tool=tool,
        is_error=is_error,
        error=error_kind(text) if is_error else "",
        starts_as_expected=not is_error and text.startswith(heading),
        message_ids=parse_message_search(text).ids if tool == "gmail_search_messages" else (),
        thread_ids=parse_thread_search(text) if tool == "gmail_search_threads" else (),
        saved=parse_saved_attachment(text) if tool == "gmail_get_attachment" and not is_error else None,
    )
