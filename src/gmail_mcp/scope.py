"""Project scope (ADR-0001 D5): a filter on what the agent sees, NOT a security boundary.

Two optional settings, combinable:

- `GMAIL_SCOPE_LABEL`: a label name or id, resolved to its id once (`labels.list`). A label
  that does not exist makes the server refuse to run. Applied as `labelIds[]` on every
  list call — a separate API parameter, so no query text can undo it.
- `GMAIL_SCOPE_QUERY`: a Gmail query, applied as `(<scope>) (<user query>)`. The user
  query is refused when its parentheses (or braces) do not balance outside double quotes —
  the cortex escape `) OR from:x (` would otherwise close the scope's group.

Both queries are bounded in characters and once percent-encoded (GMAIL_SCOPE_QUERY when
settings load, the user query by the params models and again in `apply()`), so every list call
and every scope lookup fits Gmail's URL limit; `apply()` also measures the request it composes
and refuses one over `validators.MAX_REQUEST_TARGET` (validators.py has the measurement).

**Spam and trash are never shown, in any mode, also with no scope.** Every list call runs
with `includeSpamTrash=false` AND `-in:spam -in:trash` appended to its query, so a user query
such as `in:anywhere`, `in:spam` or `in:trash` cannot reach them; `check_message()` refuses a
message labelled SPAM or TRASH; and a thread is judged (and shown) by its other messages only
(`visible_messages`).

List calls go through `apply()`. Every fetch by id is re-checked AFTER the fetch with
`check_message()` / `check_thread()`, so a known id cannot skip the scope: label scope =
the message carries the label; query scope = `messages.list` with `q = (<scope>) rfc822msgid:<Message-ID>` returns that
message's id. No usable Message-ID → out of scope. A thread is in scope if any of its
messages is; for a query scope its lookups (one per distinct Message-ID) go through
`client.batch_get`, at most `MAX_CONCURRENCY` at a time, and stop after the first batch with
a match — a 100-message thread is not 100 sequential calls. Any error during a check → out
of scope (fail closed). Callers turn "out of
scope" into the same `NotFoundInScopeError` a missing id gets, without leaking headers.

**Fetch by id: one helper.** `fetch_message()` / `fetch_thread()` are the only way a tool
reads one object by id, so no tool can drop a step: (1) the account pin, BEFORE the fetch
and outside any not-found mapping, so a profile that fails keeps its real cause; (2) the
scope resolves (an unknown label refuses to run); (3) the GET, where only a 404 and the
400 Gmail answers for an id it cannot parse (reason `invalidArgument`) mean "not found" —
any other 400, 403 or 5xx keeps its cause; (4) the returned `id` must be the one asked
for; (5) the scope check. Every "no" is the same `NotFoundInScopeError`.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal

import httpx

from gmail_mcp import validators
from gmail_mcp.client import API_BASE, MAX_CONCURRENCY, GmailClient, get_client
from gmail_mcp.config import Settings, get_settings
from gmail_mcp.errors import GmailApiError, NotFoundInScopeError, QueryRejectedError, ScopeConfigError
from gmail_mcp.validators import query_problem

ScopeMode = Literal["none", "label", "query", "both"]

# Labels of what is never shown: list calls run with includeSpamTrash=false and
# EXCLUDE_SPAM_TRASH in their query, so a fetch by id must not reach them either.
EXCLUDED_LABELS: frozenset[str] = frozenset({"SPAM", "TRASH"})
# Appended to every list query, whatever the scope: `includeSpamTrash=false` alone does not
# stop a user query such as `in:anywhere`, `in:spam` or `in:trash`.
EXCLUDE_SPAM_TRASH = "-in:spam -in:trash"

# A Message-ID is only put into a query when it is made of characters that cannot form
# Gmail syntax (no quotes, parentheses, braces, colons or whitespace); anything else is
# treated as "no usable Message-ID" — out of scope.
_MESSAGE_ID_RE = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_.@-]{1,995}")
# Enough for duplicates of one Message-ID (the same message in several copies).
_CHECK_MAX_RESULTS = 25
# The longer of the two list paths: a list call's request target is measured on it.
LIST_PATH = "users/me/messages"
# Gmail's 400 for an id it cannot parse ("Invalid id value"): `errors[].reason`, or the
# `status` when the body has no `errors` list. Any other 400 names a real problem.
INVALID_ID_REASONS: frozenset[str] = frozenset({"invalidArgument", "INVALID_ARGUMENT"})

FetchKind = Literal["message", "thread"]

logger = logging.getLogger(__name__)


def means_not_found(exc: GmailApiError) -> bool:
    """True for the answers that name no object: a 404, and the 400 for an id Gmail cannot parse."""
    return exc.status == 404 or (exc.status == 400 and exc.reason in INVALID_ID_REASONS)


@dataclass(frozen=True)
class ResolvedScope:
    """The active scope after the label is resolved."""

    mode: ScopeMode
    label_id: str | None
    label_name: str | None
    query: str | None


def check_user_query(query: str) -> None:
    """Raise `QueryRejectedError` when `query` could escape `(<scope>) (<query>)`."""
    problem = query_problem(query)
    if problem is not None:
        raise QueryRejectedError(f"the search query is refused: {problem}")


def in_spam_or_trash(message: Mapping[str, Any]) -> bool:
    """True when a message is labelled SPAM or TRASH: it is never shown.

    No `labelIds` at all is a message in no folder (archived without labels), so it is NOT
    excluded; `labelIds` that are not a list cannot be read, so it is (fail closed).
    """
    labels = message.get("labelIds")
    if labels is None:
        return False
    if not isinstance(labels, list):
        return True
    return any(label in EXCLUDED_LABELS for label in labels)


def visible_messages(thread: Mapping[str, Any]) -> tuple[list[Mapping[str, Any]], int]:
    """A thread's messages that may be shown (not in spam or trash), and how many were left out."""
    raw = thread.get("messages")
    messages = [message for message in raw if isinstance(message, Mapping)] if isinstance(raw, list) else []
    shown = [message for message in messages if not in_spam_or_trash(message)]
    return shown, len(messages) - len(shown)


def message_id_header(message: Mapping[str, Any]) -> str | None:
    """The message's Message-ID without angle brackets, or `None` when absent or unusable."""
    payload = message.get("payload")
    headers = payload.get("headers") if isinstance(payload, Mapping) else None
    if not isinstance(headers, list):
        return None
    for header in headers:
        if not isinstance(header, Mapping):
            continue
        if str(header.get("name", "")).strip().lower() != "message-id":
            continue
        value = str(header.get("value", "")).strip()
        if value.startswith("<") and value.endswith(">"):
            value = value[1:-1].strip()
        return value if _MESSAGE_ID_RE.fullmatch(value) else None
    return None


class ScopeGuard:
    """Applies and re-checks the configured scope for one client."""

    def __init__(self, settings: Settings, client: GmailClient) -> None:
        self._settings = settings
        self._client = client
        self._resolved: ResolvedScope | None = None
        self._config_error: ScopeConfigError | None = None

    @property
    def mode(self) -> ScopeMode:
        label = self._settings.scope_label is not None
        query = self._settings.scope_query is not None
        if label and query:
            return "both"
        if label:
            return "label"
        if query:
            return "query"
        return "none"

    async def resolve(self) -> ResolvedScope:
        """The scope with the label resolved to its id (one `labels.list`, then cached).

        Raises `ScopeConfigError` — for good — when GMAIL_SCOPE_LABEL names no label.
        """
        if self._config_error is not None:
            raise self._config_error
        if self._resolved is not None:
            return self._resolved
        label_id: str | None = None
        label_name: str | None = None
        wanted = self._settings.scope_label
        if wanted is not None:
            body = await self._client.get("users/me/labels")
            labels = [label for label in body.get("labels") or [] if isinstance(label, Mapping)]
            match = _find_label(labels, wanted)
            if match is None:
                self._config_error = ScopeConfigError(
                    f"GMAIL_SCOPE_LABEL={wanted} matches no label in {self._settings.account_email}: this entry refuses "
                    "to run. Fix the label name (or id), or create the label in Gmail"
                )
                raise self._config_error
            label_id = str(match["id"])
            label_name = str(match.get("name") or label_id)
        self._resolved = ResolvedScope(self.mode, label_id, label_name, self._settings.scope_query)
        return self._resolved

    async def apply(self, params: Mapping[str, Any] | None = None, *, query: str | None = None) -> dict[str, Any]:
        """The params for a `messages.list` / `threads.list` call, with the scope applied.

        `params` carries everything but the search text (`maxResults`, `pageToken`, …);
        the user's search text goes in `query`. The result has `includeSpamTrash=false`,
        the scope label in `labelIds`, and `q` composed as `(<scope>) (<query>) -in:spam
        -in:trash` — each part only when present, the exclusion always, so no query (and no
        scope) can reach spam or trash.
        """
        base = dict(params or {})
        if "q" in base:
            raise ValueError("pass the search text as apply(query=…), not as params['q']")
        user_query = " ".join((query or "").split())
        # The params models refuse it first; this holds for any caller (GMAIL_SCOPE_QUERY is
        # bounded when settings load), so `q` stays within what validators.py measured.
        size = validators.query_size_problem(
            user_query, max_chars=validators.MAX_QUERY_CHARS, max_encoded=validators.MAX_QUERY_ENCODED
        )
        if size is not None:
            raise QueryRejectedError(f"the search query is refused: {size}")
        if user_query:
            check_user_query(user_query)
        scope = await self.resolve()
        base["includeSpamTrash"] = False
        if scope.label_id is not None:
            existing = base.get("labelIds") or []
            label_ids = [str(item) for item in (existing if isinstance(existing, list | tuple) else [existing])]
            if scope.label_id not in label_ids:
                label_ids.append(scope.label_id)
            base["labelIds"] = label_ids
        parts = [f"({scope.query})"] if scope.query is not None else []
        if user_query:
            parts.append(f"({user_query})")  # grouped, so the exclusion binds to the whole query
        parts.append(EXCLUDE_SPAM_TRASH)
        base["q"] = " ".join(parts)
        # Measured, not assumed: whatever else a caller put in `params` (a page token, labels)
        # counts too, and a request Gmail would answer with a 400 page is never sent.
        target = request_target(LIST_PATH, base)
        if target is None or target > validators.MAX_REQUEST_TARGET:
            size = "cannot be encoded" if target is None else f"would be {target:,} characters"
            raise QueryRejectedError(
                f"the search is refused: its URL {size}, the most is {validators.MAX_REQUEST_TARGET:,} (Gmail refuses "
                f"a request longer than {validators.GMAIL_MAX_REQUEST_TARGET:,}): shorten the query"
            )
        return base

    async def fetch_message(self, message_id: str, params: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """`messages.get` for `message_id`, returned only when it is in scope (else `NotFoundInScopeError`).

        Fetch with `format=full` (or `metadata` + the Message-ID header) so the check has what
        it needs.
        """
        ident = validators.message_id(message_id)
        return await self._fetch("message", ident, params, self.check_message)

    async def fetch_thread(self, thread_id: str, params: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """`threads.get` for `thread_id`, returned only when it is in scope (else `NotFoundInScopeError`)."""
        ident = validators.thread_id(thread_id)
        return await self._fetch("thread", ident, params, self.check_thread)

    async def _fetch(
        self,
        kind: FetchKind,
        ident: str,
        params: Mapping[str, Any] | None,
        check: Callable[[Mapping[str, Any]], Awaitable[bool]],
    ) -> dict[str, Any]:
        # The pin first, outside the not-found mapping below: a profile that fails (a 400
        # failedPrecondition for a mailbox without Gmail, a 403, a 5xx) keeps its cause.
        await self._client.pinned_profile()
        await self.resolve()  # a scope that cannot resolve refuses to run before anything is read
        try:
            body = await self._client.get(f"users/me/{kind}s/{ident}", params)
        except GmailApiError as exc:
            if means_not_found(exc):
                raise NotFoundInScopeError(kind, ident) from None
            raise
        returned = body.get("id")
        if not isinstance(returned, str) or returned.lower() != ident.lower():
            raise NotFoundInScopeError(kind, ident)
        if not await check(body):
            raise NotFoundInScopeError(kind, ident)
        return body

    async def check_message(self, message: Mapping[str, Any]) -> bool:
        """True when a fetched message is in scope. Fail closed: any error → False.

        A message in SPAM or TRASH is out of scope in every mode, with no scope too. `message`
        must carry `id`, `labelIds` and (for a query scope) the Message-ID header, so fetch it
        with `format=full` or `format=metadata` + `metadataHeaders=Message-ID`.
        """
        scope = await self.resolve()  # a scope that cannot resolve refuses to run, loudly
        try:
            if in_spam_or_trash(message):
                return False
            if scope.mode == "none":
                return True
            return await self._in_scope(scope, message)
        except Exception as exc:
            logger.warning("scope check failed (%s); treating the message as out of scope", type(exc).__name__)
            return False

    async def check_thread(self, thread: Mapping[str, Any]) -> bool:
        """True when any message of a fetched thread outside spam and trash is in scope.

        Fail closed: any error → False. A thread whose messages are all in spam or trash is
        out of scope in every mode, with no scope too.
        """
        scope = await self.resolve()
        try:
            messages, _ = visible_messages(thread)
            if scope.mode == "none":
                return bool(messages)
            candidates = [message for message in messages if _passes_label(scope, message)]
            if scope.query is None:
                return bool(candidates)
            return await self._any_found_by_query(scope, candidates)
        except Exception as exc:
            logger.warning("scope check failed (%s); treating the thread as out of scope", type(exc).__name__)
            return False

    async def _in_scope(self, scope: ResolvedScope, message: Mapping[str, Any]) -> bool:
        if not _passes_label(scope, message):
            return False
        if scope.query is None:
            return True
        rfc822 = message_id_header(message)
        if rfc822 is None:
            return False
        body = await self._client.get("users/me/messages", _lookup_params(scope.query, rfc822))
        return _found(body, {str(message["id"])})

    async def _any_found_by_query(self, scope: ResolvedScope, messages: list[Mapping[str, Any]]) -> bool:
        """True when the query-scope lookup of any message finds it; raises on a failed batch with no match."""
        if scope.query is None:  # pragma: no cover - callers only come here with a query scope
            return False
        # One lookup per distinct Message-ID: copies of one message (sent and received) share it.
        wanted: dict[str, set[str]] = {}
        for message in messages:
            rfc822 = message_id_header(message)
            if rfc822 is not None:
                wanted.setdefault(rfc822, set()).add(str(message["id"]))
        lookups = list(wanted.items())
        for start in range(0, len(lookups), MAX_CONCURRENCY):
            batch = lookups[start : start + MAX_CONCURRENCY]
            results = await self._client.batch_get(
                [("users/me/messages", _lookup_params(scope.query, rfc822)) for rfc822, _ in batch],
                return_exceptions=True,
            )
            # A lookup that found its message proves the thread in scope (ADR D5: any message).
            if any(
                not isinstance(result, Exception) and _found(result, ids)
                for (_, ids), result in zip(batch, results, strict=True)
            ):
                return True
            failure = next((result for result in results if isinstance(result, Exception)), None)
            if failure is not None:
                raise failure  # no proof and a failed check: fail closed (check_thread logs it)
        return False


def request_target(path: str, params: Mapping[str, Any]) -> int | None:
    """The characters of the request target (path and query) httpx sends for `path` with `params`.

    Built by httpx itself, as the client sends it (`None` values dropped, bools as true/false,
    lists as repeated keys), so the count is the one Gmail's front end sees. `None` when httpx
    cannot build the URL at all.
    """
    try:
        url = httpx.URL(f"{API_BASE}/{path}", params={key: value for key, value in params.items() if value is not None})
    except (httpx.InvalidURL, UnicodeEncodeError):
        return None
    return len(url.raw_path)


def _passes_label(scope: ResolvedScope, message: Mapping[str, Any]) -> bool:
    """The local part of the check: the message has an id and, for a label scope, the label."""
    message_id = message.get("id")
    if not isinstance(message_id, str) or not message_id:
        return False
    if scope.label_id is None:
        return True
    labels = message.get("labelIds")
    return isinstance(labels, list) and scope.label_id in labels


def _lookup_params(scope_query: str, rfc822: str) -> dict[str, Any]:
    """The `messages.list` params that ask whether the message with this Message-ID is in the query scope."""
    return {"q": f"({scope_query}) rfc822msgid:{rfc822}", "includeSpamTrash": False, "maxResults": _CHECK_MAX_RESULTS}


def _found(body: Mapping[str, Any], message_ids: set[str]) -> bool:
    found = body.get("messages")
    return isinstance(found, list) and any(
        isinstance(item, Mapping) and item.get("id") in message_ids for item in found
    )


def _find_label(labels: list[Mapping[str, Any]], wanted: str) -> Mapping[str, Any] | None:
    """Exact id, then exact name, then a unique case-insensitive name."""
    for label in labels:
        if label.get("id") == wanted:
            return label
    for label in labels:
        if label.get("name") == wanted:
            return label
    folded = [label for label in labels if str(label.get("name", "")).casefold() == wanted.casefold()]
    return folded[0] if len(folded) == 1 else None


_scope: ScopeGuard | None = None


def get_scope() -> ScopeGuard:
    """Lazy module-level singleton bound to `get_client()` (tests reset it with `reset_scope`)."""
    global _scope
    if _scope is None:
        _scope = ScopeGuard(get_settings(), get_client())
    return _scope


def reset_scope() -> None:
    global _scope
    _scope = None
