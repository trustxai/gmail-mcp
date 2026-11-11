"""Error types, one-line tool errors, and redaction of anything token-like.

Every message this server produces — a tool error, a log line, a tool result — passes
through `redact()` first. It removes:

- every secret value the process knows (`register_secret`): the configured refresh token
  and client secret (registered when `Settings` loads), each access token as it is minted,
  and a refresh token a token response ever hands back;
- anything SHAPED like a Google credential, known or not: access tokens (`ya29.…`),
  refresh tokens (`1//…`), OAuth client secrets (`GOCSPX-…`), authorization codes
  (`4/0…`), `Bearer <x>`, and the value of a `refresh_token` / `access_token` / `id_token` /
  `client_secret` key in JSON, form or repr form.

Tools never return a traceback: they raise `tool_error(exc)`, a `ToolError` whose message
is one redacted line — the cause, then the fix. The MCP SDK turns it into an
`isError: true` result.
"""

from __future__ import annotations

import logging
import re
import traceback
from collections import OrderedDict
from typing import TYPE_CHECKING

import httpx
from mcp.server.fastmcp.exceptions import ToolError
from pydantic import ValidationError

if TYPE_CHECKING:
    from collections.abc import Iterable

REDACTED = "***"

# Known values shorter than this are not redacted literally: a tiny test value such as
# "key" would otherwise mangle ordinary words. The shape patterns still apply.
_MIN_SECRET_LEN = 8
# Configured secrets (refresh token, client secret) are kept for the life of the process;
# access tokens rotate every hour, so only the newest `_MAX_ROTATING` forms are kept.
_MAX_ROTATING = 64
_PINNED: set[str] = set()
_ROTATING: OrderedDict[str, None] = OrderedDict()

# Token bodies; the last character is never a dot, so a sentence's period survives.
_TOKEN_BODY = r"[A-Za-z0-9._~+/=-]*[A-Za-z0-9_~+/=-]"
_SHAPES: tuple[re.Pattern[str], ...] = (
    # OAuth 2.0 access token for Google APIs.
    re.compile(r"ya29\." + _TOKEN_BODY),
    # Google refresh tokens start with `1//`.
    re.compile(r"(?<![A-Za-z0-9])1//" + _TOKEN_BODY),
    # OAuth client secrets of the current format.
    re.compile(r"GOCSPX-[A-Za-z0-9_-]+"),
    # Authorization codes (the login's loopback redirect carries one).
    re.compile(r"(?<![A-Za-z0-9/])4/0[A-Za-z0-9_-]{20,}"),
)
_BEARER = re.compile(r"(?i)\b(bearer)\s+[^\s\"',;}\]]*[^\s\"',;}\].]")
# `"refresh_token": "…"`, `'refresh_token': '…'`, `refresh_token=…` (and the other keys).
_KEY_VALUE = re.compile(
    r"(?i)([\"']?\b(?:refresh_token|access_token|id_token|client_secret)\b[\"']?\s*[:=]\s*[\"']?)([^\"'&\s,;}\]]+)"
)


def register_secret(value: str | None, *, rotating: bool = False) -> None:
    """Remember `value` so every later message is scrubbed of it (raw, stripped and repr forms).

    `rotating=True` is for short-lived values (access tokens): those are kept in a bounded
    registry, the newest first. Everything else is kept for the life of the process.
    """
    if not value:
        return
    stripped = value.strip()
    if len(stripped) < _MIN_SECRET_LEN:
        return
    forms = {value, stripped, repr(value)[1:-1], repr(stripped)[1:-1]}
    if not rotating:
        _PINNED.update(forms)
        return
    for form in forms:
        _ROTATING.pop(form, None)
        _ROTATING[form] = None
    while len(_ROTATING) > _MAX_ROTATING:
        _ROTATING.popitem(last=False)


def clear_secrets() -> None:
    """Forget every registered value (tests isolate themselves with this)."""
    _PINNED.clear()
    _ROTATING.clear()


def redact(text: str) -> str:
    """`text` with every known secret and every token-shaped string replaced by ``***``."""
    # Longest first, so a value that contains another is replaced whole.
    for value in sorted(_PINNED.union(_ROTATING), key=len, reverse=True):
        text = text.replace(value, REDACTED)
    for pattern in _SHAPES:
        text = pattern.sub(REDACTED, text)
    text = _BEARER.sub(rf"\1 {REDACTED}", text)
    return _KEY_VALUE.sub(rf"\1{REDACTED}", text)


def one_line(text: str) -> str:
    """Collapse every run of whitespace (newlines included) to one space."""
    return " ".join(text.split())


# --- error types -------------------------------------------------------------------------


class GmailError(RuntimeError):
    """Base class: the message is already user-facing (cause, then the fix)."""


class ConfigError(GmailError):
    """The environment does not configure a runnable server (names every bad variable)."""


class GmailAuthError(GmailError):
    """The refresh-token grant failed, or the token may not be used by this entry."""


class TokenScopeError(GmailAuthError):
    """ADR D2: the token was granted more (or other) than gmail.readonly."""


class AccountMismatchError(GmailError):
    """ADR D3: the token's mailbox is not GMAIL_ACCOUNT; every tool is disabled."""


class MethodNotAllowedError(GmailError):
    """ADR D2: the Gmail client only ever sends GET."""


class ScopeConfigError(GmailError):
    """ADR D5: GMAIL_SCOPE_LABEL names no label in the mailbox; the server refuses to run."""


class QueryRejectedError(GmailError, ValueError):
    """ADR D5: a search query that could escape the project scope (unbalanced parentheses, …)."""


class NotFoundInScopeError(GmailError):
    """A missing id and an id outside the scope look the same (ADR D5: no headers leak)."""

    def __init__(self, kind: str, ident: str) -> None:
        self.kind = kind
        self.ident = ident
        super().__init__(
            f"{kind} {ident} was not found in this mailbox scope. Check the id (search for it first) and the "
            "active scope (gmail_health)."
        )


class GmailApiError(GmailError):
    """A non-2xx answer from the Gmail API. `reason` is Google's error reason (or status)."""

    def __init__(self, status: int, reason: str = "", message: str = "", *, retry_after: float | None = None) -> None:
        self.status = status
        self.reason = reason
        self.api_message = message
        self.retry_after = retry_after
        detail = f"Gmail API error {status}"
        if reason:
            detail += f" ({reason})"
        if message:
            detail += f": {message.rstrip('.')}"
        super().__init__(detail)


# --- tool errors ---------------------------------------------------------------------------

_TOKEN_FIX = "run amazing-gmail-mcp-login on the Mac and update 1Password."


def _api_hint(exc: GmailApiError) -> str:
    reason = exc.reason
    if exc.status == 400:
        if reason in {"failedPrecondition", "FAILED_PRECONDITION"}:
            return (
                "Gmail cannot serve this mailbox as it is (for example, Gmail is not enabled for the account): check "
                "the account in Gmail or in the Admin console."
            )
        return "Gmail rejected the request: check the ids, the page token and the query syntax."
    if exc.status == 401:
        return f"Google rejected the access token even after a refresh: {_TOKEN_FIX}"
    if exc.status == 403:
        if reason in {"rateLimitExceeded", "userRateLimitExceeded", "dailyLimitExceeded", "quotaExceeded"}:
            return "Gmail quota exceeded (6,000 units per minute per user): wait a minute and narrow the request."
        if reason in {"insufficientPermissions", "ACCESS_TOKEN_SCOPE_INSUFFICIENT"}:
            return f"the token does not carry gmail.readonly: {_TOKEN_FIX}"
        if reason in {"domainPolicy", "accessNotConfigured", "SERVICE_DISABLED"}:
            return (
                "the Workspace admin or the Cloud project blocks this client: enable the Gmail API in the project and "
                "trust the client ID (Admin console → Security → API controls)."
            )
        return "Google refused the request for this account."
    if exc.status == 404:
        return "not found: check the id."
    if exc.status == 429:
        wait = f" (Retry-After {exc.retry_after:g}s)" if exc.retry_after is not None else ""
        return f"rate limited by Gmail{wait}: wait before trying again; do not retry in a tight loop."
    if exc.status >= 500:
        return "Gmail is failing on its side (retried 3 times): try again in a minute."
    return ""


def _describe(exc: BaseException) -> str:
    """The unredacted one-line message for `describe_error`."""
    if isinstance(exc, GmailApiError):
        hint = _api_hint(exc)
        return f"{str(exc).rstrip('.')}." + (f" {hint}" if hint else "")
    if isinstance(exc, GmailError):
        return str(exc)
    if isinstance(exc, ValidationError):
        # Never the input values; location + message only.
        details = "; ".join(
            f"{'.'.join(str(part) for part in err['loc']) or 'value'}: {err['msg']}"
            for err in exc.errors(include_url=False, include_input=False, include_context=False)
        )
        return f"invalid input – {details}"
    if isinstance(exc, httpx.TimeoutException):
        return "the request to Google timed out: try again; if it keeps happening, check the network."
    if isinstance(exc, httpx.ConnectError):
        return "could not connect to Google: check network access and any HTTPS_PROXY setting."
    if isinstance(exc, httpx.TransportError):
        # Never str(exc): h11's "Illegal header value b'…'" quotes the header, i.e. the token.
        return f"the request to Google failed at the network layer ({type(exc).__name__}): check network access."
    message = redact(str(exc))  # before the cut: a secret cut in half matches nothing
    if len(message) > 300:
        message = message[:300] + "…"
    return (
        f"unexpected failure ({type(exc).__name__}): {message}"
        if message
        else f"unexpected failure ({type(exc).__name__})"
    )


def describe_error(exc: BaseException) -> str:
    """One redacted line for the model: the cause, then the fix. Never a traceback, never a token."""
    return one_line(redact(_describe(exc)))


def tool_error(exc: BaseException) -> ToolError:
    """The `ToolError` a tool raises for `exc` (`raise tool_error(exc) from None`)."""
    return ToolError(describe_error(exc))


# --- what the MCP SDK says on the server's behalf -----------------------------------------

# One validation message is capped at this many characters (after redaction).
MAX_ERROR_MESSAGE_CHARS = 500

# pydantic prints a rejected value as `input_value=<repr>` and cuts a long repr to its first
# and last characters, so the tail of a token would survive the shape patterns. Drop the
# whole echo: first pydantic's own `…, input_type=<type>]` ending, then any other spelling.
_INPUT_VALUE_LINE_RE = re.compile(r"input_value=.*, input_type=(\w+)\]$", re.MULTILINE)
_INPUT_VALUE_ANY_RE = re.compile(r"input_value=(?!<redacted>).*?(, input_type=|\]$|$)", re.MULTILINE)
REDACTED_INPUT = "input_value=<redacted>"


def scrub(text: str) -> str:
    """`redact`, then drop every pydantic `input_value=` echo."""
    text = redact(text)
    text = _INPUT_VALUE_LINE_RE.sub(rf"{REDACTED_INPUT}, input_type=\1]", text)
    return _INPUT_VALUE_ANY_RE.sub(rf"{REDACTED_INPUT}\1", text)


def _clip(text: str, limit: int = MAX_ERROR_MESSAGE_CHARS) -> str:
    return text if len(text) <= limit else f"{text[:limit]}… [truncated]"


def describe_validation_error(tool: str, exc: ValidationError) -> str:
    """An argument-validation failure on one line, without the raw input (redacted before clipping)."""
    errors = exc.errors(include_url=False, include_input=False, include_context=False)
    parts = [f"Error executing tool {tool}: invalid arguments for {exc.title}"]
    for err in errors:
        location = ".".join(str(part) for part in err["loc"]) or "value"
        parts.append(f"{_clip(scrub(location))}: {_clip(scrub(err['msg']))} [type={err['type']}]")
    return one_line(scrub("; ".join(parts)))


class RedactingLogFilter(logging.Filter):
    """Scrub a log record's rendered message (and traceback). Never raises."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # mismatched `%` args: logging would only report it later
            message = f"{record.msg} {record.args!r}"
        if record.exc_info or record.stack_info:
            # Fold the traceback into the message so it is scrubbed like the rest.
            try:
                extra = "".join(traceback.format_exception(*record.exc_info)) if record.exc_info else ""
            except Exception:
                extra = "<traceback unavailable>"
            if record.stack_info:
                extra += record.stack_info
            message = f"{message}\n{extra.rstrip()}"
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
        record.msg = scrub(message)
        record.args = None
        return True


def install_log_redaction(logger: logging.Logger | None = None, handlers: Iterable[logging.Handler] = ()) -> None:
    """Attach one `RedactingLogFilter` to every handler of `logger` (default: root), idempotently.

    Call it after FastMCP's constructor, which installs the stderr handler. Extra `handlers`
    (a test's capture handler) get the filter too.
    """
    target = logger if logger is not None else logging.getLogger()
    for handler in [*target.handlers, *handlers]:
        if not any(isinstance(existing, RedactingLogFilter) for existing in handler.filters):
            handler.addFilter(RedactingLogFilter())
