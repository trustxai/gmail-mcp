"""Async HTTP client for the Gmail API — the only way a tool reaches the network.

The safety rails live HERE, not in the tools, so no tool module can forget them:

- **GET only (ADR D2).** `request()` refuses every method other than GET before anything
  else happens — no token is read, no request is sent. Together with the gmail.readonly
  check in auth.py, this server cannot change a mailbox.
- **Account pin (ADR D3).** Before the first API call the client fetches
  `users/me/profile` and compares `emailAddress` with GMAIL_ACCOUNT (case-insensitive). A
  mismatch is remembered: every later call fails with the same error and sends nothing.
- **Fixed host, `users/me/` paths.** The base URL is a constant and a path must be a
  `users/me/…` path of plain characters, so a tool cannot point the token anywhere else.
- **Retries (ADR D6).** A GET that gets 429, a 5xx, or a rate-limit 403 is retried at most
  `MAX_RETRIES` times, waiting what `Retry-After` asks (or 1 s, 2 s, 4 s), never more than
  `MAX_RETRY_AFTER_SECONDS` per wait. A 401 refreshes the access token once.
- **Bounded concurrency (ADR D6).** At most `MAX_CONCURRENCY` requests are in flight at
  once, client-wide; `batch_get` is the helper for fan-out metadata fetches.

Tools call `await get_client().get("users/me/…", params)` and get the parsed JSON object.
"""

from __future__ import annotations

import asyncio
import email.utils
import re
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any

import httpx

from gmail_mcp.auth import TokenProvider
from gmail_mcp.config import Settings, get_settings
from gmail_mcp.errors import AccountMismatchError, GmailApiError, MethodNotAllowedError

API_BASE = "https://gmail.googleapis.com/gmail/v1"
PROFILE_PATH = "users/me/profile"
MAX_RETRIES = 3
BACKOFF_SECONDS: tuple[float, ...] = (1.0, 2.0, 4.0)
MAX_RETRY_AFTER_SECONDS = 30.0
MAX_CONCURRENCY = 10
REQUEST_TIMEOUT_SECONDS = 30.0
# 403s that are quota, not permission (Gmail's documented rate-limit reasons).
RETRYABLE_403_REASONS: frozenset[str] = frozenset({"rateLimitExceeded", "userRateLimitExceeded"})

# `users/me/` then path segments of id-safe characters; `..` segments are refused separately.
_PATH_RE = re.compile(r"users/me/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")

Sleep = Callable[[float], Awaitable[None]]


class GmailClient:
    """Thin async wrapper around httpx for one pinned Gmail mailbox."""

    def __init__(
        self,
        settings: Settings | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        *,
        auth: TokenProvider | None = None,
        sleep: Sleep = asyncio.sleep,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        self._settings = settings or get_settings()
        self._transport = transport
        self.auth = auth or TokenProvider(self._settings, transport)
        self._sleep = sleep
        self._wall_clock = wall_clock
        self._http: httpx.AsyncClient | None = None
        self._slots = asyncio.Semaphore(MAX_CONCURRENCY)
        self._pin_lock = asyncio.Lock()
        self._profile: dict[str, Any] | None = None
        self._pin_error: AccountMismatchError | None = None

    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def pinned(self) -> bool:
        """True once the profile matched GMAIL_ACCOUNT."""
        return self._profile is not None

    # -- public API ------------------------------------------------------------------

    async def request(self, method: str, path: str, params: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Send one API request. Only GET exists; anything else is refused before any I/O."""
        if method.upper() != "GET":
            raise MethodNotAllowedError(
                f"this server is read-only by construction: the Gmail client only sends GET, not {method.upper()!r}"
            )
        _check_path(path)
        await self._ensure_pinned()
        return await self._get(path, params)

    async def get(self, path: str, params: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """GET `<API_BASE>/<path>` and return the JSON object (pins the account first)."""
        return await self.request("GET", path, params)

    async def pinned_profile(self) -> dict[str, Any]:
        """The `users/me/profile` the pin matched (fetched once; the health tool reports it)."""
        await self._ensure_pinned()
        if self._profile is None:  # pragma: no cover - _ensure_pinned sets it or raises
            raise AccountMismatchError("the account pin did not complete")
        return dict(self._profile)

    async def batch_get(
        self, calls: Sequence[tuple[str, Mapping[str, Any] | None]], *, return_exceptions: bool = False
    ) -> list[dict[str, Any] | Exception]:
        """GET every `(path, params)` concurrently — never more than `MAX_CONCURRENCY` in flight.

        Results come back in the order of `calls`. With `return_exceptions=False` the first
        failure is raised once every call has finished; with `True` each failed slot holds
        its exception (a partial list is then the caller's choice).
        """
        for path, _ in calls:
            _check_path(path)
        await self._ensure_pinned()
        results = await asyncio.gather(*(self._get(path, params) for path, params in calls), return_exceptions=True)
        out: list[dict[str, Any] | Exception] = []
        for result in results:
            if isinstance(result, BaseException) and not isinstance(result, Exception):
                raise result  # cancellation and the like are never swallowed
            out.append(result)
        if not return_exceptions:
            for result in out:
                if isinstance(result, Exception):
                    raise result
        return out

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    # -- account pin (ADR D3) --------------------------------------------------------

    async def _ensure_pinned(self) -> None:
        if self._pin_error is not None:
            raise self._pin_error
        if self._profile is not None:
            return
        async with self._pin_lock:
            if self._pin_error is not None:
                raise self._pin_error
            if self._profile is not None:
                return
            profile = await self._get(PROFILE_PATH, None)
            expected = self._settings.account_email
            actual = profile.get("emailAddress")
            if not isinstance(actual, str) or not actual:
                self._pin_error = AccountMismatchError(
                    f"this server is pinned to GMAIL_ACCOUNT={expected}, but Gmail's profile reports no emailAddress: "
                    "every tool is disabled"
                )
                raise self._pin_error
            if actual.strip().lower() != expected.strip().lower():
                self._pin_error = AccountMismatchError(
                    f"this server is pinned to GMAIL_ACCOUNT={expected}, but the refresh token belongs to {actual}: "
                    f"every tool is disabled. Mint a token for {expected} with amazing-gmail-mcp-login, or fix "
                    "GMAIL_ACCOUNT"
                )
                raise self._pin_error
            self._profile = profile

    # -- transport -------------------------------------------------------------------

    def _client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(
                timeout=REQUEST_TIMEOUT_SECONDS,
                transport=self._transport,
                limits=httpx.Limits(max_connections=MAX_CONCURRENCY, max_keepalive_connections=MAX_CONCURRENCY),
            )
        return self._http

    async def _send(self, path: str, params: Mapping[str, Any] | None, token: str) -> httpx.Response:
        async with self._slots:
            return await self._client().get(
                f"{API_BASE}/{path}",
                params=_wire_params(params),
                headers={"accept": "application/json", "authorization": f"Bearer {token}"},
            )

    async def _get(self, path: str, params: Mapping[str, Any] | None) -> dict[str, Any]:
        token = await self.auth.access_token()
        refreshed = False
        retries = 0
        while True:
            resp = await self._send(path, params, token)
            if resp.status_code == 401 and not refreshed:
                refreshed = True
                self.auth.invalidate()
                token = await self.auth.access_token()
                continue
            if resp.status_code < 400:
                return _json_object(resp)
            error = _api_error(resp, self._wall_clock)
            if not _retryable(error) or retries >= MAX_RETRIES:
                raise error
            wait = error.retry_after if error.retry_after is not None else BACKOFF_SECONDS[retries]
            if wait > MAX_RETRY_AFTER_SECONDS:
                raise error
            retries += 1
            await self._sleep(wait)


def _check_path(path: str) -> None:
    if not _PATH_RE.fullmatch(path) or ".." in path.split("/"):
        raise ValueError(f"not a users/me/ API path: {path!r}")


def _wire_params(params: Mapping[str, Any] | None) -> dict[str, Any]:
    """Drop `None`, spell bools as `true`/`false`; lists stay lists (httpx repeats the key)."""
    out: dict[str, Any] = {}
    for key, value in (params or {}).items():
        if value is None:
            continue
        if isinstance(value, bool):
            out[key] = "true" if value else "false"
        elif isinstance(value, list | tuple):
            items = [str(item) for item in value if item is not None]
            if items:
                out[key] = items
        else:
            out[key] = value
    return out


def _json_object(resp: httpx.Response) -> dict[str, Any]:
    try:
        body = resp.json()
    except ValueError:
        raise GmailApiError(
            resp.status_code, "nonJsonResponse", "Gmail answered with something that is not JSON"
        ) from None
    if not isinstance(body, dict):
        raise GmailApiError(resp.status_code, "nonJsonResponse", "Gmail answered with something that is not an object")
    return body


def _retry_after(value: str | None, wall_clock: Callable[[], float]) -> float | None:
    """`Retry-After` in seconds: a number, or an HTTP date relative to now."""
    if value is None:
        return None
    text = value.strip()
    try:
        return max(0.0, float(text))
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None
    return max(0.0, when.timestamp() - wall_clock())


def _api_error(resp: httpx.Response, wall_clock: Callable[[], float]) -> GmailApiError:
    reason = ""
    message = ""
    try:
        body = resp.json()
    except ValueError:
        body = None
    error = body.get("error") if isinstance(body, dict) else None
    if isinstance(error, dict):
        message = str(error.get("message") or "")
        details = error.get("errors")
        if isinstance(details, list) and details and isinstance(details[0], dict):
            reason = str(details[0].get("reason") or "")
        reason = reason or str(error.get("status") or "")
    elif isinstance(error, str):
        reason = error
    return GmailApiError(
        resp.status_code, reason, message, retry_after=_retry_after(resp.headers.get("retry-after"), wall_clock)
    )


def _retryable(error: GmailApiError) -> bool:
    return error.status == 429 or error.status >= 500 or (error.status == 403 and error.reason in RETRYABLE_403_REASONS)


_client: GmailClient | None = None


def get_client() -> GmailClient:
    """Lazy module-level singleton (tests reset it with `reset_client`)."""
    global _client
    if _client is None:
        _client = GmailClient()
    return _client


def reset_client() -> None:
    """Drop the singleton (its token cache and its pin go with it)."""
    global _client
    _client = None
