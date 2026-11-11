"""Refresh token → access token, in memory only (ADR-0001 D2 and D4).

The configured refresh token is exchanged at Google's token endpoint (`grant_type=
refresh_token`). The access token is kept in memory until `EXPIRY_MARGIN_SECONDS` before it
expires and is never written anywhere.

Two refusals live here, because the token endpoint is the one place that reports what the
token can do:

- **D2, read-only by construction.** The response's `scope` must be `gmail.readonly`, plus
  at most the identity scopes (`openid`, `email`, `userinfo.email`). A token granted
  anything else — `gmail.modify`, `gmail.compose`, `https://mail.google.com/` — can send
  mail, so this entry refuses to run with it, for the life of the process.
- **D4, token death is a clear error.** `invalid_grant` (revoked, unused 6 months, password
  changed, the 100-token cap, admin restriction) raises `GmailAuthError` telling the
  operator to mint a new token. No retry loop: the failure is remembered and every later
  call gets it without another request.

A token response that ever carries a NEW `refresh_token` logs a warning (never the value):
the stored one may stop working.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable

import httpx

from gmail_mcp.config import Settings
from gmail_mcp.errors import GmailAuthError, TokenScopeError, register_secret

TOKEN_URL = "https://oauth2.googleapis.com/token"
READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
# Identity scopes a login may add next to gmail.readonly; they read no mail.
IDENTITY_SCOPES: frozenset[str] = frozenset({"openid", "email", "https://www.googleapis.com/auth/userinfo.email"})
ALLOWED_SCOPES: frozenset[str] = IDENTITY_SCOPES | {READONLY_SCOPE}
# The access token is reused until this many seconds before it expires.
EXPIRY_MARGIN_SECONDS = 60.0
# Used when a token response omits `expires_in` (Google always sends it: 3599).
DEFAULT_EXPIRES_IN_SECONDS = 3600.0
TOKEN_TIMEOUT_SECONDS = 30.0

_LOGIN_FIX = "mint a gmail.readonly token with amazing-gmail-mcp-login"

logger = logging.getLogger(__name__)


def scope_problem(granted: str | None) -> str | None:
    """Why the granted scopes break ADR D2, or `None` when they are gmail.readonly (+ identity) only."""
    if granted is None:
        return (
            "the token endpoint did not report the granted scopes, so this read-only entry cannot verify them: "
            f"{_LOGIN_FIX}"
        )
    scopes = set(granted.split())
    extra = sorted(scopes - ALLOWED_SCOPES)
    if extra:
        return f"this entry is read-only; its token can do more ({' '.join(extra)}): {_LOGIN_FIX}"
    if READONLY_SCOPE not in scopes:
        return (
            f"the token was not granted gmail.readonly (it has: {' '.join(sorted(scopes)) or 'nothing'}): {_LOGIN_FIX}"
        )
    return None


def invalid_grant_message(account: str) -> str:
    """ADR D4's message for a dead refresh token."""
    return (
        f"the refresh token for {account} is no longer valid (revoked, password changed, unused 6 months, or the "
        "100-token cap): run amazing-gmail-mcp-login on the Mac and update 1Password"
    )


class TokenProvider:
    """Exchanges the refresh token for access tokens and caches the current one in memory."""

    def __init__(
        self,
        settings: Settings,
        transport: httpx.AsyncBaseTransport | None = None,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._settings = settings
        self._transport = transport
        self._clock = clock
        self._lock = asyncio.Lock()
        self._access_token: str | None = None
        self._expires_at = 0.0
        self._granted: tuple[str, ...] = ()
        # A failure that no retry can fix (D2 refusal, D4 invalid_grant, a rejected client).
        self._fatal: GmailAuthError | None = None

    @property
    def granted_scopes(self) -> tuple[str, ...]:
        """The scopes the last successful refresh reported (empty before the first one)."""
        return self._granted

    def _valid(self) -> bool:
        return self._access_token is not None and self._clock() < self._expires_at - EXPIRY_MARGIN_SECONDS

    def invalidate(self) -> None:
        """Drop the cached access token (the API answered 401), so the next call refreshes."""
        self._access_token = None
        self._expires_at = 0.0

    async def access_token(self) -> str:
        """A valid access token: the cached one, or a fresh one from the token endpoint."""
        if self._fatal is not None:
            raise self._fatal
        if self._valid() and self._access_token is not None:
            return self._access_token
        async with self._lock:
            if self._fatal is not None:
                raise self._fatal
            if self._valid() and self._access_token is not None:
                return self._access_token
            return await self._refresh()

    async def _refresh(self) -> str:
        settings = self._settings
        credentials = settings.credentials
        form = {
            "grant_type": "refresh_token",
            "refresh_token": settings.refresh_token_value,
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret.get_secret_value(),
        }
        async with httpx.AsyncClient(timeout=TOKEN_TIMEOUT_SECONDS, transport=self._transport) as client:
            resp = await client.post(TOKEN_URL, data=form, headers={"accept": "application/json"})
        try:
            body = resp.json()
        except ValueError:
            body = None
        if not isinstance(body, dict):
            raise GmailAuthError(
                f"the token endpoint answered HTTP {resp.status_code} without a JSON body: try again in a minute"
            )
        if resp.status_code != 200:
            raise self._grant_error(resp.status_code, body)
        token = body.get("access_token")
        if not isinstance(token, str) or not token:
            raise GmailAuthError("the token endpoint answered without an access_token: try again in a minute")
        register_secret(token, rotating=True)
        self._check_new_refresh_token(body.get("refresh_token"))
        granted = body.get("scope")
        problem = scope_problem(granted if isinstance(granted, str) else None)
        if problem is not None:
            error = TokenScopeError(problem)
            if isinstance(granted, str):
                # The grant itself carries the scopes: no later refresh can change them.
                self._fatal = error
            raise error
        self._granted = tuple(sorted(str(granted).split()))
        try:
            expires_in = float(body.get("expires_in", DEFAULT_EXPIRES_IN_SECONDS))
        except (TypeError, ValueError):
            expires_in = DEFAULT_EXPIRES_IN_SECONDS
        self._access_token = token
        self._expires_at = self._clock() + expires_in
        return token

    def _check_new_refresh_token(self, value: object) -> None:
        if not isinstance(value, str) or not value:
            return
        register_secret(value)
        if value == self._settings.refresh_token_value:
            return
        logger.warning(
            "the token endpoint returned a new refresh token for %s; the stored one may stop working: run "
            "amazing-gmail-mcp-login on the Mac and update 1Password",
            self._settings.account_email,
        )

    def _grant_error(self, status: int, body: dict[str, object]) -> GmailAuthError:
        code = str(body.get("error") or "")
        if code == "invalid_grant":
            self._fatal = GmailAuthError(invalid_grant_message(self._settings.account_email))
            return self._fatal
        if code in {"invalid_client", "unauthorized_client"}:
            self._fatal = GmailAuthError(
                f"Google rejected the OAuth client ({code}): GMAIL_CLIENT_SECRET_FILE (or GMAIL_CLIENT_ID + "
                "GMAIL_CLIENT_SECRET) must be the Desktop client the refresh token was minted with"
            )
            return self._fatal
        detail = f" ({code})" if code else ""
        return GmailAuthError(f"the token endpoint answered HTTP {status}{detail}: try again in a minute")
