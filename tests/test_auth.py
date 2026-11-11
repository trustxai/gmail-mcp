"""auth.py: the refresh grant, the in-memory cache, ADR D2 (read-only scopes) and D4 (dead tokens)."""

from __future__ import annotations

import asyncio
import logging

import httpx
import pytest

from gmail_mcp.auth import (
    EXPIRY_MARGIN_SECONDS,
    READONLY_SCOPE,
    TOKEN_URL,
    TokenProvider,
    invalid_grant_message,
    scope_problem,
)
from gmail_mcp.errors import GmailAuthError, TokenScopeError, redact

from .fakes import (
    ACCOUNT,
    FAKE_CLIENT_ID,
    FAKE_CLIENT_SECRET,
    FAKE_NEW_REFRESH_TOKEN,
    FAKE_REFRESH_TOKEN,
    FULL_MAIL,
    GMAIL_COMPOSE,
    GMAIL_MODIFY,
    USERINFO_EMAIL,
    FakeClock,
    FakeGoogle,
    fake_access_token,
    form_body,
    make_settings,
    oauth_error,
    token_body,
)


def _provider(fake: FakeGoogle, clock: FakeClock | None = None) -> TokenProvider:
    return TokenProvider(make_settings(), httpx.MockTransport(fake), clock=clock or FakeClock())


# --- the refresh grant ---------------------------------------------------------------------


async def test_refresh_grant_posts_the_refresh_token_to_the_token_endpoint() -> None:
    fake = FakeGoogle()

    token = await _provider(fake).access_token()

    assert token == fake_access_token(1)
    [request] = fake.requests
    assert request.method == "POST"
    assert str(request.url) == TOKEN_URL
    assert form_body(request) == {
        "grant_type": ["refresh_token"],
        "refresh_token": [FAKE_REFRESH_TOKEN],
        "client_id": [FAKE_CLIENT_ID],
        "client_secret": [FAKE_CLIENT_SECRET],
    }


async def test_the_access_token_is_cached_until_60_seconds_before_expiry() -> None:
    fake = FakeGoogle()
    clock = FakeClock()
    provider = _provider(fake, clock)

    first = await provider.access_token()
    clock.advance(3599 - EXPIRY_MARGIN_SECONDS - 0.5)  # still inside the window
    assert await provider.access_token() == first
    assert fake.token_count == 1

    clock.advance(0.5)  # exactly 60 s before expiry: refresh
    second = await provider.access_token()

    assert fake.token_count == 2
    assert second == fake_access_token(2) != first


async def test_invalidate_forces_a_refresh() -> None:
    fake = FakeGoogle()
    provider = _provider(fake)
    await provider.access_token()

    provider.invalidate()
    await provider.access_token()

    assert fake.token_count == 2


async def test_concurrent_callers_share_one_refresh() -> None:
    fake = FakeGoogle()
    provider = _provider(fake)

    tokens = await asyncio.gather(*(provider.access_token() for _ in range(20)))

    assert set(tokens) == {fake_access_token(1)}
    assert fake.token_count == 1


async def test_a_missing_expires_in_falls_back_to_an_hour() -> None:
    body = token_body(1)
    del body["expires_in"]
    fake = FakeGoogle(token_responses=[body])
    clock = FakeClock()
    provider = _provider(fake, clock)

    await provider.access_token()
    clock.advance(3000)
    await provider.access_token()

    assert fake.token_count == 1


async def test_granted_scopes_are_recorded() -> None:
    fake = FakeGoogle(scope=f"openid {READONLY_SCOPE} {USERINFO_EMAIL} email")
    provider = _provider(fake)
    assert provider.granted_scopes == ()

    await provider.access_token()

    assert provider.granted_scopes == tuple(sorted(["openid", READONLY_SCOPE, USERINFO_EMAIL, "email"]))


# --- D4: invalid_grant -----------------------------------------------------------------------


async def test_invalid_grant_raises_the_adr_message_and_is_never_retried() -> None:
    fake = FakeGoogle(token_responses=[oauth_error("invalid_grant", description="Token has been expired or revoked.")])
    provider = _provider(fake)

    with pytest.raises(GmailAuthError) as info:
        await provider.access_token()

    assert str(info.value) == (
        f"the refresh token for {ACCOUNT} is no longer valid (revoked, password changed, unused 6 months, or the "
        "100-token cap): run amazing-gmail-mcp-login on the Mac and update 1Password"
    )
    assert str(info.value) == invalid_grant_message(ACCOUNT)
    # No retry loop: the death is remembered, later calls send nothing.
    for _ in range(3):
        with pytest.raises(GmailAuthError, match="no longer valid"):
            await provider.access_token()
    assert fake.token_count == 1


async def test_invalid_client_names_the_client_variables_and_is_remembered() -> None:
    fake = FakeGoogle(token_responses=[oauth_error("invalid_client", status=401)])
    provider = _provider(fake)

    with pytest.raises(GmailAuthError, match="GMAIL_CLIENT_SECRET_FILE"):
        await provider.access_token()
    with pytest.raises(GmailAuthError):
        await provider.access_token()

    assert fake.token_count == 1


@pytest.mark.parametrize(
    "response",
    [
        oauth_error("temporarily_unavailable", status=503),
        httpx.Response(502, text="<html>Bad Gateway</html>"),
        httpx.Response(200, json={"token_type": "Bearer"}),
    ],
    ids=["oauth-503", "non-json-502", "no-access-token"],
)
async def test_a_transient_token_failure_is_an_error_but_not_remembered(response: httpx.Response) -> None:
    fake = FakeGoogle(token_responses=[response, token_body(2)])
    provider = _provider(fake)

    with pytest.raises(GmailAuthError, match="try again"):
        await provider.access_token()
    assert await provider.access_token() == fake_access_token(2)
    assert fake.token_count == 2


# --- D2: read-only by construction -------------------------------------------------------------


@pytest.mark.parametrize("extra", [GMAIL_MODIFY, GMAIL_COMPOSE, FULL_MAIL])
@pytest.mark.parametrize("with_readonly", [True, False], ids=["plus-readonly", "alone"])
async def test_a_scope_beyond_readonly_refuses_to_run(extra: str, with_readonly: bool) -> None:
    granted = f"{READONLY_SCOPE} {extra}" if with_readonly else extra
    fake = FakeGoogle(scope=granted)
    provider = _provider(fake)

    with pytest.raises(TokenScopeError) as info:
        await provider.access_token()

    assert str(info.value) == (
        f"this entry is read-only; its token can do more ({extra}): mint a gmail.readonly token with "
        "amazing-gmail-mcp-login"
    )
    # The refusal is for good: no token is handed out, no second refresh is tried.
    with pytest.raises(TokenScopeError):
        await provider.access_token()
    assert fake.token_count == 1
    assert provider.granted_scopes == ()


async def test_several_extra_scopes_are_all_named() -> None:
    fake = FakeGoogle(scope=f"{READONLY_SCOPE} {GMAIL_MODIFY} {FULL_MAIL} openid")

    with pytest.raises(TokenScopeError) as info:
        await _provider(fake).access_token()

    assert f"({FULL_MAIL} {GMAIL_MODIFY})" in str(info.value)


async def test_readonly_plus_identity_scopes_is_accepted() -> None:
    fake = FakeGoogle(scope=f"{READONLY_SCOPE} openid email {USERINFO_EMAIL}")

    assert await _provider(fake).access_token() == fake_access_token(1)


async def test_a_token_without_gmail_readonly_is_refused() -> None:
    fake = FakeGoogle(scope=f"openid {USERINFO_EMAIL}")

    with pytest.raises(TokenScopeError, match="not granted gmail.readonly"):
        await _provider(fake).access_token()


async def test_a_response_without_scope_is_refused_fail_closed() -> None:
    fake = FakeGoogle(token_responses=[token_body(1, scope=None)])

    with pytest.raises(TokenScopeError, match="did not report the granted scopes"):
        await _provider(fake).access_token()


def test_scope_problem_unit() -> None:
    assert scope_problem(READONLY_SCOPE) is None
    assert scope_problem(f"  {READONLY_SCOPE}   openid ") is None
    assert scope_problem(f"{READONLY_SCOPE} https://www.googleapis.com/auth/gmail.metadata") is not None
    assert scope_problem(f"{READONLY_SCOPE} https://www.googleapis.com/auth/gmail.labels") is not None
    assert scope_problem("") is not None
    assert scope_problem(None) is not None


# --- a new refresh_token in a response --------------------------------------------------------


async def test_a_new_refresh_token_logs_a_warning_without_the_value(caplog: pytest.LogCaptureFixture) -> None:
    fake = FakeGoogle(token_responses=[token_body(1, refresh_token=FAKE_NEW_REFRESH_TOKEN)])

    with caplog.at_level(logging.DEBUG):
        await _provider(fake).access_token()

    warnings = [record for record in caplog.records if record.levelno == logging.WARNING]
    assert len(warnings) == 1
    message = warnings[0].getMessage()
    assert "new refresh token" in message
    assert ACCOUNT in message
    assert "amazing-gmail-mcp-login" in message
    everything = caplog.text + " ".join(record.getMessage() for record in caplog.records)
    assert FAKE_NEW_REFRESH_TOKEN not in everything
    assert FAKE_REFRESH_TOKEN not in everything
    # The new value is registered for redaction everywhere else, too.
    assert redact(f"x {FAKE_NEW_REFRESH_TOKEN} y") == "x *** y"


async def test_the_same_refresh_token_echoed_back_is_not_a_warning(caplog: pytest.LogCaptureFixture) -> None:
    fake = FakeGoogle(token_responses=[token_body(1, refresh_token=FAKE_REFRESH_TOKEN)])

    with caplog.at_level(logging.WARNING):
        await _provider(fake).access_token()

    assert not caplog.records


async def test_no_log_line_ever_carries_a_credential(caplog: pytest.LogCaptureFixture) -> None:
    fake = FakeGoogle()
    with caplog.at_level(logging.DEBUG):
        token = await _provider(fake).access_token()

    assert token not in caplog.text
    assert FAKE_REFRESH_TOKEN not in caplog.text
    assert FAKE_CLIENT_SECRET not in caplog.text


async def test_minted_access_tokens_are_registered_for_redaction() -> None:
    fake = FakeGoogle()
    token = await _provider(fake).access_token()

    assert redact(f"Authorization {token}") == "Authorization ***"
