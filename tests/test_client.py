"""client.py: GET only, the account pin (ADR D3), retries (D6) and bounded concurrency."""

from __future__ import annotations

import asyncio
import email.utils
from typing import Any

import httpx
import pytest

from gmail_mcp import client as client_module
from gmail_mcp.client import (
    API_BASE,
    BACKOFF_SECONDS,
    MAX_CONCURRENCY,
    MAX_RETRIES,
    MAX_RETRY_AFTER_SECONDS,
    get_client,
    reset_client,
)
from gmail_mcp.errors import AccountMismatchError, GmailApiError, MethodNotAllowedError

from .fakes import (
    ACCOUNT,
    OTHER_ACCOUNT,
    FakeGoogle,
    FakeSleep,
    api_error,
    fake_access_token,
    make_client,
    make_settings,
)

PROFILE = "GET users/me/profile"
LABELS = "GET users/me/labels"


# --- GET only ------------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "post", "Delete"])
async def test_every_method_but_get_is_refused_before_any_request(method: str) -> None:
    fake = FakeGoogle()
    client = make_client(fake)

    with pytest.raises(MethodNotAllowedError, match="only sends GET"):
        await client.request(method, "users/me/messages/18c2f0e9a1b2c3d4/trash")

    assert fake.requests == []  # not even a token refresh


async def test_a_refused_method_is_refused_even_after_the_pin() -> None:
    fake = FakeGoogle()
    client = make_client(fake)
    await client.get("users/me/labels")
    sent = len(fake.requests)

    with pytest.raises(MethodNotAllowedError):
        await client.request("POST", "users/me/drafts")

    assert len(fake.requests) == sent


@pytest.mark.parametrize(
    "path",
    [
        "users/other@example.com/messages",
        "users/me",
        "/users/me/messages",
        "users/me/../../oauth2/v4/token",
        "users/me/messages?q=x",
        "https://evil.example.com/users/me/messages",
        "users/me/messages/a b",
    ],
)
async def test_paths_outside_users_me_are_refused_before_any_request(path: str) -> None:
    fake = FakeGoogle()
    with pytest.raises(ValueError, match="not a users/me/ API path"):
        await make_client(fake).get(path)
    assert fake.requests == []


async def test_requests_go_to_the_gmail_api_with_the_bearer_token() -> None:
    fake = FakeGoogle()
    await make_client(fake).get("users/me/labels")

    request = fake.api_requests[-1]
    assert str(request.url).startswith(f"{API_BASE}/users/me/labels")
    assert request.method == "GET"
    assert request.headers["authorization"] == f"Bearer {fake_access_token(1)}"


async def test_params_are_encoded_for_the_wire() -> None:
    fake = FakeGoogle(routes={"users/me/messages": {"messages": []}})

    await make_client(fake).get(
        "users/me/messages",
        {"q": "from:ada@example.com", "labelIds": ["INBOX", "Label_1"], "includeSpamTrash": False, "pageToken": None},
    )

    assert fake.params(-1) == {
        "q": ["from:ada@example.com"],
        "labelIds": ["INBOX", "Label_1"],
        "includeSpamTrash": ["false"],
    }


# --- D3: the account pin -------------------------------------------------------------------


async def test_the_pin_runs_once_before_the_first_api_call() -> None:
    fake = FakeGoogle()
    client = make_client(fake)

    await client.get("users/me/labels")
    await client.get("users/me/labels")

    assert fake.log == ["token", PROFILE, LABELS, LABELS]
    assert client.pinned


async def test_the_pin_is_case_insensitive() -> None:
    fake = FakeGoogle(profile_email="Ops@Example.COM")
    await make_client(fake, make_settings(account=ACCOUNT)).get("users/me/labels")
    assert fake.log[-1] == LABELS


async def test_pinned_profile_reuses_the_pin_response() -> None:
    fake = FakeGoogle()
    client = make_client(fake)

    profile = await client.pinned_profile()
    again = await client.pinned_profile()

    assert profile["emailAddress"] == ACCOUNT
    assert again == profile
    assert fake.log == ["token", PROFILE]


async def test_a_pin_mismatch_fails_every_call_and_sends_nothing_more() -> None:
    fake = FakeGoogle(profile_email=OTHER_ACCOUNT)
    client = make_client(fake)

    with pytest.raises(AccountMismatchError) as info:
        await client.get("users/me/labels")

    message = str(info.value)
    assert f"GMAIL_ACCOUNT={ACCOUNT}" in message
    assert f"belongs to {OTHER_ACCOUNT}" in message
    assert "every tool is disabled" in message
    assert fake.log == ["token", PROFILE]  # the labels call never left

    for call in (
        client.get("users/me/labels"),
        client.get("users/me/messages", {"q": "x"}),
        client.pinned_profile(),
        client.batch_get([("users/me/messages/18c2f0e9a1b2c3d4", None)]),
    ):
        with pytest.raises(AccountMismatchError):
            await call
    assert fake.log == ["token", PROFILE]


async def test_a_profile_without_email_is_a_mismatch_fail_closed() -> None:
    fake = FakeGoogle(routes={"users/me/profile": {"messagesTotal": 1}})
    client = make_client(fake)

    with pytest.raises(AccountMismatchError, match="reports no emailAddress"):
        await client.get("users/me/labels")
    with pytest.raises(AccountMismatchError):
        await client.get("users/me/labels")
    assert fake.log == ["token", PROFILE]


async def test_a_failed_pin_request_is_not_remembered() -> None:
    fake = FakeGoogle(routes={"users/me/profile": [api_error(404, "notFound"), {"emailAddress": ACCOUNT}]})
    client = make_client(fake)

    with pytest.raises(GmailApiError):
        await client.get("users/me/labels")
    await client.get("users/me/labels")

    assert fake.log == ["token", PROFILE, PROFILE, LABELS]


async def test_concurrent_first_calls_pin_once() -> None:
    fake = FakeGoogle()
    client = make_client(fake)

    await asyncio.gather(*(client.get("users/me/labels") for _ in range(5)))

    assert fake.log.count(PROFILE) == 1
    assert fake.log.count("token") == 1


# --- D6: retries ----------------------------------------------------------------------------


async def test_5xx_is_retried_with_backoff_then_succeeds() -> None:
    fake = FakeGoogle(routes={"users/me/labels": [api_error(503), api_error(500), api_error(502), {"labels": []}]})
    sleep = FakeSleep()
    client = make_client(fake, sleep=sleep)
    await client.pinned_profile()

    body = await client.get("users/me/labels")

    assert body == {"labels": []}
    assert sleep.waits == list(BACKOFF_SECONDS) == [1.0, 2.0, 4.0]
    assert fake.log.count(LABELS) == 4


async def test_retries_stop_after_three() -> None:
    fake = FakeGoogle(routes={"users/me/labels": [api_error(503)]})
    sleep = FakeSleep()
    client = make_client(fake, sleep=sleep)
    await client.pinned_profile()

    with pytest.raises(GmailApiError) as info:
        await client.get("users/me/labels")

    assert info.value.status == 503
    assert len(sleep.waits) == MAX_RETRIES == 3
    assert fake.log.count(LABELS) == MAX_RETRIES + 1


async def test_429_honors_retry_after_seconds() -> None:
    fake = FakeGoogle(routes={"users/me/labels": [api_error(429, "rateLimitExceeded", **{"Retry-After": "7"}), {}]})
    sleep = FakeSleep()
    client = make_client(fake, sleep=sleep)
    await client.pinned_profile()

    await client.get("users/me/labels")

    assert sleep.waits == [7.0]


async def test_429_honors_an_http_date_retry_after_against_the_wall_clock() -> None:
    now = 1_800_000_000.0
    date = email.utils.formatdate(now + 12, usegmt=True)
    fake = FakeGoogle(routes={"users/me/labels": [api_error(429, **{"Retry-After": date}), {}]})
    sleep = FakeSleep()
    client = make_client(fake, sleep=sleep, wall_clock=lambda: now)
    await client.pinned_profile()

    await client.get("users/me/labels")

    assert sleep.waits == [12.0]


async def test_a_retry_after_beyond_the_cap_is_not_waited_for() -> None:
    too_long = str(int(MAX_RETRY_AFTER_SECONDS) + 1)
    fake = FakeGoogle(routes={"users/me/labels": [api_error(429, **{"Retry-After": too_long}), {}]})
    sleep = FakeSleep()
    client = make_client(fake, sleep=sleep)
    await client.pinned_profile()

    with pytest.raises(GmailApiError) as info:
        await client.get("users/me/labels")

    assert info.value.status == 429
    assert info.value.retry_after == float(too_long)
    assert sleep.waits == []
    assert fake.log.count(LABELS) == 1


async def test_a_rate_limit_403_is_retried() -> None:
    fake = FakeGoogle(routes={"users/me/labels": [api_error(403, "userRateLimitExceeded"), {}]})
    sleep = FakeSleep()
    client = make_client(fake, sleep=sleep)
    await client.pinned_profile()

    await client.get("users/me/labels")

    assert sleep.waits == [1.0]


@pytest.mark.parametrize(
    "response",
    [api_error(403, "insufficientPermissions"), api_error(404, "notFound"), api_error(400, "invalidArgument")],
    ids=["403-permission", "404", "400"],
)
async def test_client_errors_are_not_retried(response: httpx.Response) -> None:
    fake = FakeGoogle(routes={"users/me/labels": [response]})
    sleep = FakeSleep()
    client = make_client(fake, sleep=sleep)
    await client.pinned_profile()

    with pytest.raises(GmailApiError) as info:
        await client.get("users/me/labels")

    assert info.value.status == response.status_code
    assert sleep.waits == []
    assert fake.log.count(LABELS) == 1


async def test_a_401_refreshes_the_access_token_once() -> None:
    fake = FakeGoogle(routes={"users/me/labels": [api_error(401, "authError"), {"labels": []}]})
    client = make_client(fake)
    await client.pinned_profile()

    await client.get("users/me/labels")

    labels_requests = [r for r in fake.api_requests if r.url.path.endswith("/labels")]
    assert [r.headers["authorization"] for r in labels_requests] == [
        f"Bearer {fake_access_token(1)}",
        f"Bearer {fake_access_token(2)}",
    ]
    assert fake.token_count == 2


async def test_a_second_401_is_an_error() -> None:
    fake = FakeGoogle(routes={"users/me/labels": [api_error(401, "authError")]})
    client = make_client(fake)
    await client.pinned_profile()

    with pytest.raises(GmailApiError) as info:
        await client.get("users/me/labels")

    assert info.value.status == 401
    assert fake.token_count == 2


async def test_a_non_json_success_is_an_api_error() -> None:
    fake = FakeGoogle(routes={"users/me/labels": httpx.Response(200, text="<html>")})
    client = make_client(fake)
    with pytest.raises(GmailApiError, match="not JSON"):
        await client.get("users/me/labels")


# --- D6: bounded concurrency ----------------------------------------------------------------


async def test_batch_get_never_exceeds_ten_concurrent_requests() -> None:
    in_flight = 0
    peak = 0

    async def slow(request: httpx.Request) -> httpx.Response:
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.005)
        in_flight -= 1
        return httpx.Response(200, json={"id": request.url.path.rsplit("/", 1)[-1]})

    ids = [f"{n:016x}" for n in range(1, 36)]
    fake = FakeGoogle(routes={f"users/me/messages/{ident}": slow for ident in ids})
    client = make_client(fake)

    results = await client.batch_get([(f"users/me/messages/{ident}", {"format": "metadata"}) for ident in ids])

    assert [result["id"] for result in results if isinstance(result, dict)] == ids  # in order
    assert peak == MAX_CONCURRENCY == 10


async def test_the_concurrency_bound_is_client_wide() -> None:
    in_flight = 0
    peak = 0

    async def slow(request: httpx.Request) -> httpx.Response:
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.005)
        in_flight -= 1
        return httpx.Response(200, json={})

    fake = FakeGoogle(routes={"users/me/labels": slow})
    client = make_client(fake)
    await client.pinned_profile()

    await asyncio.gather(*(client.get("users/me/labels") for _ in range(25)))

    assert peak == MAX_CONCURRENCY


async def test_batch_get_raises_the_first_failure_or_returns_them() -> None:
    fake = FakeGoogle(
        routes={
            "users/me/messages/aaaaaaaaaaaaaaaa": {"id": "a"},
            "users/me/messages/bbbbbbbbbbbbbbbb": api_error(404, "notFound"),
        }
    )
    client = make_client(fake)
    calls: list[tuple[str, dict[str, Any] | None]] = [
        ("users/me/messages/aaaaaaaaaaaaaaaa", None),
        ("users/me/messages/bbbbbbbbbbbbbbbb", None),
    ]

    with pytest.raises(GmailApiError):
        await client.batch_get(calls)
    results = await client.batch_get(calls, return_exceptions=True)

    assert results[0] == {"id": "a"}
    assert isinstance(results[1], GmailApiError)


async def test_batch_get_checks_every_path_before_sending() -> None:
    fake = FakeGoogle()
    with pytest.raises(ValueError):
        await make_client(fake).batch_get([("users/me/labels", None), ("users/x/labels", None)])
    assert fake.requests == []


# --- the singleton -----------------------------------------------------------------------------


def test_get_client_is_a_singleton_until_reset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(client_module, "get_settings", make_settings)
    first = get_client()
    assert get_client() is first
    reset_client()
    assert get_client() is not first
