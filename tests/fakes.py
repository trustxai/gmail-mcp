"""Test doubles: a fake Google (token endpoint + Gmail API) behind `httpx.MockTransport`.

Credential-shaped fixtures are built at RUNTIME, so no file in this public repo holds a
literal that looks like a Google token (secret scanners flag those): see
`test_fixtures_hygiene.py`. Every address is under example.com.
"""

from __future__ import annotations

import base64
import inspect
import json
from collections.abc import Awaitable, Callable, Iterable, Mapping
from typing import Any
from urllib.parse import parse_qs

import httpx

from gmail_mcp.auth import READONLY_SCOPE, TOKEN_URL
from gmail_mcp.client import API_BASE, GmailClient
from gmail_mcp.config import Settings
from gmail_mcp.validators import encoded_length

ACCOUNT = "ops@example.com"
OTHER_ACCOUNT = "someone-else@example.com"

# `ya29.` / `1//` / `GOCSPX-` assembled from pieces: the redaction patterns match them,
# a scan of the source never does.
_DOT = "."
_SLASHES = "/" * 2
FAKE_REFRESH_TOKEN = "1" + _SLASHES + "FAKE-refresh-0123456789abcdef"
FAKE_NEW_REFRESH_TOKEN = "1" + _SLASHES + "FAKE-rotated-9876543210fedcba"
# Joined at runtime too: a numeric project prefix glued to the client host is a client-id shape.
FAKE_CLIENT_ID = "-".join(["000000000000", "fakeclient.apps.googleusercontent.com"])
FAKE_CLIENT_SECRET = "GOCSPX" + "-" + "FAKEsecret0123456789abcdef"

# A secret that matches no shape pattern (like the login's PKCE verifier): only its
# registration (`errors.register_secret`) redacts it, and only as a WHOLE value.
SHAPELESS_SECRET = "Zq9shapelessSECRETvalue77"

GMAIL_MODIFY = "https://www.googleapis.com/auth/gmail.modify"
GMAIL_COMPOSE = "https://www.googleapis.com/auth/gmail.compose"
FULL_MAIL = "https://mail.google.com/"
USERINFO_EMAIL = "https://www.googleapis.com/auth/userinfo.email"


def fake_access_token(n: int) -> str:
    return "ya29" + _DOT + f"FAKE-access-{n:04d}-abcdefghijklmnop"


def make_settings(**overrides: Any) -> Settings:
    """Valid server settings (inline client credentials) unless overridden."""
    values: dict[str, Any] = {
        "account": ACCOUNT,
        "refresh_token": FAKE_REFRESH_TOKEN,
        "client_id": FAKE_CLIENT_ID,
        "client_secret": FAKE_CLIENT_SECRET,
    }
    values.update(overrides)
    return Settings(**values)


Route = Mapping[str, Any] | httpx.Response | Callable[[httpx.Request], Any] | list[Any]


class FakeGoogle:
    """A MockTransport handler for both Google hosts; records every request in order.

    - The token endpoint answers from `token_responses` (a queue; the last entry repeats),
      by default a fresh readonly access token per refresh.
    - Gmail API paths (after `/gmail/v1/`) answer from `routes`: a mapping (JSON 200), an
      `httpx.Response`, a callable `(request) -> response | mapping`, or a list used as a
      queue (the last entry repeats). Unknown paths answer 404 like Gmail does.
    """

    def __init__(
        self,
        *,
        profile_email: str = ACCOUNT,
        scope: str = READONLY_SCOPE,
        routes: Mapping[str, Route] | None = None,
        token_responses: list[Any] | None = None,
        max_request_target: int | None = None,
    ) -> None:
        self.requests: list[httpx.Request] = []
        # Like Gmail's front end: a longer request target (path plus query) gets a 400 HTML page.
        self.max_request_target = max_request_target
        self.token_count = 0
        self.scope = scope
        self.token_responses = list(token_responses or [])
        self.routes: dict[str, Route] = {
            "users/me/profile": {
                "emailAddress": profile_email,
                "messagesTotal": 42,
                "threadsTotal": 17,
                "historyId": "123456",
            },
            "users/me/labels": {"labels": LABELS},
        }
        self.routes.update(routes or {})

    # -- views of the request log ----------------------------------------------------

    @property
    def log(self) -> list[str]:
        """`token` for a refresh, else `GET <path>` — the order requests were sent in."""
        return ["token" if _is_token(r) else f"{r.method} {_api_path(r)}" for r in self.requests]

    @property
    def api_requests(self) -> list[httpx.Request]:
        return [request for request in self.requests if not _is_token(request)]

    @property
    def token_requests(self) -> list[httpx.Request]:
        return [request for request in self.requests if _is_token(request)]

    def params(self, index: int) -> dict[str, list[str]]:
        """The query parameters of the `index`-th API request."""
        return parse_qs(self.api_requests[index].url.query.decode(), keep_blank_values=True)

    # -- the handler ---------------------------------------------------------------------

    def __call__(self, request: httpx.Request) -> Any:
        self.requests.append(request)
        if _is_token(request):
            return self._token(request)
        if self.max_request_target is not None and len(request.url.raw_path) > self.max_request_target:
            return httpx.Response(400, text="<html><title>Error 400 (Bad Request)!!1</title></html>")
        path = _api_path(request)
        route = self.routes.get(path)
        if route is None:
            return httpx.Response(404, json=_error(404, "notFound", "Requested entity was not found."))
        return _respond(route, request)

    def _token(self, request: httpx.Request) -> httpx.Response:
        self.token_count += 1
        if self.token_responses:
            entry = self.token_responses.pop(0) if len(self.token_responses) > 1 else self.token_responses[0]
            if isinstance(entry, httpx.Response):
                return _clone(entry)
            if callable(entry):
                result = entry(request)
                return result if isinstance(result, httpx.Response) else httpx.Response(200, json=result)
            return httpx.Response(200, json=entry)
        return httpx.Response(200, json=token_body(self.token_count, scope=self.scope))


def token_body(
    n: int = 1, *, scope: str | None = READONLY_SCOPE, expires_in: int = 3599, **extra: Any
) -> dict[str, Any]:
    body: dict[str, Any] = {"access_token": fake_access_token(n), "expires_in": expires_in, "token_type": "Bearer"}
    if scope is not None:
        body["scope"] = scope
    body.update(extra)
    return body


def _is_token(request: httpx.Request) -> bool:
    return str(request.url).split("?", 1)[0] == TOKEN_URL


def _api_path(request: httpx.Request) -> str:
    prefix = httpx.URL(API_BASE).path + "/"
    path = request.url.path
    return path[len(prefix) :] if path.startswith(prefix) else path


def _respond(route: Route, request: httpx.Request) -> Any:
    if isinstance(route, list):
        entry = route.pop(0) if len(route) > 1 else route[0]
        return _respond(entry, request)
    if isinstance(route, httpx.Response):
        return _clone(route)
    if callable(route):
        result = route(request)
        if inspect.isawaitable(result):
            return _awaited(result)
        return result if isinstance(result, httpx.Response) else httpx.Response(200, json=result)
    return httpx.Response(200, json=dict(route))


async def _awaited(result: Awaitable[Any]) -> httpx.Response:
    value = await result
    return value if isinstance(value, httpx.Response) else httpx.Response(200, json=value)


def _clone(response: httpx.Response) -> httpx.Response:
    """A fresh copy, so one canned response can be served any number of times."""
    return httpx.Response(response.status_code, headers=response.headers, content=response.content)


def _error(code: int, reason: str, message: str) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "errors": [{"reason": reason, "message": message}]}}


def api_error(
    code: int, reason: str = "backendError", message: str = "Backend Error", **headers: str
) -> httpx.Response:
    return httpx.Response(code, json=_error(code, reason, message), headers=headers)


def oauth_error(error: str, status: int = 400, description: str = "") -> httpx.Response:
    body = {"error": error}
    if description:
        body["error_description"] = description
    return httpx.Response(status, json=body)


LABELS: list[dict[str, Any]] = [
    {"id": "INBOX", "name": "INBOX", "type": "system"},
    {"id": "SPAM", "name": "SPAM", "type": "system"},
    {"id": "TRASH", "name": "TRASH", "type": "system"},
    {"id": "Label_1", "name": "Projects/Acme", "type": "user"},
    {"id": "Label_2", "name": "Receipts", "type": "user"},
]


def make_client(fake: FakeGoogle, settings: Settings | None = None, **kwargs: Any) -> GmailClient:
    return GmailClient(settings or make_settings(), httpx.MockTransport(fake), **kwargs)


class FakeSleep:
    """An injectable `sleep` that records the waits and returns at once (a fake clock)."""

    def __init__(self) -> None:
        self.waits: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.waits.append(seconds)


class FakeClock:
    """A monotonic clock the tests move by hand."""

    def __init__(self, now: float = 1_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# --- Gmail message payloads ------------------------------------------------------------


def b64url(data: bytes) -> str:
    """Gmail's encoding of `body.data`: URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def header(name: str, value: str) -> dict[str, str]:
    return {"name": name, "value": value}


def text_part(
    text: str = "",
    *,
    mime: str = "text/plain",
    charset: str | None = "utf-8",
    raw: bytes | None = None,
    part_id: str = "0",
    filename: str = "",
    extra_headers: Iterable[dict[str, str]] = (),
    attachment_id: str | None = None,
) -> dict[str, Any]:
    data = raw if raw is not None else text.encode(charset or "utf-8")
    content_type = f"{mime}; charset={charset}" if charset else mime
    body: dict[str, Any] = {"size": len(data)}
    if attachment_id is None:
        body["data"] = b64url(data)
    else:
        body["attachmentId"] = attachment_id
    return {
        "partId": part_id,
        "mimeType": mime,
        "filename": filename,
        "headers": [header("Content-Type", content_type), *extra_headers],
        "body": body,
    }


def attachment_part(
    filename: str, mime: str, size: int, attachment_id: str = "ANGjdJ_FAKE_attachment_0001", part_id: str = "1"
) -> dict[str, Any]:
    return {
        "partId": part_id,
        "mimeType": mime,
        "filename": filename,
        "headers": [
            header("Content-Type", f'{mime}; name="{filename}"'),
            header("Content-Disposition", f'attachment; filename="{filename}"'),
        ],
        "body": {"attachmentId": attachment_id, "size": size},
    }


def multipart(subtype: str, *parts: dict[str, Any], part_id: str = "") -> dict[str, Any]:
    return {
        "partId": part_id,
        "mimeType": f"multipart/{subtype}",
        "filename": "",
        "headers": [header("Content-Type", f'multipart/{subtype}; boundary="b-{subtype}"')],
        "body": {"size": 0},
        "parts": list(parts),
    }


DEFAULT_HEADERS: list[dict[str, str]] = [
    header("From", "Ada <ada@example.com>"),
    header("To", "ops@example.com"),
    header("Subject", "Quarterly numbers"),
    header("Date", "Tue, 10 Nov 2026 10:00:00 +0000"),
    header("Message-ID", "<msg-0001@mail.example.com>"),
]


def message(
    payload: dict[str, Any] | None = None,
    *,
    message_id: str = "18c2f0e9a1b2c3d4",
    thread_id: str = "18c2f0e9a1b2c3d4",
    labels: list[str] | None = None,
    headers: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """A `messages.get?format=full` object; the top-level headers live on the payload."""
    payload = dict(payload or text_part("Hello"))
    payload["headers"] = [*(DEFAULT_HEADERS if headers is None else headers), *payload.get("headers", [])]
    return {
        "id": message_id,
        "threadId": thread_id,
        "labelIds": ["INBOX"] if labels is None else labels,
        "snippet": "Hello",
        "internalDate": "1794308400000",
        "payload": payload,
    }


def json_body(request: httpx.Request) -> Any:
    return json.loads(request.content.decode() or "null")


def form_body(request: httpx.Request) -> dict[str, list[str]]:
    return parse_qs(request.content.decode(), keep_blank_values=True)


def install(fake: FakeGoogle, monkeypatch: Any, **env: str) -> GmailClient:
    """Configure the process like a running server (env vars) and plug `fake` into the client singleton."""
    from gmail_mcp import client as client_module
    from gmail_mcp import scope as scope_module
    from gmail_mcp.config import get_settings

    values = {
        "GMAIL_ACCOUNT": ACCOUNT,
        "GMAIL_REFRESH_TOKEN": FAKE_REFRESH_TOKEN,
        "GMAIL_CLIENT_ID": FAKE_CLIENT_ID,
        "GMAIL_CLIENT_SECRET": FAKE_CLIENT_SECRET,
    }
    values.update(env)
    for key, value in values.items():
        monkeypatch.setenv(key, value)
    get_settings.cache_clear()
    scope_module.reset_scope()
    client = make_client(fake, get_settings())
    monkeypatch.setattr(client_module, "_client", client)
    return client


# --- worst cases for the output bounds ------------------------------------------------------

# One character, four bytes of UTF-8: the most a character can weigh.
FOUR_BYTES = "\U0001f600"
# Longer than any cap, so every field is cut to its bound.
OVERLONG = 5_000
# Three bytes of UTF-8 (9 characters once percent-encoded): CJK text.
CJK = "\u6f22"
# Gmail's front end refuses a longer request target (path plus query) with a 400 page: measured
# by the v0.1 review on 2026-11-11 (validators.GMAIL_MAX_REQUEST_TARGET).
GMAIL_REQUEST_TARGET_LIMIT = 16_384


def text_of_encoded_size(char: str, size: int) -> str:
    """`char` repeated, padded with ASCII `a`, so it takes exactly `size` characters percent-encoded."""
    weight = encoded_length(char) or 0
    text = char * (size // weight)
    return text + "a" * (size - (encoded_length(text) or 0))


def longest_request_target(fake: FakeGoogle) -> int:
    """The longest request target (path and query) of the API requests `fake` received."""
    return max(len(request.url.raw_path) for request in fake.api_requests)


def worst_headers(n: int = 0) -> list[dict[str, str]]:
    """The six rendered headers, each OVERLONG 4-byte characters (and a second Cc to join)."""
    big = FOUR_BYTES * OVERLONG
    return [
        header("From", big),
        header("To", big),
        header("Cc", big),
        header("Cc", big),
        header("Date", big),
        header("Subject", big),
        header("Message-ID", f"<worst-{n:04d}@mail.example.com>"),
    ]


def worst_attachments(count: int) -> list[dict[str, Any]]:
    """`count` attachments whose name and type are OVERLONG 4-byte characters."""
    return [
        {
            "partId": str(n + 1),
            "mimeType": FOUR_BYTES * OVERLONG,
            "filename": FOUR_BYTES * OVERLONG,
            "headers": [],
            "body": {"attachmentId": f"ANGjdJ_FAKE_worst_{n:04d}", "size": 1},
        }
        for n in range(count)
    ]


def worst_labels() -> list[str]:
    return [FOUR_BYTES * 10 + str(n) for n in range(300)]


def worst_message(
    body_chars: int, *, attachments: int, message_id: str, thread_id: str | None = None, n: int = 0
) -> dict[str, Any]:
    """A `format=full` message with every rendered field at (or over) its cap, in 4-byte characters."""
    payload = multipart(
        "mixed", text_part(FOUR_BYTES * body_chars, part_id="0"), *worst_attachments(attachments), part_id=""
    )
    return message(
        payload,
        message_id=message_id,
        thread_id=thread_id if thread_id is not None else FOUR_BYTES * OVERLONG,
        labels=worst_labels(),
        headers=worst_headers(n),
    )
