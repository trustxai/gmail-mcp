"""The one fetch-by-id helper (`scope.fetch_message` / `scope.fetch_thread`), through the three tools that use it.

gmail_get_message, gmail_get_thread and gmail_get_attachment all read one object by id, and
they must agree (found in the v0.1 review): the account pin runs BEFORE the fetch and keeps
its own cause; only a 404 and the 400 for an id Gmail cannot parse (`invalidArgument`) mean
"not found"; any other 400, 403 or 5xx keeps its real cause; the returned id must be the one
asked for; and the scope check runs before anything is shown. Most cases are negative.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp.server.fastmcp.exceptions import ToolError

from gmail_mcp.errors import GmailApiError, NotFoundInScopeError, describe_error
from gmail_mcp.scope import means_not_found
from gmail_mcp.tools.attachments import GetAttachmentInput, gmail_get_attachment
from gmail_mcp.tools.messages import GetMessageInput, gmail_get_message
from gmail_mcp.tools.threads import GetThreadInput, gmail_get_thread

from .fakes import FakeGoogle, FakeSleep, api_error, attachment_part, b64url, install, message, multipart, text_part

MID = "18c2f0e9a1b2c3d4"
OTHER = "ffff0000ffff0000"
AID = "ANGjdJ_FAKE_attachment_0001"
DATA = b"%PDF-1.7 fake"
PROFILE = "GET users/me/profile"
LABELS = "GET users/me/labels"


def _message(message_id: str = MID, labels: list[str] | None = None) -> dict[str, Any]:
    payload = multipart(
        "mixed", text_part("Hello", part_id="0"), attachment_part("a.pdf", "application/pdf", len(DATA), AID, "1")
    )
    return message(payload, message_id=message_id, labels=labels)


@dataclass(frozen=True)
class Tool:
    """One tool that fetches by id: the path it GETs, what Gmail answers, and how to call it."""

    kind: str
    path: str
    answer: Callable[..., dict[str, Any]]
    call: Callable[[], Awaitable[str]]


TOOLS = {
    "gmail_get_message": Tool(
        "message",
        f"users/me/messages/{MID}",
        _message,
        lambda: gmail_get_message(GetMessageInput(message_id=MID)),
    ),
    "gmail_get_thread": Tool(
        "thread",
        f"users/me/threads/{MID}",
        lambda message_id=MID, labels=None: {"id": message_id, "messages": [_message(labels=labels)]},
        lambda: gmail_get_thread(GetThreadInput(thread_id=MID)),
    ),
    "gmail_get_attachment": Tool(
        "message",
        f"users/me/messages/{MID}",
        _message,
        lambda: gmail_get_attachment(GetAttachmentInput(message_id=MID, part_id="1")),
    ),
}


@pytest.fixture(params=sorted(TOOLS))
def tool(request: pytest.FixtureRequest) -> Tool:
    return TOOLS[request.param]


def _install(fake: FakeGoogle, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, **env: str) -> FakeGoogle:
    fake.routes.setdefault(f"users/me/messages/{MID}/attachments/{AID}", {"size": len(DATA), "data": b64url(DATA)})
    client = install(fake, monkeypatch, GMAIL_ATTACHMENT_DIR=str(tmp_path / "att"), **env)
    monkeypatch.setattr(client, "_sleep", FakeSleep())  # 5xx retries wait for nothing
    return fake


async def _error(tool: Tool) -> str:
    with pytest.raises(ToolError) as info:
        await tool.call()
    return str(info.value)


def _not_found(tool: Tool) -> str:
    return describe_error(NotFoundInScopeError(tool.kind, MID))


# --- the way it works -----------------------------------------------------------------------


async def test_the_pin_runs_before_the_fetch(tool: Tool, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake = _install(FakeGoogle(routes={tool.path: tool.answer()}), monkeypatch, tmp_path)

    await tool.call()

    assert fake.log[:3] == ["token", PROFILE, f"GET {tool.path}"]


async def test_with_a_label_scope_the_pin_then_the_label_then_the_fetch(
    tool: Tool, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = FakeGoogle(routes={tool.path: tool.answer(labels=["Label_1"])})
    _install(fake, monkeypatch, tmp_path, GMAIL_SCOPE_LABEL="Projects/Acme")

    await tool.call()

    assert fake.log[:4] == ["token", PROFILE, LABELS, f"GET {tool.path}"]


# --- the pin keeps its cause ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "reason", "text"),
    [(400, "failedPrecondition", "Mail service not enabled"), (403, "forbidden", "Forbidden")],
    ids=["400-failedPrecondition", "403"],
)
async def test_a_failing_profile_keeps_its_cause_and_nothing_is_fetched(
    tool: Tool, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, status: int, reason: str, text: str
) -> None:
    fake = FakeGoogle(routes={"users/me/profile": api_error(status, reason, text), tool.path: tool.answer()})
    _install(fake, monkeypatch, tmp_path)

    error = await _error(tool)

    assert error.startswith(f"Gmail API error {status} ({reason}): {text}.")
    assert "not found" not in error
    assert fake.log == ["token", PROFILE]


# --- the fetch keeps its cause, except for the two "not found" answers ------------------------


@pytest.mark.parametrize(
    ("status", "reason", "text"),
    [
        (400, "failedPrecondition", "Mail service not enabled"),
        (400, "badRequest", "Bad Request"),
        (403, "insufficientPermissions", "Insufficient Permission"),
        (500, "backendError", "Backend Error"),
    ],
    ids=["400-failedPrecondition", "400-badRequest", "403", "500"],
)
async def test_a_failing_fetch_keeps_its_real_cause(
    tool: Tool, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, status: int, reason: str, text: str
) -> None:
    fake = _install(FakeGoogle(routes={tool.path: api_error(status, reason, text)}), monkeypatch, tmp_path)

    error = await _error(tool)

    assert error.startswith(f"Gmail API error {status} ({reason}): {text}.")
    assert "not found" not in error
    assert fake.log[:3] == ["token", PROFILE, f"GET {tool.path}"]


@pytest.mark.parametrize(
    "answer",
    [
        api_error(404, "notFound", "Requested entity was not found."),
        api_error(400, "invalidArgument", "Invalid id value"),
        # The same 400 with only the status, no `errors` list.
        httpx.Response(400, json={"error": {"code": 400, "message": "Invalid id value", "status": "INVALID_ARGUMENT"}}),
    ],
    ids=["404", "400-invalidArgument", "400-INVALID_ARGUMENT"],
)
async def test_only_a_404_and_an_unparsable_id_mean_not_found(
    tool: Tool, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, answer: httpx.Response
) -> None:
    fake = _install(FakeGoogle(routes={tool.path: answer}), monkeypatch, tmp_path)

    assert await _error(tool) == _not_found(tool)
    assert "/attachments/" not in " ".join(fake.log)


async def test_another_id_in_the_answer_is_not_found(
    tool: Tool, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    fake = _install(FakeGoogle(routes={tool.path: tool.answer(message_id=OTHER)}), monkeypatch, tmp_path)

    error = await _error(tool)

    assert error == _not_found(tool)
    assert "Hello" not in error and "a.pdf" not in error
    assert "/attachments/" not in " ".join(fake.log)


async def test_an_answer_without_an_id_is_not_found(
    tool: Tool, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    answer = tool.answer()
    del answer["id"]
    _install(FakeGoogle(routes={tool.path: answer}), monkeypatch, tmp_path)

    assert await _error(tool) == _not_found(tool)


async def test_out_of_scope_is_the_same_not_found(tool: Tool, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake = FakeGoogle(routes={tool.path: tool.answer(labels=["INBOX"])})
    _install(fake, monkeypatch, tmp_path, GMAIL_SCOPE_LABEL="Projects/Acme")

    assert await _error(tool) == _not_found(tool)
    assert "/attachments/" not in " ".join(fake.log)


# --- the rule itself ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "reason", "expected"),
    [
        (404, "notFound", True),
        (404, "", True),
        (400, "invalidArgument", True),
        (400, "INVALID_ARGUMENT", True),
        (400, "failedPrecondition", False),
        (400, "badRequest", False),
        (400, "", False),
        (403, "invalidArgument", False),
        (500, "backendError", False),
    ],
)
def test_means_not_found(status: int, reason: str, expected: bool) -> None:
    assert means_not_found(GmailApiError(status, reason)) is expected
