"""errors.py: token-like strings never reach an error message, a tool result or a log line."""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from mcp.server.fastmcp.exceptions import ToolError
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import TextContent
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from gmail_mcp.errors import (
    AccountMismatchError,
    GmailApiError,
    GmailAuthError,
    NotFoundInScopeError,
    RedactingLogFilter,
    clear_secrets,
    describe_error,
    install_log_redaction,
    redact,
    register_secret,
    scrub,
    tool_error,
)
from gmail_mcp.server import RedactingFastMCP, mcp

from .fakes import (
    ACCOUNT,
    FAKE_CLIENT_SECRET,
    FAKE_REFRESH_TOKEN,
    SHAPELESS_SECRET,
    FakeGoogle,
    fake_access_token,
    install,
    oauth_error,
)

ACCESS = fake_access_token(7)
# Built at runtime (see test_fixtures_hygiene.py): an authorization code and a bare refresh token.
AUTH_CODE = "4" + "/" + "0AeanS0FAKEcode0123456789abcdefghij"
OTHER_REFRESH = "1" + "/" * 2 + "0gFAKEotherRefresh0123456789"
TOKENS = [ACCESS, FAKE_REFRESH_TOKEN, OTHER_REFRESH, FAKE_CLIENT_SECRET, AUTH_CODE]


# --- redact() ---------------------------------------------------------------------------------


@pytest.mark.parametrize("token", TOKENS)
def test_token_shapes_are_redacted_without_being_registered(token: str) -> None:
    clear_secrets()
    assert redact(f"before {token} after.") == "before *** after."


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Authorization: Bearer opaque-value-zzq", "Authorization: Bearer ***"),
        ("authorization='bearer opaque-value-zzq'", "authorization='bearer ***'"),
        ('{"refresh_token": "opaque-value-zzq", "x": 1}', '{"refresh_token": "***", "x": 1}'),
        ("{'access_token': 'opaque-value-zzq'}", "{'access_token': '***'}"),
        ("grant_type=refresh_token&refresh_token=opaque-value-zzq&client_id=x", None),
        ("client_secret=opaque-value-zzq", "client_secret=***"),
        ('"id_token":"opaque-value-zzq"', '"id_token":"***"'),
    ],
)
def test_key_value_and_bearer_forms_are_redacted(text: str, expected: str | None) -> None:
    result = redact(text)
    assert "opaque-value-zzq" not in result
    if expected is not None:
        assert result == expected


def test_registered_secrets_are_redacted_in_every_form() -> None:
    secret = "plain-opaque-secret-value"
    register_secret(f" {secret}\n")
    assert redact(f"a {secret} b") == "a *** b"
    assert redact(f"a {secret!r} b") == "a '***' b"
    raw = f" {secret}\n"
    assert redact(f"value={raw!r}") == "value='***'"  # OSError / h11 quote values via repr


def test_configured_secrets_outlive_any_number_of_rotating_tokens() -> None:
    register_secret("configured-opaque-value-zzq")
    for n in range(500):
        register_secret(f"rotating-opaque-{n:04d}-value", rotating=True)
    assert redact("configured-opaque-value-zzq") == "***"
    assert redact("rotating-opaque-0499-value") == "***"
    assert redact("rotating-opaque-0000-value") == "rotating-opaque-0000-value"  # evicted: bounded memory


def test_short_registered_values_are_not_redacted_literally() -> None:
    register_secret("key")
    assert redact("a key b") == "a key b"


def test_the_longest_registered_value_wins() -> None:
    register_secret("opaque-secret")
    register_secret("opaque-secret-and-more")
    assert redact("x opaque-secret-and-more y") == "x *** y"


def test_ordinary_text_is_left_alone() -> None:
    text = "Meeting 1/2 at 4/5, see https://example.com/a//b and ya29 notes; bearer-of-news"
    assert redact(text) == text


# --- describe_error(): one line, the cause and the fix, never a token ---------------------------


def test_api_errors_are_one_line_with_a_hint_and_redacted() -> None:
    exc = GmailApiError(400, "invalidArgument", f"Invalid value\nfor q: Bearer {ACCESS}")
    message = describe_error(exc)
    assert "\n" not in message
    assert message.startswith("Gmail API error 400 (invalidArgument): Invalid value for q: Bearer ***.")
    assert "check the ids" in message
    assert ACCESS not in message


@pytest.mark.parametrize(
    ("status", "reason", "fragment"),
    [
        (401, "authError", "amazing-gmail-mcp-login"),
        (403, "insufficientPermissions", "gmail.readonly"),
        (403, "rateLimitExceeded", "quota"),
        (403, "domainPolicy", "API controls"),
        (404, "notFound", "check the id"),
        (429, "rateLimitExceeded", "rate limited"),
        (503, "backendError", "try again"),
    ],
)
def test_each_api_status_carries_its_fix(status: int, reason: str, fragment: str) -> None:
    assert fragment in describe_error(GmailApiError(status, reason, "x"))


def test_gmail_errors_keep_their_own_message() -> None:
    assert describe_error(AccountMismatchError("pinned to x")) == "pinned to x"
    assert "not found in this mailbox scope" in describe_error(NotFoundInScopeError("message", "18c2f0e9a1b2c3d4"))


def test_a_protocol_error_never_quotes_the_header() -> None:
    exc = httpx.LocalProtocolError(f"Illegal header value b'Bearer {ACCESS}'")
    message = describe_error(exc)
    assert "LocalProtocolError" in message
    assert ACCESS not in message
    assert "Bearer" not in message


@pytest.mark.parametrize(
    "exc",
    [httpx.ConnectTimeout("t"), httpx.ConnectError("c"), httpx.ReadError("r")],
    ids=["timeout", "connect", "transport"],
)
def test_transport_errors_are_described_without_their_text(exc: httpx.TransportError) -> None:
    assert "Google" in describe_error(exc)


def test_validation_errors_never_carry_the_input() -> None:
    class Model(BaseModel):
        count: int

    with pytest.raises(ValidationError) as info:
        Model(count=f"Bearer {ACCESS}")  # type: ignore[arg-type]
    message = describe_error(info.value)
    assert message.startswith("invalid input – count:")
    assert ACCESS not in message


def test_unexpected_errors_are_redacted_and_clipped() -> None:
    message = describe_error(RuntimeError(f"boom {FAKE_REFRESH_TOKEN} " + "x" * 1000))
    assert message.startswith("unexpected failure (RuntimeError): boom ***")
    assert FAKE_REFRESH_TOKEN not in message
    assert len(message) < 400


def test_unexpected_errors_are_redacted_before_they_are_clipped() -> None:
    # A registered, shapeless secret straddling the 300-character cut: cut first, the kept
    # prefix would match neither the registered value nor any shape.
    register_secret(SHAPELESS_SECRET)
    message = describe_error(RuntimeError("y" * 290 + SHAPELESS_SECRET + " tail"))
    assert SHAPELESS_SECRET[:10] not in message
    assert message == "unexpected failure (RuntimeError): " + "y" * 290 + "*** tail"


def test_tool_error_is_a_tool_error_with_the_described_message() -> None:
    error = tool_error(GmailAuthError(f"bad {ACCESS}"))
    assert isinstance(error, ToolError)
    assert str(error) == "bad ***"


# --- log lines ----------------------------------------------------------------------------------


def _record(msg: str, *args: object, exc_info: bool = False) -> logging.LogRecord:
    info = None
    if exc_info:
        try:
            raise RuntimeError(f"inner {ACCESS}")
        except RuntimeError:
            info = sys.exc_info()
    return logging.LogRecord("gmail_mcp.test", logging.WARNING, __file__, 1, msg, args, info)


def test_the_log_filter_scrubs_message_args_and_traceback() -> None:
    record = _record("refresh failed for %s with %s", ACCOUNT, f"Bearer {ACCESS}", exc_info=True)

    assert RedactingLogFilter().filter(record) is True

    rendered = record.getMessage()
    assert ACCESS not in rendered
    assert "Bearer ***" in rendered
    assert "RuntimeError: inner ***" in rendered
    assert record.exc_info is None and record.args is None


def test_the_log_filter_drops_pydantic_input_echoes() -> None:
    record = _record("Failed to validate request: input_value='opaque-zzq-value', input_type=str]")
    RedactingLogFilter().filter(record)
    assert "opaque-zzq-value" not in record.getMessage()
    assert "input_value=<redacted>" in record.getMessage()


def test_install_log_redaction_is_idempotent() -> None:
    logger = logging.getLogger("gmail_mcp.test.idempotent")
    handler = logging.StreamHandler()
    logger.addHandler(handler)
    try:
        install_log_redaction(logger)
        install_log_redaction(logger)
        assert sum(isinstance(f, RedactingLogFilter) for f in handler.filters) == 1
    finally:
        logger.removeHandler(handler)


def test_the_server_installs_the_filter_on_the_root_handlers() -> None:
    script = (
        "import logging, gmail_mcp.server\n"
        "from gmail_mcp.errors import RedactingLogFilter\n"
        "handlers = logging.getLogger().handlers\n"
        "ok = handlers and all(any(isinstance(f, RedactingLogFilter) for f in h.filters) for h in handlers)\n"
        "raise SystemExit(0 if ok else 1)\n"
    )
    env = {"HOME": os.environ.get("HOME", ""), "PATH": os.environ.get("PATH", "")}
    result = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, env=env)
    assert result.returncode == 0, result.stderr


def test_a_record_through_a_filtered_handler_is_scrubbed(caplog: pytest.LogCaptureFixture) -> None:
    install_log_redaction(logging.getLogger(), handlers=[caplog.handler])
    logging.getLogger("gmail_mcp.test").warning("token %s", ACCESS)
    assert ACCESS not in caplog.text
    assert "token ***" in caplog.text


class EchoInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message_id: str = Field(min_length=1)

    @field_validator("message_id")
    @classmethod
    def _shape(cls, value: str) -> str:
        raise ValueError(f"bad id {value!r}")


# --- what leaves the server -------------------------------------------------------------------


async def test_a_tool_error_reaches_the_client_as_is_error_without_a_token(monkeypatch: pytest.MonkeyPatch) -> None:
    # A token endpoint that echoes credentials in its error code.
    fake = FakeGoogle(token_responses=[oauth_error(f"weird {FAKE_REFRESH_TOKEN} {ACCESS}", status=500)])
    install(fake, monkeypatch)

    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool("gmail_health", {})

    assert result.isError is True
    [content] = result.content
    assert isinstance(content, TextContent)
    assert "token endpoint answered HTTP 500" in content.text
    for token in (FAKE_REFRESH_TOKEN, ACCESS, FAKE_CLIENT_SECRET):
        assert token not in content.text
    assert "Traceback" not in content.text


async def test_argument_validation_failures_are_not_echoed() -> None:
    server = RedactingFastMCP("redaction-test")

    @server.tool(name="gmail_echo")
    async def gmail_echo(params: EchoInput) -> str:
        return params.message_id

    long_token = ACCESS + "Z" * 80
    with pytest.raises(ToolError) as info:
        await server.call_tool("gmail_echo", {"params": {"message_id": long_token}})
    message = str(info.value)
    assert "invalid arguments" in message
    assert long_token not in message
    assert long_token[-20:] not in message  # pydantic's head…tail cut never survives
    assert "ya29" + "." not in message


async def test_an_unknown_tool_name_is_scrubbed() -> None:
    with pytest.raises(ToolError) as info:
        await mcp.call_tool(f"gmail_{ACCESS}", {})
    assert ACCESS not in str(info.value)


def test_the_config_error_on_stderr_never_carries_the_token(tmp_path: Path) -> None:
    env = {
        "HOME": str(tmp_path),
        "PATH": os.environ.get("PATH", ""),
        "GMAIL_REFRESH_TOKEN": FAKE_REFRESH_TOKEN,
        "GMAIL_CLIENT_SECRET": FAKE_CLIENT_SECRET,
    }
    result = subprocess.run(
        [sys.executable, "-c", "from gmail_mcp.server import main_stdio; main_stdio()"],
        capture_output=True,
        text=True,
        env=env,
        cwd=tmp_path,
        timeout=60,
    )
    assert result.returncode == 2
    assert "GMAIL_ACCOUNT is not set" in result.stderr
    assert FAKE_REFRESH_TOKEN not in result.stderr + result.stdout
    assert FAKE_CLIENT_SECRET not in result.stderr + result.stdout


def test_scrub_is_redact_plus_input_echo_removal() -> None:
    assert scrub(f"input_value='{ACCESS}', input_type=str]") == "input_value=<redacted>, input_type=str]"
