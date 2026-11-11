"""gmail_get_attachment against a MockTransport Google, writing only under pytest's tmp_path.

ADR-0002: the tool takes `message_id` + `part_id`, finds the part in a FRESH `format=full`
fetch that passed the scope check, and downloads with the attachmentId of THAT fetch. Covers
the order the rails need (scope first, the size checked before any download, unknown sizes
refused), Gmail's rotating attachment ids, the file-system side (0700 / 0600, never
overwriting, safe names against path traversal and against the response redaction), and
the refusals. More than half of the cases are negative.
"""

from __future__ import annotations

import hashlib
import re
import stat
from pathlib import Path
from typing import Any

import httpx
import pytest
from mcp.server.fastmcp.exceptions import ToolError
from mcp.shared.memory import create_connected_server_and_client_session
from mcp.types import TextContent
from pydantic import ValidationError

import gmail_mcp.tools.attachments as module
from gmail_mcp.errors import redact, register_secret
from gmail_mcp.server import mcp
from gmail_mcp.tools.attachments import (
    MAX_NAME_BYTES,
    GetAttachmentInput,
    gmail_get_attachment,
    numbered,
    parse_size,
    safe_filename,
)

from .fakes import (
    FAKE_CLIENT_SECRET,
    FAKE_REFRESH_TOKEN,
    OTHER_ACCOUNT,
    FakeGoogle,
    api_error,
    attachment_part,
    b64url,
    fake_access_token,
    install,
    message,
    multipart,
    text_part,
)

MID = "18c2f0e9a1b2c3d4"
AID = "ANGjdJ_FAKE_attachment_0001"  # the id THIS fetch shows
AID_NEXT = "ANGjdJ_FAKE_attachment_0002"  # the id the NEXT fetch shows (Gmail rotates them)
PDF = b"%PDF-1.7 fake report body\n" * 40
PROFILE = "GET users/me/profile"
LABELS = "GET users/me/labels"
MESSAGE = f"GET users/me/messages/{MID}"
LIST = "GET users/me/messages"
NOT_FOUND_TAIL = (
    "was not found in this mailbox scope. Check the id (search for it first) and the active scope (gmail_health)."
)


def _att(aid: str = AID) -> str:
    return f"GET users/me/messages/{MID}/attachments/{aid}"


@pytest.fixture(autouse=True)
def _home_in_tmp(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Belt and braces: even a test that forgot GMAIL_ATTACHMENT_DIR could only reach a
    # fake home under tmp_path, never ~/Downloads.
    monkeypatch.setenv("HOME", str(tmp_path / "home"))


@pytest.fixture
def att_dir(tmp_path: Path) -> Path:
    return tmp_path / "att"


def _pdf_part(
    *, filename: str = "report.pdf", size: Any = None, attachment_id: str = AID, part_id: str = "1"
) -> dict[str, Any]:
    part = attachment_part(filename, "application/pdf", len(PDF), attachment_id=attachment_id, part_id=part_id)
    if size is not None:
        part["body"]["size"] = size
    return part


def _pdf_message(*, part: dict[str, Any] | None = None, **kwargs: Any) -> dict[str, Any]:
    payload = multipart("mixed", text_part("See attached", part_id="0"), part or _pdf_part())
    return message(payload, message_id=MID, **kwargs)


def attachment_route(data: bytes) -> Any:
    """attachments.get: size + base64url data; refuses a partial (`fields`) request."""

    def handle(request: httpx.Request) -> Any:
        assert "fields" not in request.url.params
        return {"size": len(data), "data": b64url(data)}

    return handle


def _fake(msg: Any = None, attachments: dict[str, Any] | None = None, **routes: Any) -> FakeGoogle:
    all_routes: dict[str, Any] = {f"users/me/messages/{MID}": _pdf_message() if msg is None else msg}
    for aid, route in (attachments if attachments is not None else {AID: attachment_route(PDF)}).items():
        all_routes[f"users/me/messages/{MID}/attachments/{aid}"] = route
    all_routes.update(routes)
    return FakeGoogle(routes=all_routes)


def _install(fake: FakeGoogle, monkeypatch: pytest.MonkeyPatch, att_dir: Path, **env: str) -> None:
    install(fake, monkeypatch, GMAIL_ATTACHMENT_DIR=str(att_dir), **env)


def _params(part_id: str = "1", message_id: str = MID) -> GetAttachmentInput:
    return GetAttachmentInput(message_id=message_id, part_id=part_id)


def _saved_path(result: str) -> Path:
    match = re.search(r"- \*\*path\*\*: `([^`]+)`", result)
    assert match, result
    return Path(match.group(1))


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*") if path.is_file()) if root.exists() else []


def _attachment_requests(fake: FakeGoogle) -> list[str]:
    return [entry for entry in fake.log if "/attachments/" in entry]


def _no_secrets(text: str) -> None:
    for secret in (FAKE_REFRESH_TOKEN, FAKE_CLIENT_SECRET, fake_access_token(1)):
        assert secret not in text


def _part_not_found(part_id: str) -> str:
    return f'attachment partId "{part_id}" of message {MID} {NOT_FOUND_TAIL}'


# --- registration --------------------------------------------------------------------------


async def test_get_attachment_is_registered_read_only_with_message_id_and_part_id() -> None:
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    tool = tools["gmail_get_attachment"]
    assert mcp._tool_manager.get_tool("gmail_get_attachment").fn.__module__ == module.__name__
    assert tool.annotations is not None
    assert tool.annotations.readOnlyHint is True
    assert tool.annotations.destructiveHint is False
    assert tool.annotations.openWorldHint is True
    assert list(tool.inputSchema["properties"]) == ["params"]
    model = GetAttachmentInput.model_json_schema()
    assert set(model["properties"]) == {"message_id", "part_id"}
    assert model["additionalProperties"] is False
    description = tool.description or ""
    sections = ["When to Use:", "When NOT to Use:", "Returns:", "Examples:", "Error Handling:"]
    positions = [description.find(section) for section in sections]
    assert all(position > 0 for position in positions) and positions == sorted(positions)


# --- positive ----------------------------------------------------------------------------


async def test_saves_the_attachment_and_returns_path_size_type_and_sha256(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path
) -> None:
    fake = _fake()
    _install(fake, monkeypatch, att_dir)

    result = await gmail_get_attachment(_params())

    path = _saved_path(result)
    assert path.resolve() == (att_dir / MID / "report.pdf").resolve()
    assert path.read_bytes() == PDF
    assert _mode(path) == 0o600
    assert _mode(att_dir) == 0o700
    assert _mode(att_dir / MID) == 0o700
    assert result.startswith("# Attachment saved")
    assert f"- **size**: 1.0 KiB ({len(PDF)} bytes)" in result
    assert "- **mimeType**: application/pdf" in result
    assert f"- **sha256**: `{hashlib.sha256(PDF).hexdigest()}`" in result
    assert f'- **message**: `{MID}`, partId "1"' in result
    assert b64url(PDF)[:40] not in result  # never the bytes
    assert AID not in result  # never the attachmentId
    assert "**name**" not in result  # a safe name, nothing renamed
    assert fake.log == ["token", PROFILE, MESSAGE, _att()]
    assert fake.params(1) == {"format": ["full"]}  # the message is fetched in full
    assert fake.params(2) == {}
    _no_secrets(result)


async def test_downloads_with_the_attachment_id_of_this_fetch(monkeypatch: pytest.MonkeyPatch, att_dir: Path) -> None:
    fresh = "ANGjdJ_FAKE_fresh_from_this_fetch"
    fake = _fake(_pdf_message(part=_pdf_part(attachment_id=fresh)), {fresh: attachment_route(PDF)})
    _install(fake, monkeypatch, att_dir)

    result = await gmail_get_attachment(_params())

    assert _saved_path(result).read_bytes() == PDF
    assert _attachment_requests(fake) == [_att(fresh)]


async def test_every_read_rotates_the_id_and_each_download_uses_its_own_fetch(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path
) -> None:
    reads = [_pdf_message(part=_pdf_part(attachment_id=AID)), _pdf_message(part=_pdf_part(attachment_id=AID_NEXT))]
    fake = _fake(reads, {AID: attachment_route(PDF), AID_NEXT: attachment_route(PDF)})
    _install(fake, monkeypatch, att_dir)

    first = await gmail_get_attachment(_params())
    second = await gmail_get_attachment(_params())

    assert _attachment_requests(fake) == [_att(AID), _att(AID_NEXT)]
    assert _saved_path(first).read_bytes() == _saved_path(second).read_bytes() == PDF


async def test_finds_an_attachment_in_a_nested_multipart(monkeypatch: pytest.MonkeyPatch, att_dir: Path) -> None:
    logo = attachment_part("logo.png", "image/png", 9, attachment_id=AID, part_id="0.1")
    related = multipart("related", text_part("<p>hi</p>", mime="text/html", part_id="0.0"), logo, part_id="0")
    fake = _fake(message(multipart("mixed", related), message_id=MID), {AID: attachment_route(b"PNG-bytes")})
    _install(fake, monkeypatch, att_dir)

    result = await gmail_get_attachment(_params("0.1"))

    path = _saved_path(result)
    assert path.name == "logo.png" and path.read_bytes() == b"PNG-bytes"
    assert "- **mimeType**: image/png" in result


async def test_saves_a_forwarded_message_attachment_as_one_file(monkeypatch: pytest.MonkeyPatch, att_dir: Path) -> None:
    forwarded = attachment_part("fwd.eml", "message/rfc822", 12, attachment_id=AID, part_id="1")
    forwarded["parts"] = [text_part("inner body", part_id="1.0")]
    fake = _fake(message(multipart("mixed", text_part("outer"), forwarded), message_id=MID))
    fake.routes[f"users/me/messages/{MID}/attachments/{AID}"] = attachment_route(b"From: x\r\n\r\nhi")
    _install(fake, monkeypatch, att_dir)

    path = _saved_path(await gmail_get_attachment(_params("1")))

    assert path.name == "fwd.eml" and path.read_bytes() == b"From: x\r\n\r\nhi"


async def test_an_attachment_with_inline_data_is_saved_without_a_download(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path
) -> None:
    notes = text_part("attached notes", part_id="2", filename="notes.txt")
    fake = _fake(message(multipart("mixed", text_part("body", part_id="1"), notes), message_id=MID), attachments={})
    _install(fake, monkeypatch, att_dir)

    result = await gmail_get_attachment(_params("2"))

    assert _saved_path(result).read_bytes() == b"attached notes"
    assert fake.log == ["token", PROFILE, MESSAGE]  # no attachments.get at all


async def test_a_message_that_is_one_attachment_is_saved_by_the_empty_part_id(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path
) -> None:
    root = attachment_part("scan.pdf", "application/pdf", len(PDF), attachment_id=AID, part_id="")
    _install(_fake(message(root, message_id=MID)), monkeypatch, att_dir)

    result = await gmail_get_attachment(_params(""))

    assert _saved_path(result).name == "scan.pdf"
    assert f'- **message**: `{MID}`, partId ""' in result


async def test_never_overwrites_a_file_and_numbers_the_copies(monkeypatch: pytest.MonkeyPatch, att_dir: Path) -> None:
    (att_dir / MID).mkdir(parents=True)
    existing = att_dir / MID / "report.pdf"
    existing.write_bytes(b"keep me")
    _install(_fake(), monkeypatch, att_dir)

    first = await gmail_get_attachment(_params())
    second = await gmail_get_attachment(_params())

    assert existing.read_bytes() == b"keep me"
    assert _saved_path(first).name == "report-1.pdf"
    assert _saved_path(second).name == "report-2.pdf"
    assert _saved_path(second).read_bytes() == PDF
    assert "`report.pdf` already exists there; saved as `report-1.pdf` (nothing overwritten)" in first


async def test_saves_from_a_message_inside_a_label_scope(monkeypatch: pytest.MonkeyPatch, att_dir: Path) -> None:
    fake = _fake(_pdf_message(labels=["INBOX", "Label_1"]))
    _install(fake, monkeypatch, att_dir, GMAIL_SCOPE_LABEL="Projects/Acme")

    result = await gmail_get_attachment(_params())

    assert _saved_path(result).read_bytes() == PDF
    assert fake.log == ["token", PROFILE, LABELS, MESSAGE, _att()]


async def test_saves_from_a_message_inside_a_query_scope(monkeypatch: pytest.MonkeyPatch, att_dir: Path) -> None:
    fake = _fake(**{"users/me/messages": {"messages": [{"id": MID, "threadId": MID}]}})
    _install(fake, monkeypatch, att_dir, GMAIL_SCOPE_QUERY="from:example.com")

    result = await gmail_get_attachment(_params())

    assert _saved_path(result).read_bytes() == PDF
    assert fake.log == ["token", PROFILE, MESSAGE, LIST, _att()]


async def test_an_attachment_exactly_at_the_cap_is_saved(monkeypatch: pytest.MonkeyPatch, att_dir: Path) -> None:
    _install(_fake(), monkeypatch, att_dir, GMAIL_ATTACHMENT_MAX_BYTES=str(len(PDF)))

    assert _saved_path(await gmail_get_attachment(_params())).read_bytes() == PDF


async def test_get_attachment_through_an_mcp_session(monkeypatch: pytest.MonkeyPatch, att_dir: Path) -> None:
    _install(_fake(), monkeypatch, att_dir)

    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool("gmail_get_attachment", {"params": {"message_id": MID, "part_id": "1"}})

    assert result.isError is False
    [content] = result.content
    assert isinstance(content, TextContent)
    assert _saved_path(content.text).read_bytes() == PDF
    _no_secrets(content.text)


@pytest.mark.parametrize(
    "name", ["report.pdf", "Résumé 2026.pdf", "a b.txt", "archive.tar.gz", "README", "x_y-z.v2.csv"]
)
def test_safe_filename_keeps_an_ordinary_name(name: str) -> None:
    assert safe_filename(name) == name


@pytest.mark.parametrize(("value", "expected"), [(0, 0), (1040, 1040), ("1040", 1040), (" 7 ", 7)])
def test_parse_size_accepts_non_negative_integers(value: Any, expected: int) -> None:
    assert parse_size(value) == expected


# --- negative: scope, part ids, sizes ------------------------------------------------------


async def _error(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path, fake: FakeGoogle, part_id: str = "1", **env: str
) -> str:
    _install(fake, monkeypatch, att_dir, **env)
    with pytest.raises(ToolError) as info:
        await gmail_get_attachment(_params(part_id))
    message_text = str(info.value)
    assert "\n" not in message_text and "Traceback" not in message_text
    _no_secrets(message_text)
    return message_text


async def test_a_message_outside_the_label_scope_looks_exactly_like_a_missing_one(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path
) -> None:
    out_of_scope = _fake(_pdf_message(labels=["INBOX", "Label_2"]))
    hidden = await _error(monkeypatch, att_dir, out_of_scope, GMAIL_SCOPE_LABEL="Projects/Acme")
    missing = FakeGoogle()  # no message route: Gmail answers 404
    absent = await _error(monkeypatch, att_dir, missing, GMAIL_SCOPE_LABEL="Projects/Acme")

    assert hidden == absent == f"message {MID} {NOT_FOUND_TAIL}"
    assert _attachment_requests(out_of_scope) == []  # nothing downloaded
    assert "report.pdf" not in hidden and "Quarterly" not in hidden  # no header leaks
    assert _files(att_dir) == []


async def test_a_message_outside_the_query_scope_is_not_found_and_nothing_downloads(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path
) -> None:
    fake = _fake(**{"users/me/messages": {"messages": [{"id": "ffffffffffffffff"}]}})

    text = await _error(monkeypatch, att_dir, fake, GMAIL_SCOPE_QUERY="from:example.com")

    assert text == f"message {MID} {NOT_FOUND_TAIL}"
    assert fake.log == ["token", PROFILE, MESSAGE, LIST]
    assert _files(att_dir) == []


async def test_a_message_in_trash_is_outside_a_label_scope(monkeypatch: pytest.MonkeyPatch, att_dir: Path) -> None:
    fake = _fake(_pdf_message(labels=["Label_1", "TRASH"]))

    text = await _error(monkeypatch, att_dir, fake, GMAIL_SCOPE_LABEL="Projects/Acme")

    assert text == f"message {MID} {NOT_FOUND_TAIL}"
    assert _attachment_requests(fake) == []


@pytest.mark.parametrize("excluded", ["SPAM", "TRASH"])
async def test_a_message_in_spam_or_trash_is_not_found_even_without_a_scope(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path, excluded: str
) -> None:
    fake = _fake(_pdf_message(labels=["INBOX", excluded]))

    text = await _error(monkeypatch, att_dir, fake)

    assert text == f"message {MID} {NOT_FOUND_TAIL}"
    assert _attachment_requests(fake) == []
    assert _files(att_dir) == []


@pytest.mark.parametrize("status", [400, 404])
async def test_a_missing_or_unparseable_message_id_is_not_found(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path, status: int
) -> None:
    fake = FakeGoogle(routes={f"users/me/messages/{MID}": api_error(status, "invalidArgument", "Invalid id value")})

    text = await _error(monkeypatch, att_dir, fake)

    assert text == f"message {MID} {NOT_FOUND_TAIL}"
    assert _attachment_requests(fake) == []


async def test_an_unknown_scope_label_refuses_before_reading_the_message(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path
) -> None:
    fake = _fake()

    text = await _error(monkeypatch, att_dir, fake, GMAIL_SCOPE_LABEL="Projects/Nope")

    assert "GMAIL_SCOPE_LABEL=Projects/Nope matches no label" in text
    assert fake.log == ["token", PROFILE, LABELS]


async def test_a_part_id_the_message_does_not_have_is_not_found(monkeypatch: pytest.MonkeyPatch, att_dir: Path) -> None:
    fake = _fake()

    text = await _error(monkeypatch, att_dir, fake, "7")

    assert text == _part_not_found("7")
    assert fake.log == ["token", PROFILE, MESSAGE]


async def test_a_body_part_is_not_an_attachment(monkeypatch: pytest.MonkeyPatch, att_dir: Path) -> None:
    fake = _fake()

    text = await _error(monkeypatch, att_dir, fake, "0")  # the "See attached" text part

    assert text == _part_not_found("0")
    assert _attachment_requests(fake) == []


async def test_a_text_part_gmail_stored_apart_is_not_an_attachment(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path
) -> None:
    stored_apart = text_part(raw=b"a long body\n" * 50, attachment_id=AID, part_id="0")
    fake = _fake(message(multipart("alternative", stored_apart), message_id=MID))

    text = await _error(monkeypatch, att_dir, fake, "0")

    assert text == _part_not_found("0")
    assert _attachment_requests(fake) == []


async def test_the_inside_of_a_forwarded_message_is_not_a_listed_attachment(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path
) -> None:
    inner = attachment_part("inner.csv", "text/csv", 9, attachment_id=AID_NEXT, part_id="1.1")
    forwarded = attachment_part("fwd.eml", "message/rfc822", 500, attachment_id=AID, part_id="1")
    forwarded["parts"] = [text_part("inner body", part_id="1.0"), inner]
    fake = _fake(message(multipart("mixed", text_part("outer"), forwarded), message_id=MID))

    text = await _error(monkeypatch, att_dir, fake, "1.1")

    assert text == _part_not_found("1.1")
    assert _attachment_requests(fake) == []


async def test_an_attachment_with_neither_an_id_nor_inline_data_is_not_found(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path
) -> None:
    part = _pdf_part()
    part["body"] = {"size": 10}
    fake = _fake(_pdf_message(part=part))

    text = await _error(monkeypatch, att_dir, fake)

    assert text == _part_not_found("1")
    assert _attachment_requests(fake) == []


async def test_an_attachment_gmail_no_longer_has_is_not_found(monkeypatch: pytest.MonkeyPatch, att_dir: Path) -> None:
    fake = _fake(attachments={})  # no route: Gmail answers 404 to the download

    text = await _error(monkeypatch, att_dir, fake)

    assert text == _part_not_found("1")
    assert _files(att_dir) == []


async def test_a_fresh_attachment_id_of_an_unexpected_shape_is_never_requested(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path
) -> None:
    fake = _fake(_pdf_message(part=_pdf_part(attachment_id="short")))

    text = await _error(monkeypatch, att_dir, fake)

    assert "with an attachment id of an unexpected shape: it was not downloaded" in text
    assert _attachment_requests(fake) == []


async def test_over_the_cap_is_refused_before_any_download(monkeypatch: pytest.MonkeyPatch, att_dir: Path) -> None:
    big = 30 * 1024 * 1024
    fake = _fake(_pdf_message(part=_pdf_part(size=big)))

    text = await _error(monkeypatch, att_dir, fake)

    assert f"is 30.0 MiB ({big} bytes), over GMAIL_ATTACHMENT_MAX_BYTES (25.0 MiB): it was not downloaded" in text
    assert "Raise GMAIL_ATTACHMENT_MAX_BYTES" in text
    assert _attachment_requests(fake) == []  # no attachments.get request at all
    assert fake.log == ["token", PROFILE, MESSAGE]
    assert _files(att_dir) == []


async def test_one_byte_over_a_custom_cap_is_refused(monkeypatch: pytest.MonkeyPatch, att_dir: Path) -> None:
    fake = _fake()

    text = await _error(monkeypatch, att_dir, fake, GMAIL_ATTACHMENT_MAX_BYTES=str(len(PDF) - 1))

    assert "it was not downloaded" in text
    assert _attachment_requests(fake) == []


MISSING = object()


@pytest.mark.parametrize("size", [MISSING, None, "abc", "", "12.5", 12.5, -5, "-5", True, [3], {"n": 3}])
async def test_an_unknown_or_invalid_part_size_is_refused_before_any_download(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path, size: Any
) -> None:
    part = _pdf_part()
    if size is MISSING:
        del part["body"]["size"]
    else:
        part["body"]["size"] = size
    fake = _fake(_pdf_message(part=part))

    text = await _error(monkeypatch, att_dir, fake)

    assert text.startswith(f'Gmail reports no usable size for partId "1" of message {MID}: it was not downloaded')
    assert _attachment_requests(fake) == []
    assert _files(att_dir) == []


async def test_an_inline_attachment_of_unknown_size_is_refused_too(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path
) -> None:
    notes = text_part("attached notes", part_id="2", filename="notes.txt")
    notes["body"]["size"] = "unknown"
    fake = _fake(message(multipart("mixed", text_part("body", part_id="1"), notes), message_id=MID), attachments={})

    text = await _error(monkeypatch, att_dir, fake, "2")

    assert text.startswith("Gmail reports no usable size")
    assert _files(att_dir) == []


async def test_bytes_over_the_cap_despite_a_small_declared_size_are_discarded(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path
) -> None:
    fake = _fake(_pdf_message(part=_pdf_part(size=10)))

    text = await _error(monkeypatch, att_dir, fake, GMAIL_ATTACHMENT_MAX_BYTES="100")

    assert "it was discarded, nothing was saved" in text
    assert _files(att_dir) == []


@pytest.mark.parametrize("route", [{"size": 3, "data": "!!!not base64!!!"}, {"size": 3, "data": "QUJD="}, {"size": 3}])
async def test_malformed_attachment_data_is_an_error_and_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path, route: dict[str, Any]
) -> None:
    fake = _fake(_pdf_message(part=_pdf_part(size=3)), {AID: route})

    text = await _error(monkeypatch, att_dir, fake)

    assert text.startswith("Gmail returned")
    assert _files(att_dir) == []


async def test_a_gmail_error_on_the_download_is_one_line_and_writes_nothing(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path
) -> None:
    fake = _fake(attachments={AID: api_error(403, "domainPolicy", "Blocked by policy")})

    text = await _error(monkeypatch, att_dir, fake)

    assert text.startswith("Gmail API error 403 (domainPolicy)")
    assert _files(att_dir) == []


async def test_a_pin_mismatch_reads_no_message(monkeypatch: pytest.MonkeyPatch, att_dir: Path) -> None:
    fake = _fake()
    fake.routes["users/me/profile"] = {"emailAddress": OTHER_ACCOUNT}

    text = await _error(monkeypatch, att_dir, fake)

    assert "every tool is disabled" in text
    assert fake.log == ["token", PROFILE]


@pytest.mark.parametrize("value", [-1, "-1", "1e3", "0x10", "١٢", 3.0])
def test_parse_size_refuses_anything_but_a_non_negative_integer(value: Any) -> None:
    assert parse_size(value) is None


# --- negative: names and the file system ---------------------------------------------------


TRAVERSAL_NAMES = [
    "../x",
    "/etc/passwd",
    "a/b",
    "..",
    "",
    "../../../../tmp/evil.sh",
    "..\\..\\windows\\system32",
    ".bashrc",
    "....//....//x",
    "C:evil.txt",
    "x\x00y\n.pdf",
    "invoice‮fdp.exe",
    " . . ",
]


@pytest.mark.parametrize("name", TRAVERSAL_NAMES)
async def test_a_hostile_file_name_stays_inside_the_message_directory(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path, tmp_path: Path, name: str
) -> None:
    _install(_fake(_pdf_message(part=_pdf_part(filename=name))), monkeypatch, att_dir)

    result = await gmail_get_attachment(_params())

    path = _saved_path(result)
    assert path.parent.resolve() == (att_dir / MID).resolve()
    assert path.read_bytes() == PDF
    saved = path.name
    assert "/" not in saved and "\\" not in saved and ".." not in saved
    assert not saved.startswith(".") and saved.strip() == saved and saved
    assert all(ord(char) >= 32 and char not in "\x7f‮" for char in saved)
    assert [p.resolve() for p in _files(tmp_path) if p.read_bytes() == PDF] == [path.resolve()]


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("../x", "_x"),
        ("/etc/passwd", "_etc_passwd"),
        ("a/b", "a_b"),
        ("a\\b", "a_b"),
        ("C:evil.txt", "C_evil.txt"),
        ("..", "attachment.pdf"),
        ("", "attachment.pdf"),
        ("...", "attachment.pdf"),
        (".hidden", "hidden"),
        ("report..final...pdf", "report.final.pdf"),
        ("x\x00y\n.pdf", "xy.pdf"),
        ("line\r\nbreak.pdf", "linebreak.pdf"),
        ("invoice‮fdp.exe", "invoicefdp.exe"),
        ("  spaced   out .pdf ", "spaced out .pdf"),
        ("trailing dots...", "trailing dots"),
        ("Résumé.pdf", "Résumé.pdf"),
    ],
)
def test_safe_filename_neutralises_hostile_names(name: str, expected: str) -> None:
    assert safe_filename(name, "application/pdf") == expected


# Token shapes assembled at runtime, as in tests/fakes.py (secret scanners flag literals).
_SLASHES = "/" * 2
REDACTABLE_NAMES = [
    ("Bearer Bonds Q3.pdf", "Bearer_Bonds Q3.pdf"),
    ("bearer   memo.pdf", "bearer_memo.pdf"),
    ("ya29" + ".report.pdf", "ya29_report.pdf"),
    ("GOCSPX" + "-notes.txt", "GOCSPX_notes.txt"),
    ("access_token=list.csv", "access_token_list.csv"),
    ("refresh_token = draft.txt", "refresh_token _ draft.txt"),
    ("1" + _SLASHES + "0gFAKEFAKEFAKE.pdf", "1__0gFAKEFAKEFAKE.pdf"),
    ("4" + "/" + "0AeanS0b" + "F" * 20 + ".pdf", "4_0AeanS0b" + "F" * 20 + ".pdf"),
]


@pytest.mark.parametrize(("name", "expected"), REDACTABLE_NAMES)
def test_a_name_the_redaction_would_rewrite_is_broken_before_saving(name: str, expected: str) -> None:
    assert redact(name) != name  # the premise: clip_response would rewrite it
    safe = safe_filename(name, "application/pdf")
    assert safe == expected
    assert redact(safe) == safe


# Not redacted alone (nothing follows the `=`), but rendered at the end of the path the closing
# backtick becomes the key's value: `…/refresh_token=` would be shown as `…/refresh_token=***`.
REDACTABLE_ONLY_AS_RENDERED = [
    ("refresh_token=", "refresh_token_"),
    ("notes access_token=", "notes access_token_"),
    ('id_token"=', 'id_token"_'),
    ("client_secret = ", "client_secret _"),  # the trailing space is stripped, the `=` stays
]


@pytest.mark.parametrize(("name", "expected"), REDACTABLE_ONLY_AS_RENDERED)
def test_a_name_is_checked_as_the_result_renders_it(name: str, expected: str) -> None:
    stripped = name.strip()
    assert redact(stripped) == stripped  # the premise: the bare name survives redaction…
    assert redact(f"/{stripped}`") != f"/{stripped}`"  # …but not at the end of the path
    safe = safe_filename(name, "application/pdf")
    assert safe == expected
    for form in (f"/{safe}`", f"`{safe}`", f"`{safe}` already exists"):
        assert redact(form) == form


@pytest.mark.parametrize(("name", "expected"), REDACTABLE_NAMES[:4] + REDACTABLE_ONLY_AS_RENDERED)
async def test_the_path_the_result_shows_is_the_file_on_disk(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path, name: str, expected: str
) -> None:
    _install(_fake(_pdf_message(part=_pdf_part(filename=name))), monkeypatch, att_dir)

    result = await gmail_get_attachment(_params())

    path = _saved_path(result)
    assert path.name == expected
    assert path.read_bytes() == PDF  # the shown path exists: nothing in it was redacted
    assert f"saved as `{expected}`" in result


def test_a_known_secret_in_a_name_falls_back_to_a_neutral_name() -> None:
    literal = "Zq9-known-secret-value-77"
    register_secret(literal)

    safe = safe_filename(f"{literal}.pdf", "application/pdf")

    assert safe == "attachment.pdf"
    assert redact(safe) == safe


def test_a_numbered_copy_never_becomes_a_redactable_name() -> None:
    assert redact("GOCSPX") == "GOCSPX"  # a fine name on its own…
    copy = numbered("GOCSPX", 1)  # …but "GOCSPX-1" is a client-secret shape
    assert copy == "GOCSPX_1"
    assert redact(copy) == copy
    assert numbered("report.pdf", 3) == "report-3.pdf"


async def test_a_numbered_copy_shown_in_the_result_exists_on_disk(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path
) -> None:
    (att_dir / MID).mkdir(parents=True)
    (att_dir / MID / "GOCSPX").write_bytes(b"keep me")
    _install(_fake(_pdf_message(part=_pdf_part(filename="GOCSPX"))), monkeypatch, att_dir)

    path = _saved_path(await gmail_get_attachment(_params()))

    assert path.name == "GOCSPX_1" and path.read_bytes() == PDF
    assert (att_dir / MID / "GOCSPX").read_bytes() == b"keep me"


def test_a_long_name_is_cut_under_the_limit_keeping_its_extension() -> None:
    name = "é" * 300 + ".pdf"

    safe = safe_filename(name)

    assert len(safe.encode()) <= MAX_NAME_BYTES
    assert safe.endswith(".pdf") and safe.startswith("é")


def test_a_long_name_without_a_usable_extension_is_cut_too() -> None:
    safe = safe_filename("x" * 250 + "." + "y" * 40)

    assert len(safe.encode()) <= MAX_NAME_BYTES and safe.startswith("x")


async def test_a_symlinked_message_directory_is_refused(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path, tmp_path: Path
) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    att_dir.mkdir()
    (att_dir / MID).symlink_to(elsewhere, target_is_directory=True)

    text = await _error(monkeypatch, att_dir, _fake())

    assert "is not a plain directory: refusing to save the attachment there" in text
    assert list(elsewhere.iterdir()) == []


async def test_an_attachment_dir_that_is_a_file_is_refused(monkeypatch: pytest.MonkeyPatch, att_dir: Path) -> None:
    att_dir.write_text("not a directory")

    text = await _error(monkeypatch, att_dir, _fake())

    assert "is not a plain directory" in text
    assert att_dir.read_text() == "not a directory"


async def test_a_failed_write_leaves_no_partial_file(monkeypatch: pytest.MonkeyPatch, att_dir: Path) -> None:
    def broken_write(fd: int, data: bytes) -> None:
        import os

        os.write(fd, data[:10])
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(module, "_write_all", broken_write)

    text = await _error(monkeypatch, att_dir, _fake())

    assert text.startswith("could not save the attachment under GMAIL_ATTACHMENT_DIR")
    assert "No space left on device" in text
    assert _files(att_dir) == []


# --- negative: arguments ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "fields",
    [
        {"message_id": "../../etc", "part_id": "1"},
        {"message_id": f"{MID}/attachments", "part_id": "1"},
        {"message_id": MID, "part_id": "../1"},
        {"message_id": MID, "part_id": "1/2"},
        {"message_id": MID, "part_id": "a"},
        {"message_id": MID, "part_id": "1..2"},
        {"message_id": MID, "part_id": ".1"},
        {"message_id": MID, "part_id": "1."},
        {"message_id": MID, "part_id": "-1"},
        {"message_id": MID, "part_id": "١"},
        {"message_id": MID},
        {"message_id": MID, "part_id": "1", "attachment_id": AID},  # the caller cannot name the bytes
    ],
)
def test_the_params_model_refuses_bad_ids_and_extra_fields(fields: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        GetAttachmentInput(**fields)


async def test_bad_arguments_through_an_mcp_session_send_nothing(
    monkeypatch: pytest.MonkeyPatch, att_dir: Path
) -> None:
    fake = _fake()
    _install(fake, monkeypatch, att_dir)

    async with create_connected_server_and_client_session(mcp) as session:
        result = await session.call_tool(
            "gmail_get_attachment", {"params": {"message_id": "../../etc/passwd", "part_id": "1"}}
        )

    assert result.isError is True
    [content] = result.content
    assert isinstance(content, TextContent)
    assert "message_id" in content.text and "../../etc/passwd" not in content.text
    assert fake.log == []
    assert _files(att_dir) == []
