"""Attachment tool — `gmail_get_attachment`, addressed by `partId` (ADR-0002).

Gmail returns a NEW `attachmentId` on every `messages.get` for the same attachment (and the
old ones keep working: Stack Overflow #28104157, Material Security 2023), and
`attachments.get` was reported not to bind an id to its message. So the tool never takes an
attachment id from the caller. It takes the MIME part's `partId`, which is stable across
reads, and works in the order the safety rails need:

1. **Fetch the message** with `scope.fetch_message()` (`format=full`), the spine's one
   fetch-by-id helper: the pin, the GET, the returned id compared, `scope.check_message()`.
   A message outside the project scope gets the same `NotFoundInScopeError` a missing id
   gets (ADR D5), and nothing else is requested.
2. **Find the part by `partId`** among the parts `formatters.list_attachments` lists — the
   ones gmail_get_message and gmail_get_thread show. A partId that is not an attachment (a
   body part, a text part Gmail stored apart, the inside of a forwarded `.eml`) or an
   attachment with neither an attachmentId nor inline data is "not found", same text.
3. **Refuse BEFORE downloading** (ADR D6, ADR-0002 §4): the fresh part's `body.size` must be a
   non-negative integer no larger than GMAIL_ATTACHMENT_MAX_BYTES. An unknown or invalid size
   is refused too (fail closed), never downloaded.
4. **Download with the attachmentId from THAT fetch** (or decode the part's inline data), so
   the bytes always come from the message that passed the scope check. Decode the base64url
   strictly, check the cap again on the real bytes, and **save** to
   `GMAIL_ATTACHMENT_DIR/<message_id>/<safe name>`: directories 0700, the file 0600, created
   with `O_CREAT | O_EXCL` so nothing is ever overwritten (a numbered suffix instead). The
   tool returns the path, size, mimeType and sha256 — never the bytes, never an attachmentId.

The filename Gmail reports is untrusted (it comes from the sender): `safe_filename` drops
control and format characters, path separators, `..` runs and leading dots, caps the length,
breaks any span the response redaction would rewrite (so the name the result shows is the
name on disk), and falls back to `attachment.<ext>` when nothing usable is left.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import contextlib
import hashlib
import mimetypes
import os
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp.types import ToolAnnotations
from pydantic import BaseModel, ConfigDict, Field, field_validator

from gmail_mcp import validators
from gmail_mcp.client import GmailClient, get_client
from gmail_mcp.config import get_settings
from gmail_mcp.errors import GmailApiError, GmailError, NotFoundInScopeError, redact, tool_error
from gmail_mcp.formatters import clip_response, fmt_size, is_attachment, iter_parts, one_line
from gmail_mcp.scope import get_scope, means_not_found
from gmail_mcp.server import mcp

DIR_MODE = 0o700
FILE_MODE = 0o600
FALLBACK_STEM = "attachment"
NEUTRAL_MIME = "application/octet-stream"
# Room under the usual 255-byte name limit for a `-999` suffix.
MAX_NAME_BYTES = 200
MAX_EXTENSION_CHARS = 16
MAX_SUFFIX = 999
# `/` and `\` separate paths; `:` is how Finder shows a `/` on macOS.
_SEPARATORS = re.compile(r"[/\\:]")
_DOT_RUNS = re.compile(r"\.{2,}")
# A MIME partId: `0`, `1`, `0.1`, `1.2.3`; the empty string is the message root (a message
# that is one attachment). ASCII digits only, written out (`\d` accepts any Unicode digit).
_PART_ID_RE = re.compile(r"(?:[0-9]{1,6}(?:\.[0-9]{1,6}){0,31})?")
_SIZE_RE = re.compile(r"[0-9]{1,15}")
# The spans `errors.redact()` rewrites, each broken by one same-length substitution. A `/`
# never reaches this step, so the `1//…` and `4/0…` shapes cannot occur in a name.
_REDACTABLE_SPANS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\b(bearer)\s"), r"\1_"),  # "Bearer Bonds.pdf" → "Bearer_Bonds.pdf"
    (re.compile(r"(ya29)\."), r"\1_"),  # "ya29.report.pdf" → "ya29_report.pdf"
    (re.compile(r"(GOCSPX)-"), r"\1_"),  # "GOCSPX-notes.txt" → "GOCSPX_notes.txt"
    (re.compile(r"(?i)\b(refresh_token|access_token|id_token|client_secret)\b(['\"]?\s*)[:=]"), r"\1\2_"),
)


class AttachmentTooLargeError(GmailError):
    """ADR D6: the attachment is over GMAIL_ATTACHMENT_MAX_BYTES; it was not downloaded."""


class AttachmentSizeError(GmailError):
    """ADR-0002 §4: Gmail reports no usable size for the part; refused without downloading."""


class AttachmentSaveError(GmailError):
    """The attachment could not be decoded or written to GMAIL_ATTACHMENT_DIR."""


def part_id(value: object, *, field: str = "part_id") -> str:
    """Validate a MIME partId (`1`, `0.1`; `""` = the message root), as the listings show it."""
    text = str(value).strip()
    if not _PART_ID_RE.fullmatch(text):
        raise ValueError(
            f"{field} must be the partId gmail_get_message / gmail_get_thread list for the attachment, e.g. 1 or 0.1"
        )
    return text


class GetAttachmentInput(BaseModel):
    """The message that holds the attachment and the attachment's partId."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    message_id: str = Field(
        description=(
            "The Gmail message id that holds the attachment (the `id` gmail_search_messages, gmail_get_message and "
            "gmail_get_thread show), e.g. 18c2f0e9a1b2c3d4."
        ),
    )
    part_id: str = Field(
        description=(
            "The attachment's partId, as gmail_get_message / gmail_get_thread list it (e.g. 1, or 0.1). It is stable "
            'across reads. "" (empty) is the whole message, when the message itself is one attachment.'
        ),
    )

    @field_validator("message_id", mode="before")
    @classmethod
    def _check_message_id(cls, value: object) -> str:
        return validators.message_id(value)

    @field_validator("part_id", mode="before")
    @classmethod
    def _check_part_id(cls, value: object) -> str:
        return part_id(value)


# --- the part -----------------------------------------------------------------------------


@dataclass(frozen=True)
class AttachmentPart:
    """The listed attachment the caller named, as THIS fetch of the message describes it."""

    part_id: str
    filename: str
    mime_type: str
    size: int | None  # None = Gmail reported no usable size
    attachment_id: str | None  # from this fetch; None when the data is inline
    inline_data: str | None


def parse_size(value: Any) -> int | None:
    """A part's `body.size` as a non-negative int, or None (absent, non-numeric, negative, bool, fractional)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if isinstance(value, str) and _SIZE_RE.fullmatch(value.strip()):
        return int(value.strip())
    return None


def find_attachment(payload: Any, wanted: str) -> AttachmentPart | None:
    """The part `list_attachments` would list with partId `wanted`, or None."""
    if not isinstance(payload, Mapping):
        return None
    for node in iter_parts(payload):
        node_part_id = node.get("partId")
        if not isinstance(node_part_id, str) or node_part_id != wanted or not is_attachment(node):
            continue
        body = node.get("body")
        body = body if isinstance(body, Mapping) else {}
        attachment_id = body.get("attachmentId")
        data = body.get("data")
        return AttachmentPart(
            part_id=node_part_id,
            filename=str(node.get("filename") or ""),
            mime_type=str(node.get("mimeType") or "").strip().lower() or NEUTRAL_MIME,
            size=parse_size(body.get("size")),
            attachment_id=attachment_id if isinstance(attachment_id, str) and attachment_id else None,
            inline_data=data if isinstance(data, str) and data else None,
        )
    return None


# --- file names -------------------------------------------------------------------------


def printable(text: str) -> str:
    """`text` NFC-normalised, without control / format characters, on one line (safe to echo back)."""
    text = unicodedata.normalize("NFC", text)
    return one_line("".join(char for char in text if not unicodedata.category(char).startswith("C")))


def _fallback_name(mime_type: str) -> str:
    extension = mimetypes.guess_extension(mime_type.split(";", 1)[0].strip(), strict=True) or ""
    return FALLBACK_STEM + extension


def _fit(name: str) -> str:
    """`name` cut to `MAX_NAME_BYTES` of UTF-8, keeping a short extension."""
    if len(name.encode()) <= MAX_NAME_BYTES:
        return name
    stem, dot, extension = name.rpartition(".")
    if not dot or not stem or len(extension) > MAX_EXTENSION_CHARS:
        stem, extension = name, ""
    tail = f".{extension}" if extension else ""
    while stem and len((stem + tail).encode()) > MAX_NAME_BYTES:
        stem = stem[:-1]
    return (stem.rstrip(" .") + tail) if stem.rstrip(" .") else ""


def _rendered_forms(name: str) -> tuple[str, str]:
    """How the result shows a saved name: at the end of the path, and between backticks."""
    return f"/{name}`", f"`{name}`"


def _survives_redaction(name: str) -> bool:
    return all(redact(form) == form for form in _rendered_forms(name))


def unredactable(name: str) -> str:
    """`name` with every span `errors.redact()` would rewrite broken, or "" when that is not enough.

    Every result passes through `clip_response`, which redacts token-shaped text. A file
    named `Bearer Bonds Q3.pdf` would be saved under that name and shown as `Bearer ***`, so
    the path in the result would not exist. Redaction depends on context, so the check runs
    on the name AS RENDERED (`…/<name>`` in the path, `` `<name>` `` in a note): a name that
    ends in `refresh_token=` is not redacted alone, but in the path the closing backtick
    becomes the key's value. The substitutions are same-length (`_` for one separator
    character); a name that still changes under `redact()` (a known secret's literal value)
    gives "", and the caller falls back to `attachment.<ext>`.
    """
    if _survives_redaction(name):
        return name
    for pattern, replacement in _REDACTABLE_SPANS:
        name = pattern.sub(replacement, name)
    return name if _survives_redaction(name) else ""


def safe_filename(name: str, mime_type: str = NEUTRAL_MIME) -> str:
    """A file name that cannot leave its directory, hide, carry control characters, or be redacted.

    NFC-normalised; control and format characters (category C*, e.g. NUL, newline, the
    right-to-left override that disguises an extension) dropped; `/`, `\\` and `:` turned
    into `_`; whitespace collapsed; dot runs collapsed to one dot (no `..` survives);
    leading and trailing dots and spaces stripped; cut to `MAX_NAME_BYTES`; spans the
    response redaction would rewrite broken (`unredactable`). Nothing left → `attachment`
    plus the mime type's extension.
    """
    text = unicodedata.normalize("NFC", name)
    text = "".join(char for char in text if not unicodedata.category(char).startswith("C"))
    text = _SEPARATORS.sub("_", text)
    text = one_line(text)
    text = _DOT_RUNS.sub(".", text)
    text = unredactable(_fit(text.strip(" .")))
    return text or _fallback_name(mime_type)


def numbered(name: str, n: int) -> str:
    """`report.pdf` → `report-<n>.pdf`; `README` → `README-<n>` (redaction-proof, like the name)."""
    stem, dot, extension = name.rpartition(".")
    candidate = f"{name}-{n}" if not dot or not stem else f"{stem}-{n}.{extension}"
    # `GOCSPX` is a fine name; `GOCSPX-1` is a client-secret shape.
    return unredactable(candidate) or f"{FALLBACK_STEM}-{n}"


# --- saving -----------------------------------------------------------------------------


@dataclass(frozen=True)
class SavedFile:
    path: Path
    name: str
    wanted_name: str
    size: int
    sha256: str


def _ensure_dir(path: Path, *, parents: bool, allow_symlink: bool) -> None:
    """Create `path` 0700 if missing (an existing directory keeps its mode)."""
    try:
        path.mkdir(mode=DIR_MODE, parents=parents)
        os.chmod(path, DIR_MODE)  # mkdir's mode goes through the umask
    except FileExistsError:
        pass
    if (path.is_symlink() and not allow_symlink) or not path.is_dir():
        raise AttachmentSaveError(f"{path} exists and is not a plain directory: refusing to save the attachment there")


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _create_exclusive(directory: Path, wanted: str, data: bytes) -> tuple[Path, str]:
    """Write `data` to a NEW file (0600) named `wanted`, or `wanted-1`, `-2`… — never overwriting."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    for n in range(MAX_SUFFIX + 1):
        name = wanted if n == 0 else numbered(wanted, n)
        path = directory / name
        try:
            fd = os.open(path, flags, FILE_MODE)
        except FileExistsError:
            continue
        done = False
        try:
            os.fchmod(fd, FILE_MODE)
            _write_all(fd, data)
            done = True
        finally:
            os.close(fd)
            if not done:
                with contextlib.suppress(OSError):
                    os.unlink(path)
        return path, name
    raise AttachmentSaveError(
        f"{directory} already holds {wanted} and its numbered copies up to -{MAX_SUFFIX}: move some of them away"
    )


def save_attachment(base: Path, message_id: str, part: AttachmentPart, data: bytes) -> SavedFile:
    """Save `data` under `<base>/<message_id>/` with a safe, never-overwriting name.

    The base directory may be a symlink (the operator's choice); the per-message directory
    may not (nothing else should have made one there). An OS failure becomes one line
    naming GMAIL_ATTACHMENT_DIR.
    """
    base = base.expanduser().absolute()
    try:
        _ensure_dir(base, parents=True, allow_symlink=True)
        directory = base / validators.message_id(message_id)
        _ensure_dir(directory, parents=False, allow_symlink=False)
        wanted = safe_filename(part.filename, part.mime_type)
        path, name = _create_exclusive(directory, wanted, data)
    except OSError as exc:
        raise AttachmentSaveError(
            f"could not save the attachment under GMAIL_ATTACHMENT_DIR ({base}): {exc.strerror or type(exc).__name__}. "
            "Check that the directory is writable, or point GMAIL_ATTACHMENT_DIR elsewhere"
        ) from None
    return SavedFile(path=path, name=name, wanted_name=wanted, size=len(data), sha256=hashlib.sha256(data).hexdigest())


def decode_attachment_data(data: Any) -> bytes:
    """Gmail's base64url `data` as bytes; anything malformed is an error, never an empty file."""
    if not isinstance(data, str):
        raise AttachmentSaveError("Gmail returned no data for this attachment: try again")
    text = data.strip()
    text += "=" * (-len(text) % 4)
    try:
        return base64.b64decode(text, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        raise AttachmentSaveError("Gmail returned attachment data that is not valid base64url: try again") from None


# --- Gmail requests -----------------------------------------------------------------------


def _part_label(params: GetAttachmentInput) -> str:
    return f'partId "{params.part_id}" of message {params.message_id}'


def _not_found(params: GetAttachmentInput) -> NotFoundInScopeError:
    return NotFoundInScopeError("attachment", _part_label(params))


def _check_size(params: GetAttachmentInput, part: AttachmentPart, cap: int) -> int:
    """ADR D6 + ADR-0002 §4: the fresh part's size, refused when unknown or over the cap."""
    if part.size is None:
        raise AttachmentSizeError(
            f"Gmail reports no usable size for {_part_label(params)}: it was not downloaded (an attachment of unknown "
            "size could be over GMAIL_ATTACHMENT_MAX_BYTES). Open it in Gmail"
        )
    if part.size > cap:
        raise _too_large(params, part.size, cap)
    return part.size


def _too_large(params: GetAttachmentInput, size: int, cap: int, *, downloaded: bool = False) -> AttachmentTooLargeError:
    state = "it was discarded, nothing was saved" if downloaded else "it was not downloaded"
    return AttachmentTooLargeError(
        f"attachment {_part_label(params)} is {fmt_size(size)} ({size} bytes), over GMAIL_ATTACHMENT_MAX_BYTES "
        f"({fmt_size(cap)}): {state}. Raise GMAIL_ATTACHMENT_MAX_BYTES (up to 1073741824) for this entry, or open it "
        "in Gmail"
    )


async def _download(client: GmailClient, params: GetAttachmentInput, part: AttachmentPart) -> bytes:
    """The part's bytes: `attachments.get` with THIS fetch's attachmentId, or the inline data."""
    if part.attachment_id is None:
        return decode_attachment_data(part.inline_data)
    try:
        fresh_id = validators.attachment_id(part.attachment_id)
    except ValueError:
        raise AttachmentSaveError(
            f"Gmail listed {_part_label(params)} with an attachment id of an unexpected shape: it was not downloaded"
        ) from None
    try:
        body = await client.get(f"users/me/messages/{params.message_id}/attachments/{fresh_id}")
    except GmailApiError as exc:
        if means_not_found(exc):  # the same rule as every fetch by id: a 404, or an unparsable id
            raise _not_found(params) from None
        raise
    return decode_attachment_data(body.get("data"))


def _render(params: GetAttachmentInput, part: AttachmentPart, saved: SavedFile) -> str:
    lines = [
        "# Attachment saved",
        "",
        f"- **path**: `{saved.path}`",
        f"- **size**: {fmt_size(saved.size)} ({saved.size} bytes)",
        f"- **mimeType**: {part.mime_type}",
        f"- **sha256**: `{saved.sha256}`",
        f'- **message**: `{params.message_id}`, partId "{params.part_id}"',
    ]
    original = printable(part.filename)
    if part.filename and original != saved.wanted_name:
        lines.append(
            f"- **name**: the name Gmail reports (`{original}`) is not safe as a file name; saved as `{saved.name}`"
        )
    if saved.name != saved.wanted_name:
        lines.append(
            f"- **name**: `{saved.wanted_name}` already exists there; saved as `{saved.name}` (nothing overwritten)"
        )
    lines += ["", "The content is on disk only: open the file with a local tool to read it."]
    return "\n".join(lines)


@mcp.tool(
    name="gmail_get_attachment",
    annotations=ToolAnnotations(
        title="Save Gmail Attachment",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=False,
        openWorldHint=True,
    ),
)
async def gmail_get_attachment(params: GetAttachmentInput) -> str:
    """Save one attachment of a message to a local file and return its path, size, type and sha256.

    Takes the message id and the attachment's partId (as gmail_get_message and
    gmail_get_thread list it). Fetches the message, checks it against the project scope,
    finds that attachment, and refuses before downloading when its size is unknown or over
    GMAIL_ATTACHMENT_MAX_BYTES (25 MiB by default). Otherwise it downloads the bytes from
    that same message and saves them under GMAIL_ATTACHMENT_DIR/<message_id>/ with a safe
    file name (directories 0700, file 0600), never overwriting an existing file: a second
    copy gets a numbered suffix. The bytes never come back in the result — only where they
    are and how to recognise them. Reading mail is all it does: nothing in the mailbox
    changes.

    When to Use:
    - To get a file someone sent (a PDF, a spreadsheet, an image) onto disk, then read or
      process it with a local tool.
    - To fingerprint an attachment (sha256) without loading it into the conversation.

    When NOT to Use:
    - To list a message's attachments (use gmail_get_message or gmail_get_thread: they show
      each one's name, type, size and partId).
    - To read a message's text (use gmail_get_message; long bodies are paged there).

    Returns:
    A markdown block: the absolute path, the size (human and bytes), the mimeType, the
    sha256, the message id and partId, and a note when the name had to be made safe or a
    numbered copy was written.

    Examples:
    - params = {"message_id": "18c2f0e9a1b2c3d4", "part_id": "1"}
    - params = {"message_id": "18c2f0e9a1b2c3d4", "part_id": "0.1"}  (an attachment inside a nested part)

    Error Handling:
    A message that does not exist or is outside the project scope, and a partId that is not
    one of the message's listed attachments, all answer "… was not found in this mailbox
    scope". An attachment over GMAIL_ATTACHMENT_MAX_BYTES, or of unknown size, is refused
    without downloading. A directory that cannot be written, auth, pin and quota errors come
    back as one line naming the cause and the fix.
    """
    try:
        settings = get_settings()
        client = get_client()
        # Pin, scope (an unknown GMAIL_SCOPE_LABEL refuses before any message is read), GET,
        # id compare and scope check: the bytes can only come from a message that passed it.
        message = await get_scope().fetch_message(params.message_id, {"format": "full"})
        part = find_attachment(message.get("payload"), params.part_id)
        if part is None or (part.attachment_id is None and part.inline_data is None):
            raise _not_found(params)
        cap = settings.attachment_max_bytes
        _check_size(params, part, cap)
        data = await _download(client, params, part)
        if len(data) > cap:
            raise _too_large(params, len(data), cap, downloaded=True)
        saved = await asyncio.to_thread(save_attachment, settings.attachment_path, params.message_id, part, data)
        return clip_response(_render(params, part, saved))
    except Exception as exc:
        raise tool_error(exc) from None
