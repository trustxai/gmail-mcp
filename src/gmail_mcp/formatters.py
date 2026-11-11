"""Bounded rendering of Gmail messages for the model (ADR-0001 D6).

- **Body.** The MIME tree is walked depth-first (nested multiparts included, attachments
  skipped). Inline `text/plain` parts win; without one, `text/html` parts are turned into
  text. Bytes are decoded with the declared charset, then UTF-8, then cp1252, the last with
  errors replaced — so a mislabelled or legacy body still reads instead of failing.
- **Cap and offset.** A body is paged by characters: `page_text` redacts the WHOLE text
  first, then cuts at `GMAIL_BODY_MAX_CHARS` and says which `offset` brings the next part.
  Offsets therefore count characters of the redacted text, and a credential that straddles
  a page boundary is redacted whole instead of leaking its tail on the next page. Anything
  else cut to a length (`shorten`) is redacted before the cut too.
- **Headers.** Only From, To, Cc, Date, Subject and Message-ID, each on one line.
- **Attachments.** Listed (filename, mimeType, size, partId), never inlined. The attachmentId
  is never shown: Gmail issues a new one on every read (ADR-0002), so `gmail_get_attachment`
  takes the stable partId.

Everything a tool returns goes through `clip_response`, which redacts token-shaped strings
(a mail body can carry a pasted credential) and caps the response size.

**Bounded output.** `clip_response` must never cut a paging note or a `page_token`: the model
would page past text it never saw. So every field a tool renders is bounded — each header
value (`MAX_HEADER_CHARS`), a label list, the attachment list (`MAX_LISTED_ATTACHMENTS`, each
name and type capped), ids, and the fields of a search hit (`MAX_SUMMARY_CHARS`) — and
GMAIL_BODY_MAX_CHARS is capped (config's `MAX_BODY_MAX_CHARS`) so that a full page of 4-byte
UTF-8 plus everything else of a single-message response stays under `MAX_RESPONSE_BYTES`.
Tests render every field at its cap to prove it. As a second rail, `fit_page` shrinks a body
window (and its note with it) until the response fits; a multi-message thread page stops
adding messages at a byte budget instead.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from email.header import decode_header, make_header
from html.parser import HTMLParser
from typing import Any

from gmail_mcp.errors import redact

# Context-window guard: MCP responses cap at 1 MB; stay well under it.
MAX_RESPONSE_BYTES = 900_000

# Per-field bounds (characters after redaction; a UTF-8 character is at most 4 bytes). With
# them, a single-message response without its body is at most ~200 KB, which leaves room for
# a full page of 4-byte text at config's MAX_BODY_MAX_CHARS.
MAX_HEADER_CHARS = 2_000  # one header value (From, To, Cc, Date, Subject, Message-ID)
MAX_LABEL_LIST_CHARS = 500  # a message's label ids, joined
MAX_LISTED_ATTACHMENTS = 100
MAX_FILENAME_CHARS = 200
MAX_MIME_CHARS = 100
MAX_ID_CHARS = 64  # a Gmail id Gmail sent (threadId, partId) shown without being validated
MAX_SUMMARY_CHARS = 300  # a subject, sender, date or error in a search hit
MAX_SNIPPET_CHARS = 200

HEADER_SUBSET: tuple[str, ...] = ("From", "To", "Cc", "Date", "Subject", "Message-ID")
# Headers that may legitimately repeat; their values are joined.
_JOINED_HEADERS = frozenset({"to", "cc"})

# Labels a legacy body often declares while its bytes are windows-1252 (the WHATWG
# encoding standard maps them all to windows-1252).
_CP1252_LABELS = frozenset({"iso-8859-1", "iso8859-1", "latin-1", "latin1", "l1", "us-ascii", "ascii", "cp819"})
_CHARSET_RE = re.compile(r"""charset\s*=\s*["']?([^"';\s]+)""", re.IGNORECASE)


@dataclass(frozen=True)
class Attachment:
    """One attachment; the model sees `part_id` (what `gmail_get_attachment` takes), never `attachment_id`."""

    filename: str
    mime_type: str
    size: int
    attachment_id: str | None
    part_id: str | None


@dataclass(frozen=True)
class Body:
    """The text body: `source` is `text/plain`, `text/html` or `none`."""

    text: str
    source: str
    # attachmentIds of text parts Gmail stored outside the message (no inline data).
    external_parts: tuple[str, ...] = ()


@dataclass(frozen=True)
class TextPage:
    """A window of a REDACTED text: `[offset, end)` of `total` characters; `next_offset` is None at the end."""

    text: str
    offset: int
    end: int
    total: int
    next_offset: int | None


# --- MIME walk ------------------------------------------------------------------------


def _headers(part: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    headers = part.get("headers")
    return [header for header in headers if isinstance(header, Mapping)] if isinstance(headers, list) else []


def header_values(part: Mapping[str, Any], name: str) -> list[str]:
    """Every value of header `name` (case-insensitive) on a payload or part, in order."""
    wanted = name.lower()
    return [str(header.get("value", "")) for header in _headers(part) if str(header.get("name", "")).lower() == wanted]


def _children(part: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    parts = part.get("parts")
    return [child for child in parts if isinstance(child, Mapping)] if isinstance(parts, list) else []


def _body(part: Mapping[str, Any]) -> Mapping[str, Any]:
    body = part.get("body")
    return body if isinstance(body, Mapping) else {}


def is_attachment(part: Mapping[str, Any]) -> bool:
    """A part with a filename, an `attachment` disposition, or external non-text data."""
    if str(part.get("filename") or "").strip():
        return True
    if any(value.strip().lower().startswith("attachment") for value in header_values(part, "Content-Disposition")):
        return True
    mime = str(part.get("mimeType") or "").lower()
    return bool(_body(part).get("attachmentId")) and not mime.startswith("text/") and not mime.startswith("multipart/")


def iter_parts(payload: Mapping[str, Any]) -> Iterator[Mapping[str, Any]]:
    """Every leaf part, depth-first; attachments are yielded but never descended into."""
    children = _children(payload)
    if not children or is_attachment(payload):
        yield payload
        return
    for child in children:
        yield from iter_parts(child)


def decode_body_data(data: str) -> bytes:
    """Gmail's base64url `body.data` (padding optional) as bytes."""
    text = data.strip()
    text += "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text)
    except (binascii.Error, ValueError):
        return b""


def part_charset(part: Mapping[str, Any]) -> str | None:
    """The `charset` parameter of a part's Content-Type header, if any."""
    for value in header_values(part, "Content-Type"):
        match = _CHARSET_RE.search(value)
        if match:
            return match.group(1).strip().lower()
    return None


def _codec(name: str) -> str | None:
    try:
        return codecs.lookup(name).name
    except LookupError:
        return None


def decode_text(raw: bytes, charset: str | None) -> str:
    """Decode with the declared charset, then UTF-8, then cp1252 (errors replaced at the end)."""
    candidates: list[str] = []
    declared = (charset or "").strip().lower()
    if declared in _CP1252_LABELS:
        # ASCII is a subset of UTF-8, and UTF-8 mislabelled as latin-1 is common: try it first.
        candidates.extend(["utf-8", "cp1252"])
    elif declared:
        codec = _codec(declared)
        if codec is not None:
            candidates.append(codec)
    candidates.extend(["utf-8", "cp1252"])
    tried: set[str] = set()
    for name in candidates:
        if name in tried:
            continue
        tried.add(name)
        try:
            return raw.decode(name)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("cp1252", errors="replace")


def _part_text(part: Mapping[str, Any]) -> str | None:
    data = _body(part).get("data")
    if not isinstance(data, str) or not data:
        return None
    return decode_text(decode_body_data(data), part_charset(part))


def extract_body(payload: Mapping[str, Any]) -> Body:
    """The message's text: inline text/plain parts, else text/html parts turned into text."""
    plain: list[str] = []
    html: list[str] = []
    external: list[str] = []
    for part in iter_parts(payload):
        if is_attachment(part):
            continue
        mime = str(part.get("mimeType") or "").lower()
        if mime not in {"text/plain", "text/html"}:
            continue
        text = _part_text(part)
        if text is None:
            attachment_id = _body(part).get("attachmentId")
            if isinstance(attachment_id, str) and attachment_id:
                external.append(attachment_id)
            continue
        (plain if mime == "text/plain" else html).append(text)
    if plain:
        return Body(_normalise_newlines("\n\n".join(plain)).strip(), "text/plain", tuple(external))
    if html:
        return Body("\n\n".join(html_to_text(text) for text in html).strip(), "text/html", tuple(external))
    return Body("", "none", tuple(external))


def list_attachments(payload: Mapping[str, Any]) -> list[Attachment]:
    """Every attachment part, in MIME order."""
    out: list[Attachment] = []
    for part in iter_parts(payload):
        if not is_attachment(part):
            continue
        body = _body(part)
        try:
            size = int(body.get("size") or 0)
        except (TypeError, ValueError):
            size = 0
        attachment_id = body.get("attachmentId")
        out.append(
            Attachment(
                filename=one_line(str(part.get("filename") or "")) or "(no name)",
                mime_type=str(part.get("mimeType") or "application/octet-stream"),
                size=size,
                attachment_id=str(attachment_id) if attachment_id else None,
                part_id=str(part.get("partId")) if part.get("partId") is not None else None,
            )
        )
    return out


# --- headers ---------------------------------------------------------------------------


def one_line(text: str) -> str:
    """Collapse whitespace (folded headers, newlines) to single spaces."""
    return " ".join(text.split())


def decode_header_value(value: str) -> str:
    """Decode RFC 2047 encoded-words (`=?utf-8?b?…?=`) when present; always one line."""
    if "=?" in value:
        try:
            value = str(make_header(decode_header(value)))
        except (ValueError, LookupError, UnicodeDecodeError, binascii.Error):
            pass
    return one_line(value)


def headers_subset(payload: Mapping[str, Any]) -> dict[str, str]:
    """From, To, Cc, Date, Subject and Message-ID (those present), in that order, each at most `MAX_HEADER_CHARS`."""
    out: dict[str, str] = {}
    for name in HEADER_SUBSET:
        values = [decode_header_value(value) for value in header_values(payload, name)]
        values = [value for value in values if value]
        if not values:
            continue
        out[name] = shorten(", ".join(values) if name.lower() in _JOINED_HEADERS else values[0], MAX_HEADER_CHARS)
    return out


def labels_line(value: Any) -> str:
    """A message's label ids on one line, at most `MAX_LABEL_LIST_CHARS` (`none` when it has none)."""
    labels = [one_line(str(label)) for label in value if label] if isinstance(value, list) else []
    return shorten(", ".join(labels), MAX_LABEL_LIST_CHARS) if labels else "none"


# --- HTML → text -----------------------------------------------------------------------

_SKIP_TAGS = frozenset({"script", "style", "head", "title", "noscript", "template", "svg"})
_BLOCK_TAGS = frozenset(
    {
        "address",
        "article",
        "aside",
        "blockquote",
        "div",
        "dl",
        "dt",
        "dd",
        "fieldset",
        "figure",
        "footer",
        "form",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "header",
        "hr",
        "main",
        "nav",
        "ol",
        "p",
        "pre",
        "section",
        "table",
        "tr",
        "ul",
    }
)


_PARAGRAPH_TAGS = frozenset({"p", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote", "pre", "table"})


class _TextExtractor(HTMLParser):
    """Collects text; block boundaries become (at most) one pending line or paragraph break."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.chunks: list[str] = []
        self._skip = 0
        self._pending = 0  # newlines owed before the next text
        self._started = False
        self._href: list[str | None] = []
        self._link_text: list[list[str]] = []

    def _target(self) -> list[str]:
        return self._link_text[-1] if self._link_text else self.chunks

    def _break(self, newlines: int) -> None:
        self._pending = max(self._pending, newlines)

    def _emit(self, text: str) -> None:
        if self._pending:
            if self._started:
                self._target().append("\n" * self._pending)
            self._pending = 0
        self._target().append(text)
        self._started = True

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _SKIP_TAGS:
            self._skip += 1
            return
        if self._skip:
            return
        if tag == "br":
            self._emit("\n")
        elif tag == "li":
            self._break(1)
            self._emit("- ")
        elif tag in {"td", "th"}:
            self._emit(" ")
        elif tag in _BLOCK_TAGS:
            self._break(2 if tag in _PARAGRAPH_TAGS else 1)
        elif tag == "a":
            self._href.append(dict(attrs).get("href"))
            self._link_text.append([])

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # A self-closing tag has no content and no end tag. For a skip tag (`<svg/>`,
        # `<title/>`, `<script/>`…) handle_starttag would raise `_skip` and nothing would
        # ever lower it, so the rest of the body would vanish; an empty `<a/>` carries no text.
        if tag == "a" or tag in _SKIP_TAGS:
            return
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_TAGS:
            self._skip = max(0, self._skip - 1)
            return
        if self._skip:
            return
        if tag == "a" and self._link_text:
            text = "".join(self._link_text.pop())
            href = (self._href.pop() or "").strip()
            label = one_line(text)
            if href.lower().startswith(("http://", "https://", "mailto:")) and href != label:
                rendered = f"{label} <{href}>" if label else f"<{href}>"
            else:
                rendered = text
            if rendered:
                self._emit(rendered)
        elif tag in _BLOCK_TAGS or tag == "li":
            self._break(2 if tag in _PARAGRAPH_TAGS else 1)

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        text = re.sub(r"[ \t\r\n\f\v]+", " ", data)
        if not text.strip() and (self._pending or not self._started):
            return  # whitespace next to a block break is not content
        self._emit(text)

    def text(self) -> str:
        while self._link_text:  # an <a> never closed keeps its text
            pending = "".join(self._link_text.pop())
            self._target().append(pending)
        return "".join(self.chunks)


def _normalise_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def html_to_text(html: str) -> str:
    """Readable text from an HTML body: no tags, scripts or styles; links keep their URL."""
    parser = _TextExtractor()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # HTMLParser is lenient, but never let a body take a tool down
        pass
    text = parser.text().replace("\xa0", " ")
    lines = [" ".join(line.split()) for line in text.split("\n")]
    joined = "\n".join(lines)
    return re.sub(r"\n{3,}", "\n\n", joined).strip()


# --- paging and rendering ----------------------------------------------------------------


def shorten(text: str, limit: int) -> str:
    """`text` redacted, then cut to at most `limit` characters (the last one `…` when cut).

    Redacting first is the point: a credential cut in half matches neither its registered
    value nor its shape pattern, so the half that is kept would get through.
    """
    text = redact(text)
    return text if len(text) <= limit else text[: max(0, limit - 1)] + "…"


def page_text(text: str, offset: int, max_chars: int) -> TextPage:
    """The `[offset, offset + max_chars)` window of `text` REDACTED (an offset past the end is an empty page).

    The whole text is redacted before it is cut, so a secret that straddles a window
    boundary is replaced whole; `offset`, `end` and `total` count the redacted text.
    """
    text = redact(text)
    total = len(text)
    start = min(max(0, offset), total)
    end = min(start + max(1, max_chars), total)
    return TextPage(text=text[start:end], offset=start, end=end, total=total, next_offset=end if end < total else None)


def page_note(page: TextPage, *, what: str = "body") -> str:
    """The line that tells the model where it is in a paged text and how to get the rest."""
    if page.total == 0:
        return f"[{what}: empty]"
    if page.next_offset is not None:
        return (
            f"[{what}: characters {page.offset}–{page.end} of {page.total}; pass offset={page.next_offset} for the "
            "next part]"
        )
    if page.offset > 0 or page.end < page.total:
        return f"[{what}: characters {page.offset}–{page.end} of {page.total}; end of the {what}]"
    return f"[{what}: complete, {page.total} characters]"


def fmt_size(size: int) -> str:
    """`532 B`, `12.3 KiB`, `4.0 MiB`."""
    value = float(size)
    for unit in ("B", "KiB", "MiB"):
        if value < 1024 or unit == "MiB":
            return f"{int(value)} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GiB"  # pragma: no cover - loop always returns


def fmt_internal_date(value: Any) -> str:
    """Gmail's `internalDate` (epoch milliseconds, as a string) as `YYYY-MM-DD HH:MM UTC`."""
    try:
        millis = int(str(value).strip())
        return datetime.fromtimestamp(millis / 1000, tz=UTC).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError, OverflowError, OSError):
        return "N/A"


def render_headers(headers: Mapping[str, str]) -> str:
    """The header subset as markdown lines (`- **From**: …`)."""
    return "\n".join(f"- **{name}**: {value}" for name, value in headers.items())


def _part_ident(part_id: str | None) -> str:
    if part_id is None:
        return "no partId (cannot be saved)"
    if part_id == "":
        return 'partId `""` (the whole message)'
    return f"partId `{part_id}`"


def render_attachments(attachments: Sequence[Attachment]) -> str:
    """One markdown line per attachment, with the partId `gmail_get_attachment` takes (ADR-0002).

    At most `MAX_LISTED_ATTACHMENTS` lines, each name and type capped; the rest are counted.
    """
    if not attachments:
        return "_No attachments._"
    lines = []
    for item in attachments[:MAX_LISTED_ATTACHMENTS]:
        ident = _part_ident(None if item.part_id is None else shorten(item.part_id, MAX_ID_CHARS))
        name = shorten(item.filename, MAX_FILENAME_CHARS)
        mime = shorten(one_line(item.mime_type), MAX_MIME_CHARS)
        lines.append(f"- {name} · {mime} · {fmt_size(item.size)} ({item.size} bytes) · {ident}")
    if len(attachments) > MAX_LISTED_ATTACHMENTS:
        lines.append(
            f"- … and {len(attachments) - MAX_LISTED_ATTACHMENTS} more attachment(s), not listed (this server lists "
            f"the first {MAX_LISTED_ATTACHMENTS}): open the message in Gmail for the rest"
        )
    return "\n".join(lines)


def response_bytes(text: str) -> int:
    """The size of `text` as `clip_response` measures it: redacted, UTF-8 encoded."""
    return len(redact(text).encode())


def narrow(page: TextPage, chars: int) -> TextPage:
    """`page` cut to its first `chars` characters (at least 1); its end and next offset move with it."""
    chars = max(1, min(chars, len(page.text)))
    end = page.offset + chars
    return TextPage(page.text[:chars], page.offset, end, page.total, end if end < page.total else None)


def fit_page(
    render: Callable[[TextPage], str], page: TextPage, max_bytes: int = MAX_RESPONSE_BYTES
) -> tuple[str, TextPage]:
    """`render(page)` and `page`, or — when that response is over `max_bytes` — the longest prefix of `page` that fits.

    The page note is rendered from the page, so it always tells the truth about the window
    shown: `clip_response` never has to cut a note or the window it describes. With the
    per-field bounds above a full page always fits; this is the rail for when one does not.
    If even one character does not fit, the one-character page is returned (and
    `clip_response` cuts it, saying so).
    """
    rendered = render(page)
    if response_bytes(rendered) <= max_bytes or len(page.text) <= 1:
        return rendered, page
    smallest = narrow(page, 1)
    best = (render(smallest), smallest)
    if response_bytes(best[0]) > max_bytes:
        return best
    fits, too_big = 1, len(page.text)
    while too_big - fits > 1:
        middle = (fits + too_big) // 2
        candidate = narrow(page, middle)
        text = render(candidate)
        if response_bytes(text) <= max_bytes:
            fits, best = middle, (text, candidate)
        else:
            too_big = middle
    return best


def clip_response(text: str, max_bytes: int = MAX_RESPONSE_BYTES) -> str:
    """Redact token-shaped strings, then truncate an oversized response with an explicit note."""
    text = redact(text)
    encoded = text.encode()
    if len(encoded) <= max_bytes:
        return text
    cut = encoded[:max_bytes].decode(errors="ignore")
    return f"{cut}\n\n_[truncated: response exceeded {max_bytes:,} bytes — narrow the request]_"
