"""formatters.py (ADR D6): MIME walk, body → text, charsets, cap + offset, headers, attachments."""

from __future__ import annotations

from typing import Any

import pytest

from gmail_mcp.errors import redact, register_secret
from gmail_mcp.formatters import (
    _SKIP_TAGS,
    HEADER_SUBSET,
    MAX_FILENAME_CHARS,
    MAX_HEADER_CHARS,
    MAX_LABEL_LIST_CHARS,
    MAX_LISTED_ATTACHMENTS,
    MAX_MIME_CHARS,
    MAX_RESPONSE_BYTES,
    Attachment,
    TextPage,
    clip_response,
    decode_body_data,
    decode_text,
    extract_body,
    fit_page,
    fmt_internal_date,
    fmt_size,
    headers_subset,
    html_to_text,
    labels_line,
    list_attachments,
    narrow,
    page_note,
    page_text,
    render_attachments,
    render_headers,
    response_bytes,
    shorten,
)

from .fakes import (
    SHAPELESS_SECRET,
    attachment_part,
    b64url,
    fake_access_token,
    header,
    message,
    multipart,
    text_part,
)

PLAIN = "Hi Ada,\n\nThe numbers are attached.\n\n-- \nOps"
HTML = (
    "<html><head><title>T</title><style>p{color:red}</style><script>alert(1)</script></head><body>"
    "<h1>Numbers</h1><p>Hi&nbsp;Ada, the <b>Q3</b> numbers &amp; notes.</p>"
    '<p>See <a href="https://example.com/report">the report</a> or <a href="mailto:ops@example.com">mail us</a>.</p>'
    "<ul><li>one</li><li>two</li></ul>line<br>break<table><tr><td>a</td><td>b</td></tr></table></body></html>"
)

# The cp1252 fixture: "Café – “quoted” — 50 €" as a legacy Windows mail client writes it.
CP1252_TEXT = "Café – “quoted” — 50 €"
CP1252_BYTES = CP1252_TEXT.encode("cp1252")


@pytest.fixture
def nested_message() -> dict[str, Any]:
    """mixed[ related[ alternative[plain, html], inline image ], pdf attachment, .txt attachment ]."""
    alternative = multipart(
        "alternative",
        text_part(PLAIN, part_id="0.0.0"),
        text_part(HTML, mime="text/html", part_id="0.0.1"),
        part_id="0.0",
    )
    inline_image = {
        "partId": "0.1",
        "mimeType": "image/png",
        "filename": "logo.png",
        "headers": [header("Content-Disposition", "inline; filename=logo.png"), header("Content-ID", "<logo>")],
        "body": {"attachmentId": "ANGjdJ_FAKE_logo_0001", "size": 2048},
    }
    related = multipart("related", alternative, inline_image, part_id="0")
    payload = multipart(
        "mixed",
        related,
        attachment_part("Q3 report.pdf", "application/pdf", 123_456, "ANGjdJ_FAKE_pdf_0002", part_id="1"),
        text_part("attached notes", part_id="2", filename="notes.txt"),
    )
    return message(payload)


# --- the body ------------------------------------------------------------------------------


def test_plain_is_preferred_over_html_in_an_alternative() -> None:
    payload = multipart("alternative", text_part(PLAIN), text_part(HTML, mime="text/html"))
    body = extract_body(payload)
    assert body.source == "text/plain"
    assert body.text == PLAIN


def test_html_only_becomes_readable_text() -> None:
    body = extract_body(text_part(HTML, mime="text/html"))

    assert body.source == "text/html"
    text = body.text
    assert (
        "alert" not in text and "color:red" not in text and "<" not in text.replace("<https", "").replace("<mailto", "")
    )
    assert "Numbers" in text
    assert "Hi Ada, the Q3 numbers & notes." in text
    assert "the report <https://example.com/report>" in text
    assert "mail us <mailto:ops@example.com>" in text
    assert "- one\n- two" in text
    assert "line\nbreak" in text
    assert "a b" in text


def test_a_self_closing_svg_does_not_swallow_the_rest_of_the_body() -> None:
    assert html_to_text("<p>Hello</p><svg width=1 /><p>Important reply text</p>") == "Hello\n\nImportant reply text"


def test_a_self_closing_title_does_not_swallow_the_body() -> None:
    assert html_to_text("<title/>Body here") == "Body here"


@pytest.mark.parametrize("tag", sorted(_SKIP_TAGS))
def test_no_self_closing_skip_tag_hides_what_follows(tag: str) -> None:
    assert html_to_text(f"<p>before</p><{tag}/><p>after</p><{tag} a='1' /><p>end</p>") == "before\n\nafter\n\nend"


def test_a_real_skip_element_still_hides_its_content() -> None:
    assert html_to_text("<p>a</p><svg><text>hidden</text></svg><style>p{}</style><p>b</p>") == "a\n\nb"


def test_html_to_text_handles_unclosed_and_broken_markup() -> None:
    assert html_to_text("<p>open <a href='https://example.com/x'>link") == "open link"
    assert html_to_text("<div>a</div><div>b</div>") == "a\nb"
    assert html_to_text("") == ""


def test_a_nested_multipart_yields_the_plain_body_and_skips_attachments(nested_message: dict[str, Any]) -> None:
    body = extract_body(nested_message["payload"])
    assert body.source == "text/plain"
    assert body.text == PLAIN
    assert "attached notes" not in body.text  # a .txt attachment is not the body


def test_several_inline_plain_parts_are_joined() -> None:
    payload = multipart("mixed", text_part("first"), text_part("second footer"))
    assert extract_body(payload).text == "first\n\nsecond footer"


def test_a_text_body_stored_outside_the_message_is_reported() -> None:
    payload = multipart("alternative", text_part("", attachment_id="ANGjdJ_FAKE_bigbody_01"))
    body = extract_body(payload)
    assert body.source == "none"
    assert body.external_parts == ("ANGjdJ_FAKE_bigbody_01",)


def test_a_forwarded_message_attachment_is_not_descended_into() -> None:
    forwarded = multipart("mixed", text_part("inner secret plan"))
    forwarded.update({"mimeType": "message/rfc822", "filename": "fwd.eml"})
    forwarded["body"] = {"attachmentId": "ANGjdJ_FAKE_eml_0003", "size": 900}
    payload = multipart("mixed", text_part("outer"), forwarded)

    assert extract_body(payload).text == "outer"
    assert [item.filename for item in list_attachments(payload)] == ["fwd.eml"]


def test_a_message_without_text_has_an_empty_body() -> None:
    payload = multipart("mixed", attachment_part("a.pdf", "application/pdf", 10))
    body = extract_body(payload)
    assert (body.text, body.source) == ("", "none")


# --- charsets ------------------------------------------------------------------------------


def test_the_cp1252_fixture_decodes_with_its_declared_charset() -> None:
    body = extract_body(text_part(raw=CP1252_BYTES, charset="windows-1252"))
    assert body.text == CP1252_TEXT


def test_cp1252_bytes_mislabelled_as_utf8_fall_back_to_cp1252() -> None:
    body = extract_body(text_part(raw=CP1252_BYTES, charset="utf-8"))
    assert body.text == CP1252_TEXT


def test_cp1252_bytes_labelled_latin1_keep_their_smart_quotes() -> None:
    # Python's latin-1 would turn 0x93/0x94 into C1 control characters.
    body = extract_body(text_part(raw=CP1252_BYTES, charset="iso-8859-1"))
    assert body.text == CP1252_TEXT


def test_utf8_bytes_labelled_latin1_still_read_as_utf8() -> None:
    body = extract_body(text_part(raw="Ñandú".encode(), charset="iso-8859-1"))
    assert body.text == "Ñandú"


def test_an_unknown_charset_falls_back() -> None:
    assert extract_body(text_part(raw=CP1252_BYTES, charset="x-made-up")).text == CP1252_TEXT
    assert extract_body(text_part(raw=b"plain ascii", charset=None)).text == "plain ascii"


def test_other_declared_charsets_are_honoured() -> None:
    text = "こんにちは"
    assert extract_body(text_part(raw=text.encode("shift_jis"), charset="shift_jis")).text == text
    assert extract_body(text_part(raw="Grüße".encode("iso-8859-15"), charset="ISO-8859-15")).text == "Grüße"


def test_undecodable_bytes_never_raise() -> None:
    # 0x81 is undefined in cp1252 and invalid UTF-8: the last fallback replaces it.
    assert decode_text(b"a\x81b", "utf-8") == "a�b"


@pytest.mark.parametrize("data", [b64url(b"hello"), b64url(b"hello") + "=", "aGVsbG8"])
def test_base64url_with_or_without_padding(data: str) -> None:
    assert decode_body_data(data) == b"hello"


def test_corrupt_base64_decodes_to_nothing() -> None:
    assert decode_body_data("@@@") == b""


# --- cap + offset ----------------------------------------------------------------------------


def test_page_text_caps_and_points_at_the_next_offset() -> None:
    text = "abcdefghij" * 3

    first = page_text(text, 0, 12)
    assert (first.text, first.offset, first.end, first.total, first.next_offset) == ("abcdefghijab", 0, 12, 30, 12)
    assert page_note(first) == "[body: characters 0–12 of 30; pass offset=12 for the next part]"

    last = page_text(text, 24, 12)
    assert (last.text, last.next_offset) == ("efghij", None)
    assert page_note(last) == "[body: characters 24–30 of 30; end of the body]"


def test_page_text_redacts_a_token_straddling_the_cut_whole() -> None:
    token = fake_access_token(5)
    text = "a" * 95 + token + " tail"
    assert text[95:100] == "ya29."  # cutting first would end page 1 on a bare prefix no pattern matches

    first = page_text(text, 0, 100)
    second = page_text(text, first.next_offset or 0, 100)

    assert first.text == "a" * 95 + "*** t"
    assert (first.total, first.next_offset) == (len("a" * 95 + "*** tail"), 100)
    assert second.text == "ail"
    assert token[5:] not in first.text + second.text


def test_page_text_redacts_a_registered_shapeless_secret_straddling_the_cut_whole() -> None:
    register_secret(SHAPELESS_SECRET)
    text = "b" * 90 + SHAPELESS_SECRET + " end"
    assert redact(text[:100]) == text[:100]  # the premise: a cut secret no longer matches its value

    first = page_text(text, 0, 100)

    assert first.text == "b" * 90 + "*** end"
    assert first.next_offset is None
    assert SHAPELESS_SECRET[:10] not in first.text


def test_shorten_redacts_before_it_cuts() -> None:
    register_secret(SHAPELESS_SECRET)
    assert shorten("c" * 5 + SHAPELESS_SECRET, 10) == "ccccc***"
    assert shorten("c" * 50 + fake_access_token(2), 20) == "c" * 19 + "…"
    assert shorten("short", 10) == "short"


def test_page_text_whole_and_past_the_end() -> None:
    whole = page_text("short", 0, 100)
    assert page_note(whole) == "[body: complete, 5 characters]"
    beyond = page_text("short", 99, 100)
    assert (beyond.text, beyond.offset, beyond.next_offset) == ("", 5, None)
    assert page_note(page_text("", 0, 10)) == "[body: empty]"
    assert page_text("abc", -5, 2).offset == 0


# --- headers ---------------------------------------------------------------------------------


def test_headers_subset_keeps_only_the_six_in_order() -> None:
    headers = [
        header("Subject", "Quarterly numbers"),
        header("X-Mailer", "Thing 1.0"),
        header("message-id", "<msg-0001@mail.example.com>"),
        header("From", "Ada <ada@example.com>"),
        header("Received", "from mx.example.com"),
        header("DATE", "Tue, 10 Nov 2026 10:00:00 +0000"),
        header("To", "ops@example.com"),
        header("Cc", "a@example.com"),
        header("Cc", "b@example.com"),
    ]
    subset = headers_subset({"headers": headers})

    assert list(subset) == ["From", "To", "Cc", "Date", "Subject", "Message-ID"] == list(HEADER_SUBSET)
    assert subset["Cc"] == "a@example.com, b@example.com"
    assert subset["Message-ID"] == "<msg-0001@mail.example.com>"
    assert "X-Mailer" not in subset and "Received" not in subset


def test_encoded_words_and_folded_headers_become_one_line() -> None:
    headers = [header("Subject", "=?utf-8?b?Q2Fmw6kgcmVwb3J0?=\r\n\tpart two"), header("From", "=?bad?q?x?=")]
    subset = headers_subset({"headers": headers})
    assert subset["Subject"] == "Café report part two"
    assert "\n" not in subset["From"]


def test_render_headers() -> None:
    assert render_headers({"From": "a@example.com", "Subject": "x"}) == "- **From**: a@example.com\n- **Subject**: x"


# --- attachments -------------------------------------------------------------------------------


def test_attachments_are_listed_with_filename_type_size_and_id(nested_message: dict[str, Any]) -> None:
    attachments = list_attachments(nested_message["payload"])

    assert attachments == [
        Attachment("logo.png", "image/png", 2048, "ANGjdJ_FAKE_logo_0001", "0.1"),
        Attachment("Q3 report.pdf", "application/pdf", 123_456, "ANGjdJ_FAKE_pdf_0002", "1"),
        Attachment("notes.txt", "text/plain", len(b"attached notes"), None, "2"),
    ]
    rendered = render_attachments(attachments)
    assert "- logo.png · image/png · 2.0 KiB (2048 bytes) · partId `0.1`" in rendered
    assert "- Q3 report.pdf · application/pdf · 120.6 KiB (123456 bytes) · partId `1`" in rendered
    assert "- notes.txt · text/plain · 14 B (14 bytes) · partId `2`" in rendered
    assert "ANGjdJ" not in rendered and "attachmentId" not in rendered  # ADR-0002: never the rotating id


def test_the_attachment_line_names_the_root_part_and_a_missing_part_id() -> None:
    root = Attachment("scan.pdf", "application/pdf", 10, "ANGjdJ_FAKE_root_0001", "")
    nameless = Attachment("x.bin", "application/octet-stream", 3, None, None)

    rendered = render_attachments([root, nameless])

    assert '- scan.pdf · application/pdf · 10 B (10 bytes) · partId `""` (the whole message)' in rendered
    assert "- x.bin · application/octet-stream · 3 B (3 bytes) · no partId (cannot be saved)" in rendered


def test_an_attachment_disposition_without_filename_is_an_attachment() -> None:
    part = text_part("x", extra_headers=[header("Content-Disposition", "attachment")])
    assert [item.filename for item in list_attachments(multipart("mixed", text_part("body"), part))] == ["(no name)"]
    assert extract_body(multipart("mixed", text_part("body"), part)).text == "body"


def test_no_attachments_renders_a_note() -> None:
    assert render_attachments([]) == "_No attachments._"
    assert list_attachments(text_part("only text")) == []


# --- helpers ------------------------------------------------------------------------------------


def test_fmt_size_and_internal_date() -> None:
    assert fmt_size(532) == "532 B"
    assert fmt_size(12_600) == "12.3 KiB"
    assert fmt_size(26_214_400) == "25.0 MiB"
    assert fmt_internal_date("1794308400000") == "2026-11-10 11:00 UTC"
    assert fmt_internal_date("soon") == "N/A"


def test_clip_response_redacts_and_truncates() -> None:
    token = fake_access_token(3)
    assert clip_response(f"pasted {token} in a mail") == "pasted *** in a mail"
    big = clip_response("x" * (MAX_RESPONSE_BYTES + 10))
    assert big.endswith("narrow the request]_")
    assert len(big.encode()) < MAX_RESPONSE_BYTES + 200


# --- bounded output ----------------------------------------------------------------------------


def test_a_header_value_is_capped_after_redaction() -> None:
    register_secret(SHAPELESS_SECRET)
    value = "a" * (MAX_HEADER_CHARS - 5) + SHAPELESS_SECRET + "b" * 50
    subset = headers_subset({"headers": [header("Subject", value), header("From", "ada@example.com")]})
    assert subset["Subject"] == "a" * (MAX_HEADER_CHARS - 5) + "***b…"  # redacted whole, then cut
    assert len(subset["Subject"]) <= MAX_HEADER_CHARS
    assert subset["From"] == "ada@example.com"


def test_the_attachment_list_is_capped_in_count_and_width() -> None:
    items = [Attachment("n" * 500, "m" * 500, 1, None, str(n)) for n in range(MAX_LISTED_ATTACHMENTS + 7)]
    lines = render_attachments(items).split("\n")
    assert len(lines) == MAX_LISTED_ATTACHMENTS + 1
    assert lines[0].startswith("- " + "n" * (MAX_FILENAME_CHARS - 1) + "… · " + "m" * (MAX_MIME_CHARS - 1) + "… · ")
    assert lines[-1].startswith(
        f"- … and 7 more attachment(s), not listed (this server lists the first {MAX_LISTED_ATTACHMENTS})"
    )


def test_labels_line_is_capped() -> None:
    assert labels_line(["INBOX", "UNREAD"]) == "INBOX, UNREAD"
    assert labels_line([]) == labels_line(None) == "none"
    assert len(labels_line([f"Label_{n}" for n in range(500)])) == MAX_LABEL_LIST_CHARS


def _render_with_note(page: TextPage) -> str:
    return f"# header\n{page_note(page)}\n{page.text}\n# footer"


def test_fit_page_keeps_a_page_that_fits() -> None:
    page = page_text("x" * 100, 0, 100)
    rendered, kept = fit_page(_render_with_note, page, 1_000)
    assert kept == page and rendered == _render_with_note(page)


def test_fit_page_shrinks_the_window_and_the_note_follows() -> None:
    full = page_text("\U0001f600" * 1_000, 0, 1_000)  # 4 000 bytes of body
    rendered, kept = fit_page(_render_with_note, full, 1_000)

    assert response_bytes(rendered) <= 1_000
    assert response_bytes(_render_with_note(narrow(full, len(kept.text) + 1))) > 1_000  # the longest that fits
    assert kept.offset == 0 and kept.end == len(kept.text) and kept.next_offset == kept.end
    assert f"pass offset={kept.end} for the next part" in rendered  # the note tells the truth about the window


def test_fit_page_returns_one_character_when_nothing_fits() -> None:
    rendered, kept = fit_page(lambda page: "h" * 2_000 + page.text, page_text("abc", 0, 3), 100)
    assert kept.text == "a" and kept.next_offset == 1


def test_narrow_moves_the_end_and_next_offset() -> None:
    page = page_text("abcdefghij", 2, 6)
    assert (narrow(page, 3).text, narrow(page, 3).end, narrow(page, 3).next_offset) == ("cde", 5, 5)
    last = page_text("abcdefghij", 4, 6)
    assert narrow(last, 99) == last
