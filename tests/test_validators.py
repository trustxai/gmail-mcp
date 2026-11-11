"""validators.py: id shapes, bounds, and the ADR D5 query check every search goes through."""

from __future__ import annotations

import re

import pytest

from gmail_mcp import validators as v

from .fakes import CJK, FOUR_BYTES, text_of_encoded_size


@pytest.mark.parametrize("value", ["18c2f0e9a1b2c3d4", " 18C2F0E9A1B2C3D4 ", "abc123"])
def test_message_and_thread_ids(value: str) -> None:
    assert v.message_id(value) == value.strip()
    assert v.thread_id(value) == value.strip()


@pytest.mark.parametrize(
    "value", ["", "abc", "18c2f0e9/../x", "18c2f0e9\na1b2c3d4", "١٨c2f0e9a1b2", "a" * 65, "id with space"]
)
def test_bad_ids_are_refused(value: str) -> None:
    with pytest.raises(ValueError, match="message_id must be a Gmail message id"):
        v.message_id(value)


def test_label_attachment_and_page_token_ids() -> None:
    assert v.label_id("CATEGORY_UPDATES") == "CATEGORY_UPDATES"
    assert v.label_id("Label_123") == "Label_123"
    assert v.attachment_id("ANGjdJ_FAKE_attachment-0001") == "ANGjdJ_FAKE_attachment-0001"
    assert v.page_token("09876543210123456789") == "09876543210123456789"
    for func, bad in ((v.label_id, "Projects/Acme"), (v.attachment_id, "short"), (v.page_token, "a b")):
        with pytest.raises(ValueError):
            func(bad)


@pytest.mark.parametrize(("value", "expected"), [(1, 1), ("20", 20), (100, 100)])
def test_max_results(value: object, expected: int) -> None:
    assert v.max_results(value) == expected


@pytest.mark.parametrize("value", [0, 101, -1, True, "many", 2.5, None])
def test_max_results_out_of_bounds(value: object) -> None:
    with pytest.raises(ValueError, match="max_results"):
        v.max_results(value)


def test_offset() -> None:
    assert v.offset(0) == 0
    assert v.offset("20000") == 20000
    with pytest.raises(ValueError):
        v.offset(-1)


def test_search_query_is_one_line_and_balanced() -> None:
    assert v.search_query("  from:ada@example.com\n  has:attachment ") == "from:ada@example.com has:attachment"
    assert v.search_query('subject:"a (b"') == 'subject:"a (b"'


@pytest.mark.parametrize("value", [") OR from:x (", "a\x00b", "x" * (v.MAX_QUERY_CHARS + 1), '"open'])
def test_search_query_refusals(value: str) -> None:
    with pytest.raises(ValueError, match="query"):
        v.search_query(value)


@pytest.mark.parametrize("char", [FOUR_BYTES, CJK, "é"], ids=["4-byte", "CJK", "accented"])
def test_search_query_at_the_encoded_cap_passes_and_one_past_it_is_refused(char: str) -> None:
    at = text_of_encoded_size(char, v.MAX_QUERY_ENCODED)
    assert v.encoded_length(at) == v.MAX_QUERY_ENCODED and len(at) <= v.MAX_QUERY_CHARS
    assert v.search_query(at) == at
    too_long = (
        f"query is refused: it is {v.MAX_QUERY_ENCODED + 1:,} characters once percent-encoded for the URL, "
        f"the most is {v.MAX_QUERY_ENCODED:,}"
    )
    with pytest.raises(ValueError, match=re.escape(too_long)):
        v.search_query(at + "a")
    with pytest.raises(ValueError, match="once percent-encoded"):
        v.search_query(at[: -len(char)] + char + char)  # one more of the wide character, not of `a`


def test_an_ascii_search_query_at_the_character_cap_passes_and_one_past_it_is_refused() -> None:
    for at in ("x" * v.MAX_QUERY_CHARS, ":" * v.MAX_QUERY_CHARS):  # letters 1 each, punctuation 3
        assert v.search_query(at) == at
    with pytest.raises(ValueError, match=re.escape(f"it is {v.MAX_QUERY_CHARS + 1:,} characters, the most is")):
        v.search_query("x" * (v.MAX_QUERY_CHARS + 1))


def test_ascii_reaches_the_character_cap_before_an_encoded_one() -> None:
    # 3 is the most an ASCII character takes encoded (control characters are refused).
    assert 3 * v.MAX_QUERY_CHARS <= v.MAX_QUERY_ENCODED
    assert 3 * v.MAX_SCOPE_QUERY_CHARS <= v.MAX_SCOPE_QUERY_ENCODED


def test_search_query_refuses_text_that_is_not_utf8() -> None:
    with pytest.raises(ValueError, match="query is refused: it is not valid UTF-8 text"):
        v.search_query("invoice \udcff")


def test_query_size_problem_names_sizes_never_the_text() -> None:
    for text in ("zq-secret " + FOUR_BYTES * 600, "zq-secret " + "x" * 2_000, "zq-secret \ud800"):
        problem = v.query_size_problem(text, max_chars=v.MAX_QUERY_CHARS, max_encoded=v.MAX_QUERY_ENCODED)
        assert problem is not None and "zq-secret" not in problem and FOUR_BYTES not in problem


@pytest.mark.parametrize(
    ("query", "problem"),
    [
        (") OR from:x (", "closes a group"),
        ("(a", "never closed"),
        ("{a", "never closed"),
        ("a}", "closes a group"),
        ('"a', "double quote is never closed"),
        ('\\"a\\"', "backslash"),
        ("“a”", "typographic"),
        ("({)}", "closes a '{' group"),
        ("( { ) OR from:bank ( } )", "closes a '{' group"),
        ("{(})", "closes a '(' group"),
        ("(a { b ) c }", "closes a '{' group"),
    ],
)
def test_query_problem_names_the_problem(query: str, problem: str) -> None:
    found = v.query_problem(query)
    assert found is not None and problem in found


# Each of these balances when ( ) and { } are counted apart: only one stack refuses them.
CROSSED = ["({)}", "( { ) OR from:bank ( } )", "{(})", "(a { b ) c }", "{ ( } ) OR from:x"]


@pytest.mark.parametrize("query", CROSSED)
def test_query_problem_refuses_crossed_groups(query: str) -> None:
    assert query.count("(") == query.count(")") and query.count("{") == query.count("}")
    assert v.query_problem(query) is not None
    with pytest.raises(ValueError, match="query is refused"):
        v.search_query(query)


@pytest.mark.parametrize(
    "query", ["", "a b", "(a OR b)", "{a b}", '"(" ")"', "-(a) (b)", "a:(b c)", "({a b} c)", "{(a b) c}", '({")"})']
)
def test_query_problem_accepts_balanced_queries(query: str) -> None:
    assert v.query_problem(query) is None
