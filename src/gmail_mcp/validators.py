"""Input normalisers shared by every tool module's pydantic models.

Each function takes the raw value the model sent, returns the exact value the Gmail API
expects, and raises `ValueError` with a readable message otherwise — so a
`field_validator` can call it directly. Tool modules use these instead of re-implementing
the rules. Every pattern is applied with `fullmatch` and spells its characters in ASCII:
`$` would also match before a trailing newline, and `\\d` accepts any Unicode digit.

`query_problem` is the ADR D5 check every search query goes through (the scope module
refuses the same queries again before it composes `(<scope>) (<user query>)`).
`query_size_problem` bounds the two halves of that `q` (in characters and once
percent-encoded), so every list call and scope lookup fits Gmail's URL limit; the comment
above the caps records what was measured.
"""

from __future__ import annotations

import re

import httpx

# Gmail message and thread ids are lower-case hex today (16 characters); accept any ASCII
# alphanumeric id of a sane length, so a path can never be smuggled in.
_MESSAGE_ID_RE = re.compile(r"[A-Za-z0-9]{6,64}")
# Label ids: system labels (INBOX, CATEGORY_UPDATES) and user labels (Label_123…).
_LABEL_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,128}")
# Attachment ids are long base64url strings.
_ATTACHMENT_ID_RE = re.compile(r"[A-Za-z0-9_-]{10,4096}")
_PAGE_TOKEN_RE = re.compile(r"[A-Za-z0-9_.=-]{1,1024}")

DEFAULT_MAX_RESULTS = 20
MAX_MAX_RESULTS = 100
MAX_OFFSET = 100_000_000

# --- query size: what fits Gmail's URL limit ---------------------------------------------
# Every list call sends `q` = `(<GMAIL_SCOPE_QUERY>) (<query>) -in:spam -in:trash` in its URL,
# and so does the scope check's lookup (`(<scope>) rfc822msgid:<Message-ID>`). Gmail's front end
# answers 400 (a text/html page) to a request target — path plus query — longer than
# GMAIL_MAX_REQUEST_TARGET: measured by the v0.1 review on 2026-11-11 with unauthenticated
# GETs to /gmail/v1/users/me/messages (a 16,356-character query component got 401, 16,357 got
# the 400; with the path and its `?`, 16,384 in all). Too long a scope query therefore breaks
# every search ("Gmail API error 400") and makes every fetch in a query scope "not found" (its
# lookup fails, and the check fails closed).
# httpx's own limit (65,536 for the query component, `InvalidURL`) is four times higher.
#
# So each query is bounded twice: in characters (what the output shows), and in the characters
# it takes once percent-encoded, as httpx encodes it (`encoded_length`): an ASCII letter or a
# space 1, ASCII punctuation 3, `é` 6, CJK 9, a 4-byte character such as `😀` 12. The encoded
# caps leave the worst list call and the worst lookup under MAX_REQUEST_TARGET, 1,024 under
# Gmail's limit. Measured with httpx 0.28.1 (tests/test_scope.py asserts these figures):
# - the worst list call — both queries at their encoded cap, a 1,024-character page token of
#   `=` (each `%3D`), a 128-character label id, maxResults and includeSpamTrash, on the longer
#   list path — has a 15,325-character request target (1,059 under Gmail's limit), the same
#   for 4-byte, CJK and accented text at the caps;
# - the worst lookup — the scope at its encoded cap and a 995-character Message-ID of
#   percent-encoded characters — is 9,073;
# - ASCII never reaches an encoded cap before its character cap (1,500 × 3 = 4,500).
# `scope.apply()` also measures each list call it composes and refuses one over the bound.
GMAIL_MAX_REQUEST_TARGET = 16_384
MAX_REQUEST_TARGET = GMAIL_MAX_REQUEST_TARGET - 1_024
# The `query` param of gmail_search_messages and gmail_search_threads (after whitespace is collapsed).
MAX_QUERY_CHARS = 1_500
MAX_QUERY_ENCODED = 6_000  # about 660 CJK or 500 emoji characters
# How the tools describe the two caps to the model.
QUERY_SIZE_HELP = (
    f"At most {MAX_QUERY_CHARS:,} characters, and {MAX_QUERY_ENCODED:,} once URL-encoded (a non-ASCII character "
    "counts 6 to 12: about 660 CJK characters or 500 emoji)."
)
# GMAIL_SCOPE_QUERY: past either cap it refuses to load (config.py), as it rides along every
# search. The same room as a query: a `from:(a OR b OR …)` list of some 50 addresses fits.
MAX_SCOPE_QUERY_CHARS = 1_500
MAX_SCOPE_QUERY_ENCODED = 6_000

# Typographic double quotes. Gmail may or may not treat them as phrase quotes; if it did,
# a parenthesis "inside" them would not count for Gmail while it counts here, and the
# balance check below would be unsound. Refusing them keeps one reading of the query.
_TYPOGRAPHIC_QUOTES = frozenset("“”„‟«»＂〝〞")


def message_id(value: object, *, field: str = "message_id") -> str:
    """Validate a Gmail message id (e.g. `18c2f0e9a1b2c3d4`)."""
    text = str(value).strip()
    if not _MESSAGE_ID_RE.fullmatch(text):
        raise ValueError(f"{field} must be a Gmail message id like 18c2f0e9a1b2c3d4 (take it from a search result)")
    return text


def thread_id(value: object, *, field: str = "thread_id") -> str:
    """Validate a Gmail thread id (same shape as a message id)."""
    text = str(value).strip()
    if not _MESSAGE_ID_RE.fullmatch(text):
        raise ValueError(f"{field} must be a Gmail thread id like 18c2f0e9a1b2c3d4 (take it from a search result)")
    return text


def label_id(value: object, *, field: str = "label_id") -> str:
    """Validate a label id (`INBOX`, `Label_123`, …) — not a label name."""
    text = str(value).strip()
    if not _LABEL_ID_RE.fullmatch(text):
        raise ValueError(f"{field} must be a Gmail label id like INBOX or Label_123 (see gmail_list_labels)")
    return text


def attachment_id(value: object, *, field: str = "attachment_id") -> str:
    """Validate an attachment id (a long base64url string from gmail_get_message)."""
    text = str(value).strip()
    if not _ATTACHMENT_ID_RE.fullmatch(text):
        raise ValueError(f"{field} must be the attachmentId gmail_get_message lists for that attachment")
    return text


def page_token(value: object, *, field: str = "page_token") -> str:
    """Validate a `nextPageToken` from a previous list call."""
    text = str(value).strip()
    if not _PAGE_TOKEN_RE.fullmatch(text):
        raise ValueError(f"{field} must be the next_page_token a previous call returned")
    return text


def max_results(value: object, *, field: str = "max_results", low: int = 1, high: int = MAX_MAX_RESULTS) -> int:
    """An int in `[low, high]` (bools refused)."""
    if isinstance(value, bool) or not isinstance(value, int | str):
        raise ValueError(f"{field} must be an integer from {low} to {high}")
    try:
        number = int(str(value).strip())
    except ValueError:
        raise ValueError(f"{field} must be an integer from {low} to {high}") from None
    if not low <= number <= high:
        raise ValueError(f"{field} must be from {low} to {high}")
    return number


def offset(value: object, *, field: str = "offset") -> int:
    """A character offset into a body (0 = from the start)."""
    return max_results(value, field=field, low=0, high=MAX_OFFSET)


def encoded_length(text: str) -> int | None:
    """The characters `text` takes as a URL query value, percent-encoded exactly as httpx sends it.

    `None` when it is not UTF-8 text (a lone surrogate, e.g. an undecodable byte in an
    environment variable): httpx could not send it at all.
    """
    try:
        return len(str(httpx.QueryParams({"q": text}))) - len("q=")
    except UnicodeEncodeError:
        return None


def query_size_problem(text: str, *, max_chars: int, max_encoded: int) -> str | None:
    """Why `text` cannot ride in a search URL, or `None`. Names sizes only, never the text."""
    if len(text) > max_chars:
        return f"it is {len(text):,} characters, the most is {max_chars:,}"
    size = encoded_length(text)
    if size is None:
        return "it is not valid UTF-8 text"
    if size > max_encoded:
        return (
            f"it is {size:,} characters once percent-encoded for the URL, the most is {max_encoded:,} (a non-ASCII "
            f"character takes 6 to 12; Gmail refuses a request longer than {GMAIL_MAX_REQUEST_TARGET:,})"
        )
    return None


def query_problem(query: str) -> str | None:
    """Why `query` could escape a `(<scope>) (<query>)` composition, or `None` when it cannot.

    Groups are read with ONE stack over `( )` and `{ }` (Gmail's OR group), outside double
    quotes, so every closer must close the innermost group still open. Refused: a closer with
    no group open (the cortex escape is `) OR from:x (`), a closer of the other kind (crossed
    groups such as `( { ) OR from:bank ( } )`, whose reading by Gmail nobody has checked), and
    a group left open. Also refused because they would make "outside double quotes"
    ambiguous: an unterminated `"`, a backslash before a `"`, and typographic quotes.
    """
    if any(char in _TYPOGRAPHIC_QUOTES for char in query):
        return 'it contains typographic quotes; use straight double quotes (") for a phrase'
    if '\\"' in query:
        return 'it contains a backslash before a double quote; Gmail has no escapes inside a "phrase"'
    opener_of = {")": "(", "}": "{"}
    open_groups: list[str] = []
    in_phrase = False
    for char in query:
        if char == '"':
            in_phrase = not in_phrase
            continue
        if in_phrase:
            continue
        if char in "({":
            open_groups.append(char)
        elif char in opener_of:
            if not open_groups:
                return f"a '{char}' closes a group that was never opened; parentheses and braces must balance"
            innermost = open_groups.pop()
            if innermost != opener_of[char]:
                return (
                    f"a '{char}' closes a '{innermost}' group; parentheses and braces must close in the order they "
                    "were opened"
                )
    if in_phrase:
        return 'a double quote is never closed; every "phrase" needs both quotes'
    if open_groups:
        return "a group is opened and never closed; parentheses and braces must balance"
    return None


def search_query(value: object, *, field: str = "query") -> str:
    """A Gmail search query: one line, bounded, and never able to escape the project scope."""
    text = " ".join(str(value).split())
    if any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise ValueError(f"{field} must not contain control characters")
    size = query_size_problem(text, max_chars=MAX_QUERY_CHARS, max_encoded=MAX_QUERY_ENCODED)
    if size is not None:
        raise ValueError(f"{field} is refused: {size}")
    problem = query_problem(text)
    if problem is not None:
        raise ValueError(f"{field} is refused: {problem}")
    return text
