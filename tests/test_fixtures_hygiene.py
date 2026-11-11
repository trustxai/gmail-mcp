"""What this repo must not hold, because it becomes public: credential literals and real mailboxes.

- **No token-shaped literal** in any tracked file: Google access tokens (`ya29.…`), refresh
  tokens (`1//…`), client secrets (`GOCSPX-…`), authorization codes (`4/0…`), or a Desktop
  client id glued to its numeric project prefix. Secret scanners (GitHub push protection
  among them) flag those even when fake, so `tests/fakes.py` assembles its fixtures at
  runtime and the redaction tests build theirs the same way.
- **Every email address is a placeholder** under example.com / example.org / example.net (or
  a subdomain): no real company mailbox, in tests, docs or examples.

Both scans are checked in both directions: a planted sample is caught, a placeholder is not.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
# Generated files: release-please writes the first, uv the second.
_NOT_SCANNED = {"CHANGELOG.md", "uv.lock"}

TOKEN_SHAPES: dict[str, re.Pattern[str]] = {
    "access-token": re.compile(r"ya29\.[A-Za-z0-9_-]{8,}"),
    "refresh-token": re.compile(r"(?<![A-Za-z0-9])1//[A-Za-z0-9_-]{8,}"),
    "client-secret": re.compile(r"GOCSPX-[A-Za-z0-9_-]{8,}"),
    "auth-code": re.compile(r"(?<![A-Za-z0-9/])4/0[A-Za-z0-9_-]{20,}"),
    "client-id": re.compile(r"[0-9]{6,}-[A-Za-z0-9_]+\.apps\.googleusercontent\.com"),
}
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})")
_PLACEHOLDER_DOMAIN = re.compile(r"(?:.+\.)?example\.(?:com|org|net)", re.IGNORECASE)


def _tracked_files() -> list[Path]:
    # Tracked files plus new ones not yet committed (the scan must cover a branch before its
    # first commit too); ignored files (.env, tokens) are never listed.
    try:
        listed = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            capture_output=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        pytest.skip(f"the scan needs `git ls-files` in a checkout: {exc}")
    names = sorted({name for name in listed.stdout.decode().split("\0") if name and name not in _NOT_SCANNED})
    return [REPO_ROOT / name for name in names if (REPO_ROOT / name).is_file()]


def _lines() -> list[tuple[str, int, str]]:
    out = []
    for path in _tracked_files():
        text = path.read_text(encoding="utf-8", errors="replace")
        rel = path.relative_to(REPO_ROOT).as_posix()
        out.extend((rel, number, line) for number, line in enumerate(text.splitlines(), start=1))
    return out


def foreign_emails(text: str) -> list[str]:
    """The email addresses in `text` whose domain is not a reserved example domain."""
    return [match.group(0) for match in _EMAIL.finditer(text) if not _PLACEHOLDER_DOMAIN.fullmatch(match.group(1))]


def test_the_scan_covers_the_repo() -> None:
    names = {path.relative_to(REPO_ROOT).as_posix() for path in _tracked_files()}
    expected = {
        "README.md",
        ".env.example",
        "SECURITY.md",
        "pyproject.toml",
        "src/gmail_mcp/errors.py",
        "tests/fakes.py",
        "tests/test_errors.py",
        "tests/test_fixtures_hygiene.py",
    }
    assert expected <= names, expected - names
    assert not _NOT_SCANNED & names


@pytest.mark.parametrize("shape", sorted(TOKEN_SHAPES))
def test_no_file_holds_a_token_shaped_literal(shape: str) -> None:
    pattern = TOKEN_SHAPES[shape]
    hits = [f"{rel}:{number}" for rel, number, line in _lines() if pattern.search(line)]
    # file:line only — never the match itself (CI logs are public).
    assert not hits, f"{shape} literals (build fixtures at runtime, see tests/fakes.py):\n" + "\n".join(hits)


def test_every_email_address_is_a_placeholder() -> None:
    hits = [f"{rel}:{number}" for rel, number, line in _lines() if foreign_emails(line)]
    assert not hits, "email addresses outside example.com/.org/.net:\n" + "\n".join(hits)


# Both directions of each scanner, with samples assembled at runtime.
_SLASHES = "/" * 2
_PLANTED = {
    "access-token": "ya29" + "." + "a0AfB_byC-FAKEFAKE",
    "refresh-token": "1" + _SLASHES + "0gFAKEFAKEFAKE",
    "client-secret": "GOCSPX" + "-" + "FAKEFAKEFAKE",
    "auth-code": "4" + "/" + "0AeanS0b" + "F" * 20,
    "client-id": "123456789012" + "-" + "abc" + ".apps.googleusercontent.com",
}


@pytest.mark.parametrize("shape", sorted(TOKEN_SHAPES))
def test_each_token_scanner_catches_a_planted_literal(shape: str) -> None:
    assert TOKEN_SHAPES[shape].search(f"x = '{_PLANTED[shape]}'")


@pytest.mark.parametrize("text", ["ya29 notes", "see 1/2 and 4/5", "fakeclient.apps.googleusercontent.com", "GOCSPX"])
def test_the_token_scanners_spare_near_misses(text: str) -> None:
    assert not [shape for shape, pattern in TOKEN_SHAPES.items() if pattern.search(text)]


# Planted mailboxes are joined at runtime, or this very file would trip the scan.
_AT = "@"


@pytest.mark.parametrize(
    "text",
    [
        "ops" + _AT + "clientco.com",
        "Ana <ana.perez" + _AT + "mail.clientco.pe>",
        "x" + _AT + "example.com.evil.org",
        "bot" + _AT + "examplecom.net",
    ],
)
def test_the_email_scan_catches_a_real_looking_mailbox(text: str) -> None:
    assert foreign_emails(text)


@pytest.mark.parametrize(
    "text",
    [
        "you@example.com",
        "Ada <ada@mail.example.com>",
        "rfc822msgid:msg-0001@mail.example.com",
        "x@EXAMPLE.ORG and y@sub.example.net",
        "uvx amazing-gmail-mcp@0.1.0",
        "uses: actions/checkout@v4",
    ],
)
def test_the_email_scan_spares_placeholders_and_non_addresses(text: str) -> None:
    assert not foreign_emails(text)
