"""`amazing-gmail-mcp-login` — mints the gmail.readonly refresh token, once per company (ADR D3).

    amazing-gmail-mcp-login --account ops@example.com \\
        --client-secret-file ~/.config/workspace-mcp/client_secret.json \\
        --out ~/.config/amazing-gmail-mcp/company.token.json [--force]

The flow (Google's "OAuth 2.0 for Desktop Apps", loopback redirect):

1. **Everything checkable is checked before the browser opens**, so a bad flag never costs a
   consent nor one of the 100 refresh-token slots Google keeps per account and client: the
   account's shape, the client JSON (read with `config.load_client_credentials`), and `--out`
   (not a directory, not inside a git work tree, not an existing file unless `--force`).
2. A listener on `127.0.0.1` with a random free port; PKCE S256 (a fresh verifier from
   `secrets`); a random `state`. The authorization URL asks for `gmail.readonly` and nothing
   else, `access_type=offline`, `prompt=consent`, `login_hint=<account>`. It is printed (to
   stderr) and opened with `webbrowser`.
3. The listener answers ONE request and closes, with a timeout. A redirect whose `state`
   does not match, that carries an `error`, or that lacks the code is refused.
4. The code is exchanged at the token endpoint. The granted scope must pass the same rule the
   server applies at every refresh (`auth.scope_problem`, ADR D2), the response must carry a
   refresh token, and `users/me/profile` must be `--account` (case-insensitive). Any failure:
   nothing is written.
5. `{"account", "client_id", "refresh_token", "scope", "created_at"}` is written to `--out`,
   mode 0600 (a parent directory it creates is 0700), atomically (temp file + rename), never
   replacing a file without `--force`.

stdout gets only the path and an 8-hex sha256 fingerprint of the token. The refresh token,
the access token, the authorization code and the PKCE verifier never reach stdout, stderr or
a log: each is registered with `errors.register_secret` the moment it exists, every message
goes through `errors.redact`, and the listener's request logging (which would print the
redirect's query string, i.e. the code) is switched off.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import html
import json
import os
import re
import secrets
import sys
import tempfile
import webbrowser
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx

from gmail_mcp.auth import READONLY_SCOPE, TOKEN_URL, scope_problem
from gmail_mcp.client import API_BASE, PROFILE_PATH
from gmail_mcp.config import ClientCredentials, load_client_credentials
from gmail_mcp.errors import GmailError, one_line, redact, register_secret

PROG = "amazing-gmail-mcp-login"
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
PROFILE_URL = f"{API_BASE}/{PROFILE_PATH}"
LOOPBACK_HOST = "127.0.0.1"
CALLBACK_PATH = "/"
# How long the listener waits for Google's redirect (the consent screen is a human step).
CALLBACK_TIMEOUT_SECONDS = 300.0
# How long one accepted connection may take to send its request line and headers.
REQUEST_READ_TIMEOUT_SECONDS = 30.0
HTTP_TIMEOUT_SECONDS = 30.0
# RFC 7636: the verifier is 43-128 characters of [A-Za-z0-9-._~]; token_urlsafe(64) is 86.
VERIFIER_BYTES = 64
STATE_BYTES = 32
FINGERPRINT_HEX_CHARS = 8
FILE_MODE = 0o600
DIR_MODE = 0o700

_PERMISSIONS_URL = "https://myaccount.google.com/permissions"
_RETRY = "run the login again"
# An `error` value from the redirect is echoed only if it looks like an OAuth error code.
_ERROR_CODE_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_ERROR_HINTS: dict[str, str] = {
    "access_denied": "the consent was cancelled in the browser; run the login again and allow access",
    "admin_policy_enforced": (
        "the Workspace admin blocks this client: Admin console → Security → API controls → trust the client "
        "ID (or 'Trust internal apps'), then run the login again"
    ),
    "org_internal": (
        "the client is Internal to another Workspace organization: sign in with an account of the client's "
        "organization, or use that company's client JSON"
    ),
}


class LoginError(GmailError):
    """The login cannot finish; the message is one line: the cause, then the fix."""


@dataclass(frozen=True)
class LoginResult:
    """What the CLI reports: where the token went and a fingerprint to tell tokens apart."""

    path: Path
    fingerprint: str
    account: str


# --- PKCE, state, the authorization URL --------------------------------------------------


def code_challenge(verifier: str) -> str:
    """RFC 7636 S256: base64url(sha256(verifier)) without padding."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def pkce_pair() -> tuple[str, str]:
    """A fresh `(verifier, challenge)` pair."""
    verifier = secrets.token_urlsafe(VERIFIER_BYTES)
    return verifier, code_challenge(verifier)


def new_state() -> str:
    """The CSRF `state` the redirect must echo back."""
    return secrets.token_urlsafe(STATE_BYTES)


def authorization_url(*, client_id: str, redirect_uri: str, account: str, state: str, challenge: str) -> str:
    """Google's consent URL: gmail.readonly only, offline, consent forced, PKCE S256.

    `include_granted_scopes` is deliberately absent: incremental authorization would fold
    scopes granted to this client before into the new token.
    """
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": READONLY_SCOPE,
        "access_type": "offline",
        "prompt": "consent",
        "login_hint": account,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return f"{AUTH_URL}?{urlencode(params)}"


# --- the loopback listener ---------------------------------------------------------------


def parse_callback(target: str, expected_state: str) -> str:
    """The authorization code from the redirect's request target, or `LoginError` (a refusal)."""
    parts = urlsplit(target)
    if parts.path != CALLBACK_PATH:
        raise LoginError(
            "the request to the listener was not Google's redirect (wrong path): "
            f"{_RETRY} and finish it in the browser it opens"
        )
    try:
        query = parse_qs(parts.query, keep_blank_values=True, max_num_fields=32)
    except ValueError:
        raise LoginError(f"the redirect's query string could not be read: {_RETRY}") from None
    for name in ("state", "code", "error"):
        if len(query.get(name, [])) > 1:
            raise LoginError(f"the redirect repeats the {name} parameter, so it is ambiguous: {_RETRY}")
    state = query.get("state", [""])[0]
    if not state:
        raise LoginError(f"the redirect carried no state, so it did not come from this login: {_RETRY}")
    if not secrets.compare_digest(state.encode(), expected_state.encode()):
        raise LoginError(f"the redirect's state does not match this login (a stale tab or a forged request): {_RETRY}")
    error = query.get("error", [""])[0]
    if error:
        shown = error if _ERROR_CODE_RE.fullmatch(error) else "an unrecognized error"
        raise LoginError(f"Google refused the authorization ({shown}): {_ERROR_HINTS.get(error, _RETRY)}")
    code = query.get("code", [""])[0]
    if not code:
        raise LoginError(f"the redirect carried no authorization code: {_RETRY}")
    register_secret(code)
    return code


_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="color-scheme" content="light dark">
<title>{title}</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 38rem; margin: 3rem auto; line-height: 1.5">
<h1>{title}</h1><p>{text}</p></body></html>
"""


class _CallbackServer(HTTPServer):
    """A one-shot HTTP server on the loopback interface that captures the redirect."""

    # Never share the port: SO_REUSEPORT would let another local process bind it too and
    # receive the redirect (the authorization code).
    allow_reuse_address = False
    allow_reuse_port = False

    def __init__(self, expected_state: str, read_timeout: float) -> None:
        self.expected_state = expected_state
        self.read_timeout = read_timeout
        self.code: str | None = None
        self.refusal: LoginError | None = None
        self.connected = False
        super().__init__((LOOPBACK_HOST, 0), _CallbackHandler)

    @property
    def redirect_uri(self) -> str:
        return f"http://{LOOPBACK_HOST}:{self.server_port}{CALLBACK_PATH}"

    def finish_request(self, request: Any, client_address: Any) -> None:
        self.connected = True
        super().finish_request(request, client_address)

    def handle_error(self, request: Any, client_address: Any) -> None:
        # socketserver prints the traceback to stderr, and a frame may hold the request line
        # (the code): record a refusal instead, and print nothing.
        if self.code is None and self.refusal is None:
            self.refusal = LoginError(f"the redirect could not be read: {_RETRY}")

    def wait_for_code(self, timeout: float) -> str:
        """Serve exactly one request (or time out), then return the code or raise `LoginError`."""
        self.timeout = timeout
        self.handle_request()
        if self.refusal is not None:
            raise self.refusal
        if self.code is not None:
            return self.code
        if self.connected:
            raise LoginError(
                "the one request the listener accepted was not Google's redirect (no GET request arrived): "
                f"{_RETRY} and finish it in the browser it opens"
            )
        raise LoginError(
            f"no redirect from Google within {timeout:g} s: {_RETRY} and finish the consent in the browser"
        )


class _CallbackHandler(BaseHTTPRequestHandler):
    """Answers the redirect with a short page; logs nothing (the request line holds the code)."""

    server_version = PROG

    def _callback_server(self) -> _CallbackServer:
        server = self.server
        if not isinstance(server, _CallbackServer):  # pragma: no cover - only _CallbackServer uses it
            raise TypeError("the callback handler needs a _CallbackServer")
        return server

    def setup(self) -> None:
        super().setup()
        # A connection that never sends its request (a browser preconnect) must not hang the login.
        self.connection.settimeout(self._callback_server().read_timeout)

    def do_GET(self) -> None:
        server = self._callback_server()
        try:
            server.code = parse_callback(self.path, server.expected_state)
        except LoginError as exc:
            server.refusal = exc
            self._page(400, "Login refused", f"{exc}. The token was not created; check the terminal.")
            return
        self._page(
            200,
            "Signed in",
            f"{PROG} received Google's answer. Return to the terminal: it checks the account and writes the "
            "token file. You can close this tab.",
        )

    def _page(self, status: int, title: str, text: str) -> None:
        body = _PAGE.format(title=html.escape(title), text=html.escape(redact(text))).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        """Silenced: http.server would print the request line, query string (the code) included."""


@contextlib.contextmanager
def listen(expected_state: str, *, read_timeout: float = REQUEST_READ_TIMEOUT_SECONDS) -> Iterator[_CallbackServer]:
    """A callback server bound to 127.0.0.1 on a random free port, closed on exit."""
    try:
        server = _CallbackServer(expected_state, read_timeout)
    except OSError as exc:
        raise LoginError(
            f"could not open a listener on {LOOPBACK_HOST} ({exc.strerror or type(exc).__name__})"
        ) from None
    try:
        yield server
    finally:
        server.server_close()


# --- --out ---------------------------------------------------------------------------------


def git_work_tree(directory: Path) -> Path | None:
    """The closest ancestor of `directory` (itself included) that holds a `.git`, or `None`.

    Checked on the path as written and on its resolved form, so a symlinked directory that
    points into a repository is caught too.
    """
    candidates = [Path(os.path.abspath(directory))]
    resolved = directory.resolve()
    if resolved != candidates[0]:
        candidates.append(resolved)
    for start in candidates:
        for ancestor in (start, *start.parents):
            if os.path.lexists(ancestor / ".git"):
                return ancestor
    return None


def _first_existing(directory: Path) -> Path:
    for ancestor in (directory, *directory.parents):
        if os.path.lexists(ancestor):
            return ancestor
    return Path(directory.anchor)  # pragma: no cover - the root always exists


def check_out_path(out: str | os.PathLike[str], *, force: bool) -> Path:
    """`--out` as an absolute path, or `LoginError` — checked before the browser opens."""
    text = os.fspath(out)
    if not text.strip():
        raise LoginError("--out is empty: name the token file, e.g. ~/.config/amazing-gmail-mcp/company.token.json")
    path = Path(os.path.abspath(Path(text).expanduser()))
    if os.path.isdir(path):
        raise LoginError(f"--out {path} is a directory: name the token file, e.g. {path / 'company.token.json'}")
    repo = git_work_tree(path.parent)
    if repo is not None:
        raise LoginError(
            f"--out {path} is inside the git work tree {repo}: a token there is one `git add` away from a commit; "
            "write it outside any repository, e.g. ~/.config/amazing-gmail-mcp/"
        )
    if os.path.lexists(path) and not force:
        raise LoginError(f"{path} already exists: pass --force to replace it")
    existing = _first_existing(path.parent)
    if not existing.is_dir() or not os.access(existing, os.W_OK | os.X_OK):
        raise LoginError(f"cannot create {path}: {existing} is not a writable directory")
    return path


def _make_private_dirs(directory: Path) -> None:
    """Create the missing directories of `directory`, each 0700 (umask notwithstanding)."""
    missing: list[Path] = []
    for ancestor in (directory, *directory.parents):
        if os.path.lexists(ancestor):
            break
        missing.append(ancestor)
    for path in reversed(missing):
        os.mkdir(path, DIR_MODE)
        os.chmod(path, DIR_MODE)


def _fsync_directory(directory: Path) -> None:
    with contextlib.suppress(OSError):
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def write_token_file(path: Path, payload: Mapping[str, str], *, force: bool) -> None:
    """Write `payload` as JSON to `path`, mode 0600, atomically; never replace a file without `force`.

    The JSON goes to a temp file in the same directory first. With `force` it is renamed
    over `path`; without, it is hard-linked to `path`, which fails if `path` appeared in the
    meantime, so a file is never replaced by accident even in a race.
    """
    data = (json.dumps(dict(payload), indent=2) + "\n").encode("utf-8")
    try:
        _make_private_dirs(path.parent)
        fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    except OSError as exc:
        raise LoginError(
            f"could not write {path} ({exc.strerror or type(exc).__name__}): nothing was written"
        ) from None
    tmp = Path(tmp_name)
    try:
        os.fchmod(fd, FILE_MODE)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if force:
            os.replace(tmp, path)
        else:
            try:
                os.link(tmp, path)
            except FileExistsError:
                raise LoginError(f"{path} already exists: pass --force to replace it") from None
    except OSError as exc:
        raise LoginError(
            f"could not write {path} ({exc.strerror or type(exc).__name__}): nothing was written"
        ) from None
    finally:
        tmp.unlink(missing_ok=True)
    _fsync_directory(path.parent)


def fingerprint(token: str) -> str:
    """The first 8 hex characters of sha256(token): tells two tokens apart, reveals nothing."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:FINGERPRINT_HEX_CHARS]


# --- inputs ----------------------------------------------------------------------------------


def _check_account(account: str) -> str:
    value = account.strip()
    local, at, domain = value.partition("@")
    if not at or not local or "@" in domain or "." not in domain.strip(".") or any(c.isspace() for c in value):
        raise LoginError(
            f"--account {value!r} is not an email address: pass the mailbox to log in as, e.g. you@example.com"
        )
    return value


def _client(client_secret_file: str) -> ClientCredentials:
    if not client_secret_file.strip():
        raise LoginError("--client-secret-file is empty: pass the Desktop client JSON downloaded from Google Cloud")
    try:
        credentials = load_client_credentials(secret_file=client_secret_file, client_id=None, client_secret=None)
    except ValueError as exc:
        raise LoginError(str(exc).replace("GMAIL_CLIENT_SECRET_FILE", "--client-secret-file")) from None
    register_secret(credentials.client_secret.get_secret_value())
    return credentials


# --- Google ----------------------------------------------------------------------------------


def _json_object(resp: httpx.Response) -> dict[str, Any] | None:
    try:
        body = resp.json()
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


def _exchange_code(
    http: httpx.Client, credentials: ClientCredentials, *, code: str, verifier: str, redirect_uri: str
) -> dict[str, Any]:
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": verifier,
        "redirect_uri": redirect_uri,
        "client_id": credentials.client_id,
        "client_secret": credentials.client_secret.get_secret_value(),
    }
    try:
        resp = http.post(TOKEN_URL, data=form, headers={"accept": "application/json"})
    except httpx.HTTPError as exc:
        raise LoginError(
            f"could not reach Google's token endpoint ({type(exc).__name__}): check the network and {_RETRY}"
        ) from None
    body = _json_object(resp)
    if body is None:
        raise LoginError(f"the token endpoint answered HTTP {resp.status_code} without a JSON object: {_RETRY}")
    for key in ("access_token", "refresh_token", "id_token"):
        value = body.get(key)
        if isinstance(value, str):
            register_secret(value, rotating=key != "refresh_token")
    if resp.status_code != 200:
        raise _grant_error(resp.status_code, body)
    return body


def _grant_error(status: int, body: Mapping[str, Any]) -> LoginError:
    code = str(body.get("error") or "")
    # Redacted BEFORE the cut: a secret cut in half matches neither its value nor its shape.
    description = one_line(redact(str(body.get("error_description") or "")))[:200]
    detail = f": {description}" if description else ""
    if code == "invalid_grant":
        return LoginError(
            f"Google refused the authorization code (invalid_grant{detail}): it expired, was already used, or the "
            f"redirect did not match; {_RETRY}"
        )
    if code in {"invalid_client", "unauthorized_client"}:
        return LoginError(
            f"Google rejected the OAuth client ({code}{detail}): --client-secret-file must be the Desktop client JSON "
            "of the company's Cloud project"
        )
    label = f" ({code}{detail})" if code else ""
    return LoginError(f"the token endpoint answered HTTP {status}{label}: {_RETRY}")


def _profile_email(http: httpx.Client, access_token: str) -> str:
    try:
        resp = http.get(PROFILE_URL, headers={"authorization": f"Bearer {access_token}", "accept": "application/json"})
    except httpx.HTTPError as exc:
        raise LoginError(
            f"could not reach the Gmail API ({type(exc).__name__}) to check the account: nothing was written; "
            f"check the network and {_RETRY}"
        ) from None
    body = _json_object(resp) or {}
    if resp.status_code != 200:
        raise LoginError(
            f"could not read the Gmail profile ({_profile_problem(resp.status_code, body)}): nothing was written"
        )
    email = body.get("emailAddress")
    if not isinstance(email, str) or not email.strip():
        raise LoginError(f"the Gmail profile has no emailAddress: nothing was written; {_RETRY}")
    return email.strip()


def _profile_problem(status: int, body: Mapping[str, Any]) -> str:
    error = body.get("error")
    reason = ""
    if isinstance(error, dict):
        details = error.get("errors")
        if isinstance(details, list) and details and isinstance(details[0], dict):
            reason = str(details[0].get("reason") or "")
        reason = reason or str(error.get("status") or "")
    label = f"HTTP {status}" + (f" {reason}" if reason and _ERROR_CODE_RE.fullmatch(reason) else "")
    if status == 403 and reason in {"accessNotConfigured", "SERVICE_DISABLED"}:
        return f"{label}; enable the Gmail API in the client's Cloud project and {_RETRY}"
    if status == 403:
        return f"{label}; the Workspace admin may block this client (Admin console → Security → API controls)"
    return f"{label}; {_RETRY}"


# --- the flow --------------------------------------------------------------------------------


def _say(text: str) -> None:
    sys.stderr.write(redact(text) + "\n")
    sys.stderr.flush()


def _open(url: str, opener: Callable[[str], object]) -> None:
    try:
        opened = opener(url)
    except Exception:  # webbrowser.Error, OSError: the printed URL is the fallback
        opened = False
    if opened is False:
        _say("Could not open a browser: open the URL above by hand, on this machine.")


def login(
    *,
    account: str,
    client_secret_file: str,
    out: str | os.PathLike[str],
    force: bool = False,
    transport: httpx.BaseTransport | None = None,
    open_browser: Callable[[str], object] | None = None,
    timeout: float = CALLBACK_TIMEOUT_SECONDS,
) -> LoginResult:
    """Run the whole flow; return where the token went, or raise `LoginError` having written nothing.

    `transport` and `open_browser` exist for tests (an `httpx.MockTransport`, a fake browser
    that hits the callback in-process); the CLI uses the network and `webbrowser.open`.
    """
    account = _check_account(account)
    credentials = _client(client_secret_file)
    target = check_out_path(out, force=force)

    verifier, challenge = pkce_pair()
    register_secret(verifier)
    state = new_state()
    with listen(state, read_timeout=min(timeout, REQUEST_READ_TIMEOUT_SECONDS)) as server:
        redirect_uri = server.redirect_uri
        url = authorization_url(
            client_id=credentials.client_id,
            redirect_uri=redirect_uri,
            account=account,
            state=state,
            challenge=challenge,
        )
        _say(
            f"{PROG}: signing in as {account} (scope gmail.readonly only).\n"
            "Opening the browser; if it does not open, visit this URL on this machine:\n\n"
            f"  {url}\n\n"
            f"Waiting up to {timeout:g} s for Google's redirect to {redirect_uri} …"
        )
        _open(url, open_browser if open_browser is not None else webbrowser.open)
        code = server.wait_for_code(timeout)

    with httpx.Client(timeout=HTTP_TIMEOUT_SECONDS, transport=transport) as http:
        body = _exchange_code(http, credentials, code=code, verifier=verifier, redirect_uri=redirect_uri)
        access_token = body.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise LoginError(f"the token endpoint answered without an access_token: nothing was written; {_RETRY}")
        granted = body.get("scope")
        problem = scope_problem(granted if isinstance(granted, str) else None)
        if problem is not None:
            raise LoginError(
                f"refusing to save the token: {problem}. Nothing was written; if Google keeps granting more, remove "
                f"this client's access at {_PERMISSIONS_URL} and log in again"
            )
        refresh_token = body.get("refresh_token")
        if not isinstance(refresh_token, str) or not refresh_token:
            raise LoginError(
                "Google returned no refresh token (prompt=consent should force one): nothing was written; remove this "
                f"client's access at {_PERMISSIONS_URL} and {_RETRY}"
            )
        email = _profile_email(http, access_token)

    if email.casefold() != account.casefold():
        raise LoginError(
            f"Google signed in {email}, not {account}: nothing was written; run again and choose {account} in "
            "Google's account chooser"
        )
    payload = {
        "account": email,
        "client_id": credentials.client_id,
        "refresh_token": refresh_token,
        "scope": " ".join(sorted(set(str(granted).split()))),
        "created_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    write_token_file(target, payload, force=force)
    return LoginResult(path=target, fingerprint=fingerprint(refresh_token), account=email)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Mint the gmail.readonly refresh token for one mailbox (once per company, from a Mac) and write it to a "
            "0600 JSON file. Only the file's path and the token's fingerprint are printed."
        ),
    )
    parser.add_argument("--account", required=True, help="the mailbox to log in as, e.g. ops@example.com")
    parser.add_argument(
        "--client-secret-file",
        required=True,
        help="the Desktop OAuth client JSON of the company's Google Cloud project",
    )
    parser.add_argument(
        "--out",
        required=True,
        help="the token file to write (mode 0600), outside any git work tree, e.g. "
        "~/.config/amazing-gmail-mcp/company.token.json",
    )
    parser.add_argument("--force", action="store_true", help="replace --out if it already exists")
    return parser


def _fail(message: str, status: int = 1) -> NoReturn:
    sys.stderr.write(f"{PROG}: {one_line(redact(message))}\n")
    raise SystemExit(status)


def main(
    argv: Sequence[str] | None = None,
    *,
    transport: httpx.BaseTransport | None = None,
    open_browser: Callable[[str], object] | None = None,
    timeout: float = CALLBACK_TIMEOUT_SECONDS,
) -> None:
    """Entry point of `amazing-gmail-mcp-login` (exit 0 written, 1 refused/failed, 2 usage, 130 cancelled)."""
    args = build_parser().parse_args(argv)
    try:
        result = login(
            account=args.account,
            client_secret_file=args.client_secret_file,
            out=args.out,
            force=args.force,
            transport=transport,
            open_browser=open_browser,
            timeout=timeout,
        )
    except KeyboardInterrupt:
        _fail("cancelled: nothing was written", 130)
    except LoginError as exc:
        _fail(str(exc))
    except Exception as exc:  # never a traceback: a frame could hold a token
        # Redacted BEFORE the cut (then again by _fail): a cut secret would match nothing.
        _fail(f"unexpected failure ({type(exc).__name__}): {redact(str(exc))[:300]}; nothing was written")
    else:
        sys.stdout.write(f"wrote {result.path}\nrefresh token fingerprint sha256:{result.fingerprint}\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
