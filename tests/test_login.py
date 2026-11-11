"""login.py: `amazing-gmail-mcp-login` end to end, with no browser and no network.

The browser is played by `Browser`: it reads the authorization URL the CLI opens and hits the
loopback callback from a thread, in this process. Google's token endpoint and the Gmail
profile are `FakeGoogle` behind an `httpx.MockTransport`. Two autouse guards make a slip
loud: a real `webbrowser` call or a real HTTP request fails the test.

Every test runs under `output`, which captures stdout, stderr (at the fd level) and every
log record, and fails if a secret — the refresh token, an access token, the authorization
code, the PKCE verifier, the client secret — or the code on the callback page shows up.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import logging
import os
import re
import socket
import stat
import subprocess
import sys
import threading
import time
import webbrowser
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, quote_plus, urlencode, urlsplit

import httpx
import pytest

import gmail_mcp.auth as auth_module
import gmail_mcp.login as login_module
from gmail_mcp.auth import READONLY_SCOPE, TOKEN_URL, scope_problem
from gmail_mcp.client import API_BASE
from gmail_mcp.errors import register_secret
from gmail_mcp.login import (
    AUTH_URL,
    LoginError,
    LoginResult,
    authorization_url,
    check_out_path,
    code_challenge,
    fingerprint,
    git_work_tree,
    listen,
    login,
    main,
    new_state,
    parse_callback,
    pkce_pair,
    write_token_file,
)

from .fakes import (
    ACCOUNT,
    FAKE_CLIENT_ID,
    FAKE_CLIENT_SECRET,
    FAKE_NEW_REFRESH_TOKEN,
    FAKE_REFRESH_TOKEN,
    FULL_MAIL,
    GMAIL_COMPOSE,
    GMAIL_MODIFY,
    OTHER_ACCOUNT,
    SHAPELESS_SECRET,
    USERINFO_EMAIL,
    FakeGoogle,
    api_error,
    fake_access_token,
    form_body,
    oauth_error,
    token_body,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
# An authorization-code shape, joined at runtime (see test_fixtures_hygiene.py).
CODE = "4" + "/" + "0AeanS0FAKEloginCode0123456789abcdef"
PROFILE_URL = f"{API_BASE}/users/me/profile"
_VERIFIER_RE = re.compile(r"[A-Za-z0-9._~-]{43,128}")


# --- guards and capture --------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_real_browser_and_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_browser(*args: object, **kwargs: object) -> bool:
        raise AssertionError("a test tried to open a real browser")

    def no_network(self: object, request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"a test tried a real HTTP request to {request.url.host}")

    for name in ("open", "open_new", "open_new_tab"):
        monkeypatch.setattr(webbrowser, name, no_browser)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", no_network)


class Output:
    """Everything the CLI wrote (stdout, stderr, log records, the callback pages), checked for secrets."""

    def __init__(self, capfd: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture) -> None:
        self._capfd = capfd
        self._caplog = caplog
        self.stdout = ""
        self.stderr = ""
        self.fakes: list[FakeGoogle] = []
        self.browsers: list[Browser] = []

    def watch(self, fake: FakeGoogle, browser: Browser) -> None:
        self.fakes.append(fake)
        self.browsers.append(browser)

    def read(self) -> tuple[str, str]:
        """The stdout and stderr written since the last read (after checking them)."""
        out, err = self._capfd.readouterr()
        self.stdout += out
        self.stderr += err
        self.check()
        return out, err

    def _secrets(self) -> dict[str, str]:
        found = {
            "refresh token": FAKE_REFRESH_TOKEN,
            "rotated refresh token": FAKE_NEW_REFRESH_TOKEN,
            "authorization code": CODE,
            "client secret": FAKE_CLIENT_SECRET,
            "access token 1": fake_access_token(1),
            "access token 2": fake_access_token(2),
        }
        for fake in self.fakes:
            for index, request in enumerate(fake.token_requests):
                for verifier in form_body(request).get("code_verifier", []):
                    found[f"PKCE verifier {index}"] = verifier
        return found

    def _forms(self) -> list[tuple[str, str]]:
        # Raw and percent-encoded: a logged request line carries the code as `4%2F0…`, which
        # is also how Google's real redirect encodes it.
        forms: list[tuple[str, str]] = []
        for name, value in self._secrets().items():
            for form in dict.fromkeys((value, quote(value, safe=""), quote_plus(value))):
                forms.append((name, form))
        return forms

    def check(self) -> None:
        out, err = self._capfd.readouterr()
        self.stdout += out
        self.stderr += err
        written = self.stdout + self.stderr + self._caplog.text
        leaked = sorted({name for name, form in self._forms() if form in written})
        # Labels only: a failing assertion must not print the value either.
        assert not leaked, f"secrets on stdout/stderr/logs: {leaked}"
        on_pages = sorted({name for name, form in self._forms() for b in self.browsers if form in b.page})
        assert not on_pages, f"secrets on the callback page: {on_pages}"


@pytest.fixture(autouse=True)
def output(capfd: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture) -> Iterator[Output]:
    caplog.set_level(logging.DEBUG)
    for name in ("httpx", "httpcore", "gmail_mcp"):
        caplog.set_level(logging.DEBUG, logger=name)
    captured = Output(capfd, caplog)
    yield captured
    captured.check()


# --- the fake browser ------------------------------------------------------------------------

Query = Callable[[str], Mapping[str, str | list[str]]]


def _callback_query(state: str) -> dict[str, str | list[str]]:
    return {"state": state, "code": CODE, "scope": READONLY_SCOPE}


class Browser:
    """Plays the browser: reads the authorization URL, then visits the redirect from a thread.

    `query(state)` builds the redirect's query string (default: the right state and a code),
    `path` its path, `method` its method. `mode="silent"` opens a connection and sends
    nothing (a browser preconnect); `mode="none"` never visits (the user walked away).
    `report` is what the opener returns to the CLI (`webbrowser.open` returns a bool).
    """

    def __init__(
        self,
        query: Query = _callback_query,
        *,
        path: str = "/",
        method: str = "GET",
        mode: str = "visit",
        report: object = True,
    ) -> None:
        self.query = query
        self.path = path
        self.method = method
        self.mode = mode
        self.report = report
        self.urls: list[str] = []
        self.status: int | None = None
        self.headers: dict[str, str] = {}
        self.page = ""
        self.error: BaseException | None = None
        self._thread: threading.Thread | None = None

    @property
    def params(self) -> dict[str, list[str]]:
        """The query parameters of the authorization URL the CLI opened."""
        return parse_qs(urlsplit(self.urls[0]).query, keep_blank_values=True)

    @property
    def redirect(self) -> tuple[str, int]:
        target = urlsplit(self.params["redirect_uri"][0])
        assert target.hostname is not None and target.port is not None
        return target.hostname, target.port

    def __call__(self, url: str) -> object:
        self.urls.append(url)
        if self.mode != "none":
            self._thread = threading.Thread(target=self._visit, daemon=True)
            self._thread.start()
        return self.report

    def _visit(self) -> None:
        host, port = self.redirect
        try:
            if self.mode == "silent":
                with socket.create_connection((host, port), timeout=10) as sock:
                    sock.recv(1)  # returns when the listener gives up on this connection
                return
            target = self.path + "?" + urlencode(dict(self.query(self.params["state"][0])), doseq=True)
            connection = http.client.HTTPConnection(host, port, timeout=10)
            connection.request(self.method, target)
            response = connection.getresponse()
            self.status = response.status
            self.headers = {key.lower(): value for key, value in response.getheaders()}
            self.page = response.read().decode("utf-8", errors="replace")
            connection.close()
        except BaseException as exc:  # recorded for the test, never raised in the thread
            self.error = exc

    def join(self) -> None:
        if self._thread is not None:
            self._thread.join(10)
            assert not self._thread.is_alive(), "the browser thread is still waiting on the listener"


# --- helpers ---------------------------------------------------------------------------------


def client_file(tmp_path: Path, content: Any = None) -> Path:
    path = tmp_path / "client_secret_desktop.json"
    data = (
        content
        if content is not None
        else {
            "installed": {
                "client_id": FAKE_CLIENT_ID,
                "client_secret": FAKE_CLIENT_SECRET,
                "redirect_uris": ["http://localhost"],
            }
        }
    )
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    return path


def out_path(tmp_path: Path) -> Path:
    return tmp_path / "cfg" / "company.token.json"


def ok_google(**kwargs: Any) -> FakeGoogle:
    """Google that grants gmail.readonly with a refresh token, for ACCOUNT (unless overridden)."""
    kwargs.setdefault("token_responses", [token_body(1, refresh_token=FAKE_REFRESH_TOKEN)])
    return FakeGoogle(**kwargs)


def attempt(
    output: Output,
    tmp_path: Path,
    *,
    fake: FakeGoogle | None = None,
    browser: Browser | None = None,
    account: str = ACCOUNT,
    out: Path | None = None,
    force: bool = False,
    timeout: float = 5.0,
    client: Path | None = None,
) -> LoginResult:
    fake = fake if fake is not None else ok_google()
    browser = browser if browser is not None else Browser()
    output.watch(fake, browser)
    try:
        return login(
            account=account,
            client_secret_file=str(client if client is not None else client_file(tmp_path)),
            out=str(out if out is not None else out_path(tmp_path)),
            force=force,
            transport=httpx.MockTransport(fake),
            open_browser=browser,
            timeout=timeout,
        )
    finally:
        browser.join()


def refused(output: Output, tmp_path: Path, **kwargs: Any) -> str:
    """Run the flow expecting a refusal; return the one-line message."""
    with pytest.raises(LoginError) as info:
        attempt(output, tmp_path, **kwargs)
    message = str(info.value)
    assert "\n" not in message
    return message


def assert_nothing_written(tmp_path: Path) -> None:
    # The token file's parent is created only when the file is written.
    assert not (tmp_path / "cfg").exists()


def mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


# --- the happy path --------------------------------------------------------------------------


def test_main_writes_the_token_file_and_prints_only_its_path_and_fingerprint(tmp_path: Path, output: Output) -> None:
    fake = ok_google()
    browser = Browser()
    output.watch(fake, browser)
    target = out_path(tmp_path)

    main(
        ["--account", ACCOUNT, "--client-secret-file", str(client_file(tmp_path)), "--out", str(target)],
        transport=httpx.MockTransport(fake),
        open_browser=browser,
        timeout=5.0,
    )
    browser.join()

    stdout, stderr = output.read()
    digest = hashlib.sha256(FAKE_REFRESH_TOKEN.encode()).hexdigest()[:8]
    assert stdout == f"wrote {target}\nrefresh token fingerprint sha256:{digest}\n"
    assert re.fullmatch(r"[0-9a-f]{8}", digest)
    assert browser.urls[0] in stderr  # the URL is printed as well as opened
    saved = json.loads(target.read_text())
    assert list(saved) == ["account", "client_id", "refresh_token", "scope", "created_at"]
    assert saved["account"] == ACCOUNT
    assert saved["client_id"] == FAKE_CLIENT_ID
    assert saved["refresh_token"] == FAKE_REFRESH_TOKEN
    assert saved["scope"] == READONLY_SCOPE
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", saved["created_at"])
    assert mode(target) == 0o600
    assert mode(target.parent) == 0o700
    assert sorted(p.name for p in target.parent.iterdir()) == [target.name]  # no temp file left


def test_the_callback_page_confirms_without_showing_the_code(tmp_path: Path, output: Output) -> None:
    browser = Browser()

    attempt(output, tmp_path, browser=browser)

    assert browser.error is None
    assert browser.status == 200
    assert "Signed in" in browser.page
    assert browser.headers["cache-control"] == "no-store"
    assert browser.headers["referrer-policy"] == "no-referrer"


def test_the_authorization_url_asks_for_gmail_readonly_only(tmp_path: Path, output: Output) -> None:
    browser = Browser()

    attempt(output, tmp_path, browser=browser)

    assert browser.urls[0].startswith(AUTH_URL + "?")
    params = browser.params
    assert all(len(values) == 1 for values in params.values())
    flat = {key: values[0] for key, values in params.items()}
    host, port = browser.redirect
    assert flat == {
        "client_id": FAKE_CLIENT_ID,
        "redirect_uri": f"http://127.0.0.1:{port}/",
        "response_type": "code",
        "scope": READONLY_SCOPE,
        "access_type": "offline",
        "prompt": "consent",
        "login_hint": ACCOUNT,
        "state": flat["state"],
        "code_challenge": flat["code_challenge"],
        "code_challenge_method": "S256",
    }
    assert host == "127.0.0.1" and port > 0
    assert "include_granted_scopes" not in params  # incremental auth would fold in older scopes
    assert len(flat["state"]) >= 43


def test_the_code_exchange_carries_the_verifier_of_the_challenge_and_the_same_redirect(
    tmp_path: Path, output: Output
) -> None:
    fake = ok_google()
    browser = Browser()

    attempt(output, tmp_path, fake=fake, browser=browser)

    [request] = fake.token_requests
    assert request.method == "POST"
    assert str(request.url) == TOKEN_URL
    form = form_body(request)
    verifier = form["code_verifier"][0]
    assert _VERIFIER_RE.fullmatch(verifier)
    assert code_challenge(verifier) == browser.params["code_challenge"][0]
    assert form == {
        "grant_type": ["authorization_code"],
        "code": [CODE],
        "code_verifier": [verifier],
        "redirect_uri": browser.params["redirect_uri"],
        "client_id": [FAKE_CLIENT_ID],
        "client_secret": [FAKE_CLIENT_SECRET],
    }


def test_the_profile_check_reads_users_me_profile_with_the_new_access_token(tmp_path: Path, output: Output) -> None:
    fake = ok_google()

    attempt(output, tmp_path, fake=fake)

    assert fake.log == ["token", "GET users/me/profile"]
    [request] = fake.api_requests
    assert str(request.url) == PROFILE_URL
    assert request.headers["authorization"] == f"Bearer {fake_access_token(1)}"


def test_the_listener_is_closed_once_the_flow_returns(tmp_path: Path, output: Output) -> None:
    browser = Browser()

    attempt(output, tmp_path, browser=browser)

    with pytest.raises(ConnectionRefusedError):
        socket.create_connection(browser.redirect, timeout=2).close()


def test_the_listener_binds_loopback_on_a_random_port_and_never_shares_it() -> None:
    with listen(new_state()) as first, listen(new_state()) as second:
        assert first.server_address[0] == "127.0.0.1"
        assert first.server_port > 0 and first.server_port != second.server_port
        assert first.redirect_uri == f"http://127.0.0.1:{first.server_port}/"
        assert first.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) == 0
        assert first.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT) == 0


def test_the_account_is_compared_case_insensitively_and_saved_as_google_spells_it(
    tmp_path: Path, output: Output
) -> None:
    result = attempt(output, tmp_path, fake=ok_google(profile_email="Ops@Example.COM"))

    assert result.account == "Ops@Example.COM"
    assert json.loads(result.path.read_text())["account"] == "Ops@Example.COM"


def test_identity_scopes_next_to_gmail_readonly_are_accepted(tmp_path: Path, output: Output) -> None:
    granted = f"openid {READONLY_SCOPE} {USERINFO_EMAIL}"
    fake = ok_google(token_responses=[token_body(1, scope=granted, refresh_token=FAKE_REFRESH_TOKEN)])

    result = attempt(output, tmp_path, fake=fake)

    assert json.loads(result.path.read_text())["scope"] == " ".join(sorted(granted.split()))


def test_force_replaces_an_existing_token_file(tmp_path: Path, output: Output) -> None:
    target = out_path(tmp_path)
    target.parent.mkdir()
    target.write_text("old")

    attempt(output, tmp_path, force=True)

    assert json.loads(target.read_text())["refresh_token"] == FAKE_REFRESH_TOKEN
    assert mode(target) == 0o600


def test_force_replaces_a_symlink_without_writing_through_it(tmp_path: Path, output: Output) -> None:
    elsewhere = tmp_path / "elsewhere.json"
    elsewhere.write_text("keep")
    target = out_path(tmp_path)
    target.parent.mkdir()
    target.symlink_to(elsewhere)

    attempt(output, tmp_path, force=True)

    assert not target.is_symlink() and mode(target) == 0o600
    assert elsewhere.read_text() == "keep"


def test_an_existing_parent_directory_keeps_its_mode(tmp_path: Path, output: Output) -> None:
    target = out_path(tmp_path)
    target.parent.mkdir(mode=0o755)
    os.chmod(target.parent, 0o755)

    attempt(output, tmp_path)

    assert mode(target.parent) == 0o755
    assert mode(target) == 0o600


def test_missing_parent_directories_are_all_created_0700_whatever_the_umask(tmp_path: Path) -> None:
    target = tmp_path / "a" / "b" / "c" / "company.token.json"
    old = os.umask(0)
    try:
        write_token_file(target, {"refresh_token": "x"}, force=False)
    finally:
        os.umask(old)

    assert [mode(tmp_path / part) for part in ("a", "a/b", "a/b/c")] == [0o700, 0o700, 0o700]
    assert mode(target) == 0o600


def test_main_opens_the_url_with_webbrowser_by_default(
    tmp_path: Path, output: Output, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = ok_google()
    browser = Browser()
    output.watch(fake, browser)
    monkeypatch.setattr(webbrowser, "open", browser)

    main(
        ["--account", ACCOUNT, "--client-secret-file", str(client_file(tmp_path)), "--out", str(out_path(tmp_path))],
        transport=httpx.MockTransport(fake),
        timeout=5.0,
    )
    browser.join()

    assert len(browser.urls) == 1
    assert out_path(tmp_path).exists()


@pytest.mark.parametrize("report", [False, "raise"])
def test_a_browser_that_does_not_open_falls_back_to_the_printed_url(
    tmp_path: Path, output: Output, report: object
) -> None:
    browser = Browser(report=report)

    def opener(url: str) -> object:
        result = browser(url)
        if report == "raise":
            raise webbrowser.Error("no runnable browser")
        return result

    fake = ok_google()
    output.watch(fake, browser)
    login(
        account=ACCOUNT,
        client_secret_file=str(client_file(tmp_path)),
        out=str(out_path(tmp_path)),
        transport=httpx.MockTransport(fake),
        open_browser=opener,
        timeout=5.0,
    )
    browser.join()

    _, stderr = output.read()
    assert "Could not open a browser: open the URL above by hand" in stderr
    assert out_path(tmp_path).exists()


# --- PKCE and state --------------------------------------------------------------------------


def test_code_challenge_matches_rfc7636_appendix_b() -> None:
    # The S256 example of RFC 7636 Appendix B (rfc-editor.org/rfc/rfc7636.txt, lines 942 and 962).
    assert (
        code_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    )


def test_each_login_draws_a_fresh_verifier_and_state_from_secrets() -> None:
    pairs = [pkce_pair() for _ in range(3)]
    states = [new_state() for _ in range(3)]

    for verifier, challenge in pairs:
        assert _VERIFIER_RE.fullmatch(verifier)
        digest = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        assert challenge == digest
    assert len({verifier for verifier, _ in pairs}) == 3
    assert len(set(states)) == 3 and all(len(state) >= 43 for state in states)


def test_the_authorization_url_builder_never_adds_scopes() -> None:
    url = authorization_url(
        client_id=FAKE_CLIENT_ID, redirect_uri="http://127.0.0.1:1/", account=ACCOUNT, state="s", challenge="c"
    )

    assert parse_qs(urlsplit(url).query)["scope"] == [READONLY_SCOPE]


# --- the callback: refusals ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        (lambda state: {"state": "x" + state, "code": CODE}, "state does not match this login"),
        (lambda state: {"code": CODE}, "carried no state"),
        (lambda state: {"state": "", "code": CODE}, "carried no state"),
        (lambda state: {"state": state}, "carried no authorization code"),
        (lambda state: {"state": state, "code": ""}, "carried no authorization code"),
        (lambda state: {"state": [state, state], "code": CODE}, "repeats the state parameter"),
        (lambda state: {"state": state, "code": [CODE, CODE + "x"]}, "repeats the code parameter"),
        (lambda state: {"state": state, "error": ["access_denied", "x"]}, "repeats the error parameter"),
    ],
    ids=[
        "state-mismatch",
        "state-missing",
        "state-blank",
        "code-missing",
        "code-blank",
        "dup-state",
        "dup-code",
        "dup-error",
    ],
)
def test_a_bad_redirect_is_refused_and_nothing_reaches_google(
    tmp_path: Path, output: Output, query: Query, expected: str
) -> None:
    fake = ok_google()
    browser = Browser(query)

    message = refused(output, tmp_path, fake=fake, browser=browser)

    assert expected in message
    assert fake.requests == []  # no code exchange, no profile call
    assert browser.status == 400
    assert "Login refused" in browser.page
    assert_nothing_written(tmp_path)


def test_a_state_mismatch_is_refused_even_with_a_valid_looking_code(tmp_path: Path, output: Output) -> None:
    # The forged-redirect case: a request with someone else's state and code.
    fake = ok_google()

    message = refused(output, tmp_path, fake=fake, browser=Browser(lambda state: {"state": new_state(), "code": CODE}))

    assert "forged request" in message
    assert fake.requests == []


@pytest.mark.parametrize(
    ("error", "hint"),
    [
        ("access_denied", "the consent was cancelled"),
        ("admin_policy_enforced", "Admin console → Security → API controls"),
        ("org_internal", "Internal to another Workspace organization"),
        ("temporarily_unavailable", "run the login again"),
    ],
)
def test_an_error_redirect_is_refused_with_its_hint(tmp_path: Path, output: Output, error: str, hint: str) -> None:
    fake = ok_google()
    # Google sends `error` with the state; a stray code must not be used either.
    browser = Browser(lambda state: {"state": state, "error": error, "code": CODE})

    message = refused(output, tmp_path, fake=fake, browser=browser)

    assert f"Google refused the authorization ({error})" in message
    assert hint in message
    assert fake.requests == []
    assert_nothing_written(tmp_path)


def test_an_error_value_that_is_not_an_oauth_code_is_not_echoed(tmp_path: Path, output: Output) -> None:
    browser = Browser(lambda state: {"state": state, "error": "<script>alert(1)</script>"})

    message = refused(output, tmp_path, browser=browser)

    assert "an unrecognized error" in message
    assert "<script>" not in message and "<script>" not in browser.page


def test_a_request_on_another_path_is_refused(tmp_path: Path, output: Output) -> None:
    fake = ok_google()

    message = refused(output, tmp_path, fake=fake, browser=Browser(path="/favicon.ico"))

    assert "was not Google's redirect" in message
    assert fake.requests == []
    assert_nothing_written(tmp_path)


def test_a_non_get_request_is_refused(tmp_path: Path, output: Output) -> None:
    fake = ok_google()
    browser = Browser(method="POST")

    message = refused(output, tmp_path, fake=fake, browser=browser)

    assert "not Google's redirect" in message
    assert browser.status == 501
    assert fake.requests == []


def test_no_redirect_within_the_timeout_is_refused(tmp_path: Path, output: Output) -> None:
    fake = ok_google()

    message = refused(output, tmp_path, fake=fake, browser=Browser(mode="none"), timeout=0.3)

    assert "no redirect from Google within 0.3 s" in message
    assert fake.requests == []
    assert_nothing_written(tmp_path)


def test_a_silent_connection_neither_hangs_the_login_nor_counts_as_a_redirect(tmp_path: Path, output: Output) -> None:
    fake = ok_google()
    started = time.monotonic()

    message = refused(output, tmp_path, fake=fake, browser=Browser(mode="silent"), timeout=1.0)

    # The fake browser holds the connection open for 10 s: only the read timeout ends it sooner.
    assert time.monotonic() - started < 5
    assert "not Google's redirect" in message
    assert fake.requests == []
    assert_nothing_written(tmp_path)


def test_a_crash_while_handling_the_redirect_prints_nothing_and_is_refused(
    tmp_path: Path, output: Output, monkeypatch: pytest.MonkeyPatch
) -> None:
    def crash(target: str, expected_state: str) -> str:
        raise RuntimeError(f"unexpected, while holding {CODE}")

    monkeypatch.setattr(login_module, "parse_callback", crash)
    fake = ok_google()

    message = refused(output, tmp_path, fake=fake)

    # socketserver's default handle_error would print this traceback, the code with it.
    assert "the redirect could not be read" in message
    assert fake.requests == []
    assert_nothing_written(tmp_path)


def test_the_listener_answers_one_request_only() -> None:
    state = new_state()
    with listen(state, read_timeout=2) as server:
        host, port = server.server_address[:2]
        first = http.client.HTTPConnection(str(host), int(port), timeout=5)
        first.request("GET", "/?" + urlencode({"state": state, "code": CODE}))
        second = socket.create_connection((str(host), int(port)), timeout=5)
        assert server.wait_for_code(2) == CODE
        assert first.getresponse().status == 200
    # The second connection was queued but never answered: closing the listener drops it.
    second.settimeout(5)
    try:
        assert second.recv(1) == b""
    except ConnectionResetError:
        pass
    finally:
        second.close()
        first.close()


def test_parse_callback_rejects_an_oversized_query() -> None:
    target = "/?" + "&".join(f"k{i}=v" for i in range(40))

    with pytest.raises(LoginError, match="could not be read"):
        parse_callback(target, "state")


# --- after the code: Google's answers --------------------------------------------------------


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (oauth_error("invalid_grant", description="Malformed auth code."), "invalid_grant: Malformed auth code."),
        (oauth_error("invalid_client", status=401), "Google rejected the OAuth client (invalid_client)"),
        (oauth_error("unauthorized_client", status=400), "--client-secret-file must be the Desktop client JSON"),
        (oauth_error("server_error", status=500), "the token endpoint answered HTTP 500 (server_error)"),
        (httpx.Response(502, text="<html>bad gateway</html>"), "answered HTTP 502 without a JSON object"),
        (httpx.Response(200, json=["not", "an", "object"]), "answered HTTP 200 without a JSON object"),
    ],
    ids=["invalid_grant", "invalid_client", "unauthorized_client", "500", "html", "json-list"],
)
def test_a_failed_code_exchange_writes_nothing(
    tmp_path: Path, output: Output, response: httpx.Response, expected: str
) -> None:
    fake = ok_google(token_responses=[response])

    message = refused(output, tmp_path, fake=fake)

    assert expected in message
    assert fake.log == ["token"]  # no profile call
    assert_nothing_written(tmp_path)


def test_an_error_description_is_redacted_before_it_is_cut(tmp_path: Path, output: Output) -> None:
    # The PKCE verifier is registered but has no token shape: cut in half at char 200, the
    # kept prefix would match nothing. Here Google echoes it right across the cut.
    def echo_the_verifier(request: httpx.Request) -> httpx.Response:
        verifier = form_body(request)["code_verifier"][0]
        return oauth_error("invalid_grant", description="x" * 190 + verifier + " end")

    fake = ok_google(token_responses=[echo_the_verifier])

    message = refused(output, tmp_path, fake=fake)

    verifier = form_body(fake.token_requests[0])["code_verifier"][0]
    assert verifier[:10] not in message and verifier[-10:] not in message
    assert "invalid_grant: " + "x" * 190 + "*** end)" in message
    assert_nothing_written(tmp_path)


def test_an_unreachable_token_endpoint_writes_nothing(tmp_path: Path, output: Output) -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    message = refused(output, tmp_path, fake=ok_google(token_responses=[down]))

    assert "could not reach Google's token endpoint (ConnectError)" in message
    assert_nothing_written(tmp_path)


def test_a_token_response_without_an_access_token_writes_nothing(tmp_path: Path, output: Output) -> None:
    body = {"refresh_token": FAKE_REFRESH_TOKEN, "scope": READONLY_SCOPE, "expires_in": 3599}
    fake = ok_google(token_responses=[body])

    message = refused(output, tmp_path, fake=fake)

    assert "without an access_token" in message
    assert fake.log == ["token"]
    assert_nothing_written(tmp_path)


@pytest.mark.parametrize(
    "granted",
    [
        GMAIL_MODIFY,
        GMAIL_COMPOSE,
        FULL_MAIL,
        f"{READONLY_SCOPE} {GMAIL_MODIFY}",
        f"{READONLY_SCOPE} https://www.googleapis.com/auth/drive.readonly",
        f"openid {USERINFO_EMAIL}",
        "",
        None,
    ],
    ids=["modify", "compose", "full-mail", "readonly+modify", "readonly+drive", "identity-only", "empty", "absent"],
)
def test_a_token_granted_anything_but_gmail_readonly_is_not_saved(
    tmp_path: Path, output: Output, granted: str | None
) -> None:
    fake = ok_google(token_responses=[token_body(1, scope=granted, refresh_token=FAKE_REFRESH_TOKEN)])

    message = refused(output, tmp_path, fake=fake)

    # The same rule the server applies at every refresh (auth.scope_problem), not a copy of it.
    assert login_module.scope_problem is auth_module.scope_problem
    problem = scope_problem(granted)
    assert problem is not None
    assert message.startswith(f"refusing to save the token: {problem}. Nothing was written")
    assert fake.log == ["token"]  # the over-scoped token is never used, not even for the profile
    assert_nothing_written(tmp_path)


@pytest.mark.parametrize("refresh", [None, ""], ids=["absent", "empty"])
def test_a_response_without_a_refresh_token_is_a_clear_error(
    tmp_path: Path, output: Output, refresh: str | None
) -> None:
    extra = {} if refresh is None else {"refresh_token": refresh}
    fake = ok_google(token_responses=[token_body(1, **extra)])

    message = refused(output, tmp_path, fake=fake)

    assert "Google returned no refresh token" in message
    assert "myaccount.google.com/permissions" in message
    assert fake.log == ["token"]
    assert_nothing_written(tmp_path)


def test_a_token_for_another_mailbox_is_not_saved(tmp_path: Path, output: Output) -> None:
    fake = ok_google(profile_email=OTHER_ACCOUNT)

    message = refused(output, tmp_path, fake=fake)

    assert message.startswith(f"Google signed in {OTHER_ACCOUNT}, not {ACCOUNT}: nothing was written")
    assert f"choose {ACCOUNT}" in message
    assert_nothing_written(tmp_path)


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        (
            api_error(403, "accessNotConfigured", "Gmail API has not been used"),
            "HTTP 403 accessNotConfigured; enable the Gmail API",
        ),
        (api_error(403, "domainPolicy", "blocked"), "HTTP 403 domainPolicy; the Workspace admin may block this client"),
        (api_error(401, "authError", "Invalid Credentials"), "HTTP 401 authError; run the login again"),
        (api_error(500), "HTTP 500 backendError; run the login again"),
        (httpx.Response(503, text="unavailable"), "HTTP 503; run the login again"),
        (httpx.Response(200, json={"messagesTotal": 1}), "the Gmail profile has no emailAddress"),
    ],
    ids=["api-disabled", "admin-block", "401", "500", "non-json", "no-email"],
)
def test_a_profile_that_cannot_be_read_writes_nothing(
    tmp_path: Path, output: Output, response: httpx.Response, expected: str
) -> None:
    fake = ok_google(routes={"users/me/profile": response})

    message = refused(output, tmp_path, fake=fake)

    assert expected in message
    assert "nothing was written" in message
    assert_nothing_written(tmp_path)


def test_an_unreachable_gmail_api_writes_nothing(tmp_path: Path, output: Output) -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timed out", request=request)

    message = refused(output, tmp_path, fake=ok_google(routes={"users/me/profile": down}))

    assert "could not reach the Gmail API (ReadTimeout)" in message
    assert_nothing_written(tmp_path)


# --- before the browser: inputs ----------------------------------------------------------------


def _assert_browser_never_opened(browser: Browser, fake: FakeGoogle) -> None:
    assert browser.urls == []
    assert fake.requests == []


def test_an_existing_token_file_is_never_replaced_without_force(tmp_path: Path, output: Output) -> None:
    target = out_path(tmp_path)
    target.parent.mkdir()
    target.write_text("old")
    fake, browser = ok_google(), Browser()

    message = refused(output, tmp_path, fake=fake, browser=browser)

    assert message == f"{target} already exists: pass --force to replace it"
    assert target.read_text() == "old"
    _assert_browser_never_opened(browser, fake)


def test_a_dangling_symlink_at_out_counts_as_an_existing_file(tmp_path: Path, output: Output) -> None:
    target = out_path(tmp_path)
    target.parent.mkdir()
    target.symlink_to(tmp_path / "nowhere")

    message = refused(output, tmp_path)

    assert "already exists" in message


@pytest.mark.parametrize("dot_git", ["dir", "file"], ids=["repo", "worktree"])
def test_out_inside_a_git_work_tree_is_refused(tmp_path: Path, output: Output, dot_git: str) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    if dot_git == "dir":
        (repo / ".git").mkdir()
    else:
        (repo / ".git").write_text("gitdir: /elsewhere/.git/worktrees/x\n")
    target = repo / "deep" / "er" / "company.token.json"
    fake, browser = ok_google(), Browser()

    message = refused(output, tmp_path, fake=fake, browser=browser, out=target)

    assert f"is inside the git work tree {repo}" in message
    assert not (repo / "deep").exists()
    _assert_browser_never_opened(browser, fake)


def test_out_inside_this_very_checkout_is_refused(tmp_path: Path, output: Output) -> None:
    target = REPO_ROOT / f"t4-probe-{os.getpid()}.token.json"
    try:
        message = refused(output, tmp_path, out=target)

        assert "is inside the git work tree" in message
        assert not target.exists()
    finally:
        # Even a broken check must not leave a (fake) token file in the checkout.
        target.unlink(missing_ok=True)


def test_out_under_a_symlink_into_a_git_work_tree_is_refused(tmp_path: Path, output: Output) -> None:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "secrets").mkdir()
    link = tmp_path / "looks-safe"
    link.symlink_to(repo / "secrets")

    message = refused(output, tmp_path, out=link / "company.token.json")

    assert "is inside the git work tree" in message
    assert list((repo / "secrets").iterdir()) == []


def test_git_work_tree_finds_the_closest_ancestor_or_none(tmp_path: Path) -> None:
    (tmp_path / "repo" / ".git").mkdir(parents=True)

    assert git_work_tree(tmp_path / "repo" / "a" / "b") == tmp_path / "repo"
    assert git_work_tree(tmp_path / "elsewhere" / "a") is None


def test_out_that_is_a_directory_is_refused(tmp_path: Path, output: Output) -> None:
    (tmp_path / "cfg").mkdir()

    message = refused(output, tmp_path, out=tmp_path / "cfg", force=True)

    assert "is a directory: name the token file" in message


def test_out_under_a_regular_file_is_refused(tmp_path: Path, output: Output) -> None:
    (tmp_path / "file").write_text("x")
    fake, browser = ok_google(), Browser()

    message = refused(output, tmp_path, fake=fake, browser=browser, out=tmp_path / "file" / "company.token.json")

    assert "is not a writable directory" in message
    _assert_browser_never_opened(browser, fake)


def test_an_empty_out_is_refused() -> None:
    with pytest.raises(LoginError, match="--out is empty"):
        check_out_path("  ", force=False)


@pytest.mark.parametrize(
    "account",
    ["ops", "ops@", "@example.com", "ops@example", "ops@.", "a b@example.com", "a@b@example.com", ""],
)
def test_an_account_that_is_not_an_email_is_refused_before_the_browser(
    tmp_path: Path, output: Output, account: str
) -> None:
    fake, browser = ok_google(), Browser()

    message = refused(output, tmp_path, fake=fake, browser=browser, account=account)

    assert "is not an email address" in message
    _assert_browser_never_opened(browser, fake)


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (None, "--client-secret-file points to"),
        ("{not json", "is not JSON"),
        ({"web": {"client_id": FAKE_CLIENT_ID, "client_secret": FAKE_CLIENT_SECRET}}, "is not a Desktop OAuth client"),
        ({"installed": {"client_id": FAKE_CLIENT_ID}}, "lacks client_secret"),
    ],
    ids=["missing", "not-json", "web-client", "no-secret"],
)
def test_a_bad_client_file_is_refused_before_the_browser(
    tmp_path: Path, output: Output, content: Any, expected: str
) -> None:
    fake, browser = ok_google(), Browser()
    path = tmp_path / "missing.json" if content is None else client_file(tmp_path, content)

    message = refused(output, tmp_path, fake=fake, browser=browser, client=path)

    assert expected in message
    assert "GMAIL_CLIENT_SECRET_FILE" not in message  # the CLI names its own flag
    assert FAKE_CLIENT_SECRET not in message
    _assert_browser_never_opened(browser, fake)


def test_an_empty_client_secret_file_flag_is_refused(tmp_path: Path, output: Output) -> None:
    with pytest.raises(LoginError, match="--client-secret-file is empty"):
        login(account=ACCOUNT, client_secret_file=" ", out=str(out_path(tmp_path)), open_browser=Browser())


# --- the write ---------------------------------------------------------------------------------


def test_a_file_that_appears_during_the_flow_is_not_replaced_without_force(tmp_path: Path) -> None:
    target = check_out_path(out_path(tmp_path), force=False)
    target.parent.mkdir()
    target.write_text("appeared meanwhile")

    with pytest.raises(LoginError, match="already exists: pass --force"):
        write_token_file(target, {"refresh_token": FAKE_REFRESH_TOKEN}, force=False)

    assert target.read_text() == "appeared meanwhile"
    assert [p.name for p in target.parent.iterdir()] == [target.name]  # the temp file is gone


@pytest.mark.skipif(os.geteuid() == 0, reason="root writes through directory permissions")
def test_an_unwritable_directory_is_a_clear_error(tmp_path: Path) -> None:
    locked = tmp_path / "locked"
    locked.mkdir()
    os.chmod(locked, 0o500)
    try:
        with pytest.raises(LoginError, match="could not write .*nothing was written"):
            write_token_file(locked / "company.token.json", {"refresh_token": FAKE_REFRESH_TOKEN}, force=False)
    finally:
        os.chmod(locked, 0o700)


def test_the_fingerprint_is_8_hex_of_sha256() -> None:
    assert fingerprint("abc") == hashlib.sha256(b"abc").hexdigest()[:8] == "ba7816bf"


# --- main: exit codes and what reaches the terminal --------------------------------------------


def test_main_reports_a_refusal_on_one_redacted_line_and_exits_1(tmp_path: Path, output: Output) -> None:
    fake = ok_google(profile_email=OTHER_ACCOUNT)
    browser = Browser()
    output.watch(fake, browser)

    with pytest.raises(SystemExit) as info:
        main(
            [
                "--account",
                ACCOUNT,
                "--client-secret-file",
                str(client_file(tmp_path)),
                "--out",
                str(out_path(tmp_path)),
            ],
            transport=httpx.MockTransport(fake),
            open_browser=browser,
            timeout=5.0,
        )
    browser.join()

    assert info.value.code == 1
    stdout, stderr = output.read()
    assert stdout == ""
    last = stderr.rstrip("\n").splitlines()[-1]
    assert last.startswith(f"amazing-gmail-mcp-login: Google signed in {OTHER_ACCOUNT}, not {ACCOUNT}")
    assert "Traceback" not in stderr
    assert_nothing_written(tmp_path)


def test_main_never_prints_a_traceback_and_redacts_an_unexpected_failure(
    tmp_path: Path, output: Output, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(**kwargs: Any) -> LoginResult:
        raise RuntimeError(f"boom while holding {FAKE_REFRESH_TOKEN} and {CODE}")

    monkeypatch.setattr(login_module, "login", explode)

    with pytest.raises(SystemExit) as info:
        main(["--account", ACCOUNT, "--client-secret-file", "x.json", "--out", str(out_path(tmp_path))])

    assert info.value.code == 1
    _, stderr = output.read()
    assert stderr.startswith("amazing-gmail-mcp-login: unexpected failure (RuntimeError): boom while holding ***")
    assert "Traceback" not in stderr


def test_main_redacts_an_unexpected_failure_before_cutting_it(
    tmp_path: Path, output: Output, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A registered, shapeless secret straddling char 300: cut first, its prefix would print.
    def explode(**kwargs: Any) -> LoginResult:
        register_secret(SHAPELESS_SECRET)
        raise RuntimeError("y" * 290 + SHAPELESS_SECRET + " tail")

    monkeypatch.setattr(login_module, "login", explode)

    with pytest.raises(SystemExit) as info:
        main(["--account", ACCOUNT, "--client-secret-file", "x.json", "--out", str(out_path(tmp_path))])

    assert info.value.code == 1
    _, stderr = output.read()
    assert SHAPELESS_SECRET[:10] not in stderr
    assert "y" * 290 + "*** tail; nothing was written" in stderr


def test_main_exits_130_when_cancelled(tmp_path: Path, output: Output, monkeypatch: pytest.MonkeyPatch) -> None:
    def interrupted(**kwargs: Any) -> LoginResult:
        raise KeyboardInterrupt

    monkeypatch.setattr(login_module, "login", interrupted)

    with pytest.raises(SystemExit) as info:
        main(["--account", ACCOUNT, "--client-secret-file", "x.json", "--out", str(out_path(tmp_path))])

    assert info.value.code == 130
    assert "cancelled: nothing was written" in output.read()[1]


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--account", ACCOUNT],
        ["--account", ACCOUNT, "--client-secret-file", "x.json"],
        ["--client-secret-file", "x.json", "--out", "t.json"],
        ["--account", ACCOUNT, "--client-secret-file", "x.json", "--out", "t.json", "--scope", "gmail.modify"],
    ],
    ids=["nothing", "no-client", "no-out", "no-account", "unknown-flag"],
)
def test_main_rejects_missing_or_unknown_flags_with_usage(output: Output, argv: list[str]) -> None:
    with pytest.raises(SystemExit) as info:
        main(argv, open_browser=Browser())

    assert info.value.code == 2
    assert "usage: amazing-gmail-mcp-login" in output.read()[1]


def _clean_env(tmp_path: Path) -> dict[str, str]:
    return {"HOME": str(tmp_path), "PATH": os.environ.get("PATH", ""), "LANG": "en_US.UTF-8"}


def test_the_console_script_documents_every_flag(tmp_path: Path) -> None:
    script = Path(sys.executable).parent / "amazing-gmail-mcp-login"
    assert script.exists(), script

    result = subprocess.run(
        [str(script), "--help"], capture_output=True, text=True, env=_clean_env(tmp_path), timeout=60
    )

    assert result.returncode == 0, result.stderr
    for flag in ("--account", "--client-secret-file", "--out", "--force"):
        assert flag in result.stdout


def test_the_console_script_without_flags_exits_2_naming_them(tmp_path: Path) -> None:
    script = Path(sys.executable).parent / "amazing-gmail-mcp-login"

    result = subprocess.run([str(script)], capture_output=True, text=True, env=_clean_env(tmp_path), timeout=60)

    assert result.returncode == 2
    assert "the following arguments are required: --account, --client-secret-file, --out" in result.stderr
    assert "Traceback" not in result.stderr
