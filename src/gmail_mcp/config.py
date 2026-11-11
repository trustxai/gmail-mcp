"""Settings for the Gmail MCP server, from `GMAIL_*` environment variables (and `.env`).

Loading fails fast: `get_settings()` raises `ConfigError` naming every variable that is
missing or wrong, and never echoes a value. Any `GMAIL_*` variable (environment or `.env`)
that is not a setting is wrong too: a misspelt name would otherwise be dropped in silence,
and a typo such as GMAIL_LABEL_SCOPE would start the server with the whole mailbox in view. The server entry point calls it before it
starts, so a misconfigured entry exits at once with that message instead of failing at the
first tool call.

Secrets (`GMAIL_REFRESH_TOKEN`, the client secret) are `SecretStr`, so they never show in a
repr, and they are registered with `errors.register_secret` the moment they load, so every
message the process writes afterwards is scrubbed of them.
"""

from __future__ import annotations

import difflib
import json
import os
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from dotenv import dotenv_values
from pydantic import Field, PrivateAttr, SecretStr, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from gmail_mcp.errors import ConfigError, register_secret
from gmail_mcp.validators import MAX_SCOPE_QUERY_CHARS, MAX_SCOPE_QUERY_ENCODED, query_problem, query_size_problem

ENV_PREFIX = "GMAIL_"
DEFAULT_BODY_MAX_CHARS = 20_000
# The largest GMAIL_BODY_MAX_CHARS. A page of it in 4-byte UTF-8 is 600 KB; with every other
# field of a single-message response at its cap (formatters' MAX_* bounds, ~200 KB) it stays
# under formatters.MAX_RESPONSE_BYTES (900 KB), so clip_response never cuts a page or its note.
# The tests at the maximum (test_messages, test_threads) render that worst case.
MAX_BODY_MAX_CHARS = 150_000
DEFAULT_ATTACHMENT_DIR = "~/Downloads/gmail-mcp"
DEFAULT_ATTACHMENT_MAX_BYTES = 26_214_400  # 25 MiB

_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")

_ACCOUNT_HELP = "the one mailbox this server reads, e.g. you@example.com"
_TOKEN_HELP = "the gmail.readonly refresh token minted with amazing-gmail-mcp-login (from 1Password)"
_CLIENT_HELP = (
    "set GMAIL_CLIENT_SECRET_FILE to the Desktop client's JSON downloaded from Google Cloud, or both "
    "GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET"
)


def unknown_variables(known: frozenset[str]) -> list[str]:
    """`GMAIL_*` names in the environment or `./.env` that are not in `known` (case-insensitive, as the settings)."""
    names = set(os.environ)
    env_file = Path(".env")
    if env_file.is_file():
        names |= {name for name in dotenv_values(env_file) if name}
    return sorted(name for name in names if name.upper().startswith(ENV_PREFIX) and name.upper() not in known)


def _suggestion(name: str, known: frozenset[str]) -> str | None:
    """The known variable `name` most likely meant: the same words in another order, else a close spelling."""
    words = sorted(name.upper().split("_"))
    for candidate in sorted(known):
        if sorted(candidate.split("_")) == words:
            return candidate
    close = difflib.get_close_matches(name.upper(), sorted(known), n=1, cutoff=0.75)
    return close[0] if close else None


def unknown_variable_problem(name: str, known: frozenset[str]) -> str:
    """The refusal for one unknown `GMAIL_*` variable: its name and a fix, never its value."""
    suggestion = _suggestion(name, known)
    fix = f"did you mean {suggestion}?" if suggestion else f"the settings are {', '.join(sorted(known))}"
    return (
        f"{name} is not a known variable ({fix}): a misspelt setting is refused, so a typo can never leave the "
        "whole mailbox in view or a bound unset"
    )


@dataclass(frozen=True)
class ClientCredentials:
    """The OAuth client the refresh token was minted with (a Desktop / `installed` client)."""

    client_id: str
    client_secret: SecretStr
    source: str  # which variables it came from, for messages


def _read_client_file(path_text: str) -> ClientCredentials:
    """Parse Google's client JSON (`{"installed": {"client_id", "client_secret", …}}`).

    Raises `ValueError` naming GMAIL_CLIENT_SECRET_FILE; never echoes the file's content.
    """
    path = Path(path_text).expanduser()
    var = "GMAIL_CLIENT_SECRET_FILE"
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ValueError(f"{var} points to {path}, which does not exist") from None
    except OSError as exc:
        raise ValueError(f"{var} points to {path}, which cannot be read ({type(exc).__name__})") from None
    try:
        data = json.loads(raw)
    except ValueError:
        raise ValueError(f"{var} ({path}) is not JSON: download the client JSON from Google Cloud again") from None
    if not isinstance(data, dict):
        raise ValueError(f"{var} ({path}) is not a Google OAuth client JSON object")
    if "installed" not in data:
        kind = next((key for key in ("web", "service_account") if key in data or data.get("type") == key), None)
        detail = f"it is a {kind} credential" if kind else "it has no `installed` key"
        raise ValueError(
            f"{var} ({path}) is not a Desktop OAuth client: {detail}. Create an OAuth client of type 'Desktop app' "
            "and download its JSON"
        )
    installed = data["installed"]
    if not isinstance(installed, dict):
        raise ValueError(f"{var} ({path}): `installed` is not an object")
    missing = [key for key in ("client_id", "client_secret") if not str(installed.get(key) or "").strip()]
    if missing:
        raise ValueError(f"{var} ({path}): `installed` lacks {' and '.join(missing)}")
    return ClientCredentials(
        client_id=str(installed["client_id"]).strip(),
        client_secret=SecretStr(str(installed["client_secret"]).strip()),
        source=var,
    )


def load_client_credentials(
    *, secret_file: str | None, client_id: str | None, client_secret: SecretStr | str | None
) -> ClientCredentials:
    """One OAuth client from EITHER a client JSON file OR an inline id + secret.

    Raises `ValueError` naming the variables. Both forms at once are refused: two sources
    that may disagree would make which client is used depend on precedence rules.
    """
    secret_text = client_secret.get_secret_value() if isinstance(client_secret, SecretStr) else client_secret
    secret_text = (secret_text or "").strip() or None
    client_id = (client_id or "").strip() or None
    inline = client_id is not None or secret_text is not None
    if secret_file and inline:
        raise ValueError(
            "set either GMAIL_CLIENT_SECRET_FILE or GMAIL_CLIENT_ID + GMAIL_CLIENT_SECRET, not both: they could name "
            "different OAuth clients"
        )
    if secret_file:
        return _read_client_file(secret_file)
    if client_id and secret_text:
        return ClientCredentials(
            client_id=client_id, client_secret=SecretStr(secret_text), source="GMAIL_CLIENT_ID+GMAIL_CLIENT_SECRET"
        )
    if client_id:
        raise ValueError("GMAIL_CLIENT_SECRET is not set (GMAIL_CLIENT_ID is): set both, or GMAIL_CLIENT_SECRET_FILE")
    if secret_text:
        raise ValueError("GMAIL_CLIENT_ID is not set (GMAIL_CLIENT_SECRET is): set both, or GMAIL_CLIENT_SECRET_FILE")
    raise ValueError(f"no OAuth client configured: {_CLIENT_HELP}")


class Settings(BaseSettings):
    """The server's configuration. Constructing it validates everything (see `get_settings`)."""

    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX, env_file=".env", env_file_encoding="utf-8", extra="ignore", hide_input_in_errors=True
    )

    # ADR D3: the mailbox this process serves; the client checks the token's profile against it.
    account: str | None = None
    # The gmail.readonly refresh token, minted once per company with amazing-gmail-mcp-login.
    refresh_token: SecretStr | None = None
    # The OAuth client: Google's Desktop client JSON, or the same id + secret inline.
    client_secret_file: str | None = None
    client_id: str | None = None
    client_secret: SecretStr | None = None
    # ADR D5: an optional project scope (a filter, not a security boundary). The query is at
    # most validators.MAX_SCOPE_QUERY_CHARS characters and MAX_SCOPE_QUERY_ENCODED once
    # percent-encoded: it rides along every search's URL, which Gmail caps.
    scope_label: str | None = None
    scope_query: str | None = None
    # ADR D6: output bounds.
    body_max_chars: int = Field(default=DEFAULT_BODY_MAX_CHARS, ge=100, le=MAX_BODY_MAX_CHARS)
    attachment_dir: str = DEFAULT_ATTACHMENT_DIR
    attachment_max_bytes: int = Field(default=DEFAULT_ATTACHMENT_MAX_BYTES, ge=1, le=1_073_741_824)

    _credentials: ClientCredentials | None = PrivateAttr(default=None)

    # MCP clients pass these via a JSON `env` block, where a pasted value often keeps a
    # trailing space/newline; a blank value means "not set".
    @field_validator(
        "account",
        "refresh_token",
        "client_secret_file",
        "client_id",
        "client_secret",
        "scope_label",
        "scope_query",
        mode="before",
    )
    @classmethod
    def _blank_is_unset(cls, value: Any) -> Any:
        if isinstance(value, SecretStr):
            value = value.get_secret_value()
        if isinstance(value, str):
            value = value.strip()
            return value or None
        return value

    @field_validator("attachment_dir", mode="before")
    @classmethod
    def _strip_dir(cls, value: Any) -> Any:
        if isinstance(value, str):
            return value.strip() or DEFAULT_ATTACHMENT_DIR
        return value

    @model_validator(mode="after")
    def _require_and_resolve(self) -> Settings:
        # Register the secrets before anything can fail, so even an error about another
        # variable can never carry them.
        if self.refresh_token is not None:
            register_secret(self.refresh_token.get_secret_value())
        if self.client_secret is not None:
            register_secret(self.client_secret.get_secret_value())
        problems: list[str] = []
        if self.account is None:
            problems.append(f"GMAIL_ACCOUNT is not set ({_ACCOUNT_HELP})")
        elif not _EMAIL_RE.fullmatch(self.account):
            problems.append(f"GMAIL_ACCOUNT is not an email address ({_ACCOUNT_HELP})")
        if self.refresh_token is None:
            problems.append(f"GMAIL_REFRESH_TOKEN is not set ({_TOKEN_HELP})")
        elif any(char.isspace() for char in self.refresh_token.get_secret_value()):
            problems.append("GMAIL_REFRESH_TOKEN contains whitespace inside the value (a broken paste?)")
        try:
            self._credentials = load_client_credentials(
                secret_file=self.client_secret_file, client_id=self.client_id, client_secret=self.client_secret
            )
            register_secret(self._credentials.client_secret.get_secret_value())
        except ValueError as exc:
            problems.append(str(exc))
        known = known_variables()
        problems.extend(unknown_variable_problem(name, known) for name in unknown_variables(known))
        if self.scope_query is not None:
            # Sizes only, never the value (it may name clients or people).
            size = query_size_problem(
                self.scope_query, max_chars=MAX_SCOPE_QUERY_CHARS, max_encoded=MAX_SCOPE_QUERY_ENCODED
            )
            if size is not None:
                problems.append(
                    f"GMAIL_SCOPE_QUERY is refused: {size}. It goes into the URL of every search and of every "
                    "scope check: fix or shorten it, or scope by a label with GMAIL_SCOPE_LABEL"
                )
            problem = query_problem(self.scope_query)
            if problem is not None:
                problems.append(f"GMAIL_SCOPE_QUERY is refused: {problem}")
        if problems:
            raise ValueError("; ".join(problems))
        return self

    @property
    def credentials(self) -> ClientCredentials:
        """The resolved OAuth client (always set on a constructed `Settings`)."""
        if self._credentials is None:  # pragma: no cover - the validator always sets it
            raise ConfigError("no OAuth client configured")
        return self._credentials

    @property
    def account_email(self) -> str:
        """GMAIL_ACCOUNT (always set on a constructed `Settings`)."""
        if self.account is None:  # pragma: no cover - the validator requires it
            raise ConfigError(f"GMAIL_ACCOUNT is not set ({_ACCOUNT_HELP})")
        return self.account

    @property
    def refresh_token_value(self) -> str:
        """The refresh token, unwrapped (only auth.py calls this)."""
        if self.refresh_token is None:  # pragma: no cover - the validator requires it
            raise ConfigError(f"GMAIL_REFRESH_TOKEN is not set ({_TOKEN_HELP})")
        return self.refresh_token.get_secret_value()

    @property
    def attachment_path(self) -> Path:
        """GMAIL_ATTACHMENT_DIR with `~` expanded."""
        return Path(self.attachment_dir).expanduser()


def known_variables() -> frozenset[str]:
    """Every variable a setting reads: `GMAIL_` + each field name, upper-case."""
    return frozenset(f"{ENV_PREFIX}{name.upper()}" for name in Settings.model_fields)


def _env_name(location: tuple[int | str, ...]) -> str:
    field = ".".join(str(part) for part in location)
    return f"{ENV_PREFIX}{field.upper()}" if field else "configuration"


def config_error_from(exc: ValidationError) -> ConfigError:
    """A `ConfigError` naming each bad variable, with pydantic's message and never the value."""
    parts: list[str] = []
    for err in exc.errors(include_url=False, include_input=False, include_context=False):
        message = str(err["msg"]).removeprefix("Value error, ")
        location = tuple(err["loc"])
        parts.append(message if not location else f"{_env_name(location)}: {message}")
    return ConfigError("configuration error: " + "; ".join(parts))


def load_settings(**overrides: Any) -> Settings:
    """Build `Settings` (env, `.env`, then `overrides`), raising `ConfigError` on any problem."""
    try:
        return Settings(**overrides)
    except ValidationError as exc:
        raise config_error_from(exc) from None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings singleton (tests call `get_settings.cache_clear()`). Raises `ConfigError`."""
    return load_settings()
