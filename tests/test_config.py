"""Settings: every variable of spec §Config, secrets as SecretStr, fail-fast errors naming the variable."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from pydantic import SecretStr

from gmail_mcp.config import (
    DEFAULT_ATTACHMENT_MAX_BYTES,
    DEFAULT_BODY_MAX_CHARS,
    MAX_BODY_MAX_CHARS,
    Settings,
    get_settings,
    known_variables,
    load_client_credentials,
    load_settings,
    unknown_variables,
)
from gmail_mcp.errors import ConfigError, redact
from gmail_mcp.formatters import MAX_RESPONSE_BYTES
from gmail_mcp.validators import MAX_SCOPE_QUERY_CHARS, MAX_SCOPE_QUERY_ENCODED, encoded_length

from .fakes import (
    ACCOUNT,
    CJK,
    FAKE_CLIENT_ID,
    FAKE_CLIENT_SECRET,
    FAKE_REFRESH_TOKEN,
    FOUR_BYTES,
    text_of_encoded_size,
)

INLINE: dict[str, Any] = {"client_id": FAKE_CLIENT_ID, "client_secret": FAKE_CLIENT_SECRET}


def _client_file(tmp_path: Path, content: Any, name: str = "client.json") -> str:
    path = tmp_path / name
    path.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
    return str(path)


def _installed(**overrides: Any) -> dict[str, Any]:
    installed = {
        "client_id": FAKE_CLIENT_ID,
        "project_id": "example-project",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "client_secret": FAKE_CLIENT_SECRET,
        "redirect_uris": ["http://localhost"],
    }
    installed.update(overrides)
    return {"installed": installed}


def _error(**values: Any) -> str:
    with pytest.raises(ConfigError) as info:
        load_settings(**values)
    return str(info.value)


# --- the happy paths ----------------------------------------------------------------------


def test_inline_client_credentials_load() -> None:
    settings = load_settings(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, **INLINE)

    assert settings.account_email == ACCOUNT
    assert settings.credentials.client_id == FAKE_CLIENT_ID
    assert settings.credentials.client_secret.get_secret_value() == FAKE_CLIENT_SECRET
    assert settings.credentials.source == "GMAIL_CLIENT_ID+GMAIL_CLIENT_SECRET"
    assert settings.refresh_token_value == FAKE_REFRESH_TOKEN


def test_client_secret_file_loads_the_installed_client(tmp_path: Path) -> None:
    path = _client_file(tmp_path, _installed())

    settings = load_settings(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, client_secret_file=path)

    assert settings.credentials.client_id == FAKE_CLIENT_ID
    assert settings.credentials.client_secret.get_secret_value() == FAKE_CLIENT_SECRET
    assert settings.credentials.source == "GMAIL_CLIENT_SECRET_FILE"


def test_every_spec_variable_is_read_from_the_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = _client_file(tmp_path, _installed())
    env = {
        "GMAIL_ACCOUNT": ACCOUNT,
        "GMAIL_REFRESH_TOKEN": FAKE_REFRESH_TOKEN,
        "GMAIL_CLIENT_SECRET_FILE": path,
        "GMAIL_SCOPE_LABEL": "Projects/Acme",
        "GMAIL_SCOPE_QUERY": "from:example.com",
        "GMAIL_BODY_MAX_CHARS": "5000",
        "GMAIL_ATTACHMENT_DIR": str(tmp_path / "attachments"),
        "GMAIL_ATTACHMENT_MAX_BYTES": "1024",
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    settings = get_settings()

    assert settings.account == ACCOUNT
    assert settings.refresh_token_value == FAKE_REFRESH_TOKEN
    assert settings.client_secret_file == path
    assert settings.scope_label == "Projects/Acme"
    assert settings.scope_query == "from:example.com"
    assert settings.body_max_chars == 5000
    assert settings.attachment_path == tmp_path / "attachments"
    assert settings.attachment_max_bytes == 1024


def test_inline_client_variables_are_read_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GMAIL_ACCOUNT", ACCOUNT)
    monkeypatch.setenv("GMAIL_REFRESH_TOKEN", FAKE_REFRESH_TOKEN)
    monkeypatch.setenv("GMAIL_CLIENT_ID", FAKE_CLIENT_ID)
    monkeypatch.setenv("GMAIL_CLIENT_SECRET", FAKE_CLIENT_SECRET)

    assert get_settings().credentials.client_id == FAKE_CLIENT_ID


def test_a_dotenv_file_in_the_cwd_is_read(tmp_path: Path) -> None:
    # The autouse fixture chdirs into an empty temporary directory: write .env there.
    Path(".env").write_text(
        f"GMAIL_ACCOUNT={ACCOUNT}\nGMAIL_REFRESH_TOKEN={FAKE_REFRESH_TOKEN}\n"
        f"GMAIL_CLIENT_ID={FAKE_CLIENT_ID}\nGMAIL_CLIENT_SECRET={FAKE_CLIENT_SECRET}\n",
        encoding="utf-8",
    )

    assert get_settings().account == ACCOUNT


def test_defaults() -> None:
    settings = load_settings(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, **INLINE)

    assert settings.body_max_chars == DEFAULT_BODY_MAX_CHARS == 20_000
    assert settings.attachment_max_bytes == DEFAULT_ATTACHMENT_MAX_BYTES == 26_214_400
    assert settings.attachment_path == Path("~/Downloads/gmail-mcp").expanduser()
    assert settings.scope_label is None
    assert settings.scope_query is None


def test_values_are_stripped_and_blank_means_unset() -> None:
    settings = load_settings(
        account=f"  {ACCOUNT}\n",
        refresh_token=f"{FAKE_REFRESH_TOKEN}\n",
        scope_label="   ",
        scope_query="",
        **INLINE,
    )

    assert settings.account == ACCOUNT
    assert settings.refresh_token_value == FAKE_REFRESH_TOKEN
    assert settings.scope_label is None
    assert settings.scope_query is None


def test_secrets_are_secretstr_and_never_in_the_repr() -> None:
    settings = load_settings(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, **INLINE)

    assert isinstance(settings.refresh_token, SecretStr)
    assert isinstance(settings.client_secret, SecretStr)
    assert isinstance(settings.credentials.client_secret, SecretStr)
    for rendered in (repr(settings), str(settings), repr(settings.credentials), settings.model_dump_json()):
        assert FAKE_REFRESH_TOKEN not in rendered
        assert FAKE_CLIENT_SECRET not in rendered


def test_loading_registers_the_secrets_for_redaction(tmp_path: Path) -> None:
    load_settings(
        account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, client_secret_file=_client_file(tmp_path, _installed())
    )

    assert redact(f"a {FAKE_REFRESH_TOKEN} b {FAKE_CLIENT_SECRET} c") == "a *** b *** c"


# --- each failure names the variable --------------------------------------------------------


def test_missing_account_is_named() -> None:
    message = _error(refresh_token=FAKE_REFRESH_TOKEN, **INLINE)
    assert "GMAIL_ACCOUNT is not set" in message
    assert "GMAIL_REFRESH_TOKEN" not in message


def test_missing_refresh_token_is_named() -> None:
    message = _error(account=ACCOUNT, **INLINE)
    assert "GMAIL_REFRESH_TOKEN is not set" in message
    assert "amazing-gmail-mcp-login" in message


def test_missing_client_is_named() -> None:
    message = _error(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN)
    assert "no OAuth client configured" in message
    assert "GMAIL_CLIENT_SECRET_FILE" in message
    assert "GMAIL_CLIENT_ID" in message


def test_nothing_set_names_every_missing_variable_at_once() -> None:
    message = _error()
    assert message.startswith("configuration error: ")
    assert "GMAIL_ACCOUNT is not set" in message
    assert "GMAIL_REFRESH_TOKEN is not set" in message
    assert "no OAuth client configured" in message


def test_client_id_without_secret_names_the_secret() -> None:
    message = _error(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, client_id=FAKE_CLIENT_ID)
    assert "GMAIL_CLIENT_SECRET is not set" in message


def test_client_secret_without_id_names_the_id() -> None:
    message = _error(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, client_secret=FAKE_CLIENT_SECRET)
    assert "GMAIL_CLIENT_ID is not set" in message


def test_file_and_inline_together_are_refused(tmp_path: Path) -> None:
    path = _client_file(tmp_path, _installed())
    message = _error(
        account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, client_secret_file=path, client_id=FAKE_CLIENT_ID
    )
    assert "not both" in message


def test_missing_client_file_is_named(tmp_path: Path) -> None:
    message = _error(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, client_secret_file=str(tmp_path / "nope.json"))
    assert "GMAIL_CLIENT_SECRET_FILE" in message
    assert "does not exist" in message


def test_client_file_that_is_not_json_is_named_without_its_content(tmp_path: Path) -> None:
    path = _client_file(tmp_path, f"not json {FAKE_CLIENT_SECRET}")
    message = _error(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, client_secret_file=path)
    assert "GMAIL_CLIENT_SECRET_FILE" in message
    assert "is not JSON" in message
    assert FAKE_CLIENT_SECRET not in message


def test_a_web_client_file_is_refused(tmp_path: Path) -> None:
    path = _client_file(tmp_path, {"web": _installed()["installed"]})
    message = _error(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, client_secret_file=path)
    assert "not a Desktop OAuth client" in message
    assert "web credential" in message
    assert FAKE_CLIENT_SECRET not in message


def test_a_service_account_file_is_refused(tmp_path: Path) -> None:
    path = _client_file(tmp_path, {"type": "service_account", "client_email": "bot@example.com"})
    message = _error(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, client_secret_file=path)
    assert "not a Desktop OAuth client" in message


@pytest.mark.parametrize("missing", ["client_id", "client_secret"])
def test_an_installed_entry_without_its_keys_is_named(tmp_path: Path, missing: str) -> None:
    path = _client_file(tmp_path, _installed(**{missing: ""}))
    message = _error(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, client_secret_file=path)
    assert "GMAIL_CLIENT_SECRET_FILE" in message
    assert f"lacks {missing}" in message


def test_a_json_array_client_file_is_refused(tmp_path: Path) -> None:
    path = _client_file(tmp_path, [1, 2])
    message = _error(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, client_secret_file=path)
    assert "is not a Google OAuth client JSON object" in message


@pytest.mark.parametrize("account", ["ops", "ops@", "two words@example.com", "a@b@example.com"])
def test_an_account_that_is_not_an_email_is_refused(account: str) -> None:
    message = _error(account=account, refresh_token=FAKE_REFRESH_TOKEN, **INLINE)
    assert "GMAIL_ACCOUNT is not an email address" in message


def test_a_refresh_token_with_inner_whitespace_is_refused_without_echo() -> None:
    broken = FAKE_REFRESH_TOKEN[:10] + " " + FAKE_REFRESH_TOKEN[10:]
    message = _error(account=ACCOUNT, refresh_token=broken, **INLINE)
    assert "GMAIL_REFRESH_TOKEN contains whitespace" in message
    assert FAKE_REFRESH_TOKEN[10:] not in message


def test_a_bad_integer_names_the_variable_and_never_the_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GMAIL_ACCOUNT", ACCOUNT)
    monkeypatch.setenv("GMAIL_REFRESH_TOKEN", FAKE_REFRESH_TOKEN)
    monkeypatch.setenv("GMAIL_CLIENT_ID", FAKE_CLIENT_ID)
    monkeypatch.setenv("GMAIL_CLIENT_SECRET", FAKE_CLIENT_SECRET)
    monkeypatch.setenv("GMAIL_BODY_MAX_CHARS", "plenty-zzq")

    with pytest.raises(ConfigError) as info:
        get_settings()

    assert "GMAIL_BODY_MAX_CHARS" in str(info.value)
    assert "plenty-zzq" not in str(info.value)


def test_the_body_cap_tops_out_where_a_full_page_still_fits_one_response() -> None:
    # 4 bytes per character at most: a full page of the largest cap is 600 KB of the 900 KB a
    # response may carry, leaving room for the rest (the tests at the maximum render it).
    assert 4 * MAX_BODY_MAX_CHARS <= MAX_RESPONSE_BYTES - 200_000
    assert (
        load_settings(
            account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, body_max_chars=MAX_BODY_MAX_CHARS, **INLINE
        ).body_max_chars
        == MAX_BODY_MAX_CHARS
    )
    message = _error(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, body_max_chars=MAX_BODY_MAX_CHARS + 1, **INLINE)
    assert "GMAIL_BODY_MAX_CHARS" in message and "150000" in message


@pytest.mark.parametrize(("field", "value"), [("body_max_chars", 10), ("attachment_max_bytes", 0)])
def test_bounds_are_enforced(field: str, value: int) -> None:
    message = _error(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, **INLINE, **{field: value})
    assert f"GMAIL_{field.upper()}" in message


@pytest.mark.parametrize("query", [") OR from:x (", "(label:acme", 'subject:"open'])
def test_an_unbalanced_scope_query_is_refused_at_load(query: str) -> None:
    message = _error(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, scope_query=query, **INLINE)
    assert "GMAIL_SCOPE_QUERY is refused" in message


# A scope query names a client or a person: its size is reported, never the value.
_SCOPE_PREFIX = "from:zq-client@example.com "
WIDE = [FOUR_BYTES, CJK, "é"]
WIDE_IDS = ["4-byte", "CJK", "accented"]


def _scope_at(char: str, encoded: int) -> str:
    """A scope query that takes exactly `encoded` characters percent-encoded."""
    prefix = encoded_length(_SCOPE_PREFIX) or 0
    return _SCOPE_PREFIX + text_of_encoded_size(char, encoded - prefix)


def _load_scope(value: str) -> Settings:
    return load_settings(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, scope_query=value, **INLINE)


@pytest.mark.parametrize("char", WIDE, ids=WIDE_IDS)
def test_a_scope_query_at_the_encoded_cap_loads(char: str) -> None:
    at = _scope_at(char, MAX_SCOPE_QUERY_ENCODED)
    assert encoded_length(at) == MAX_SCOPE_QUERY_ENCODED
    assert _load_scope(f"  {at}\n").scope_query == at  # stripped, then measured


@pytest.mark.parametrize("char", WIDE, ids=WIDE_IDS)
def test_a_scope_query_one_past_the_encoded_cap_refuses_to_load_naming_only_the_variable(char: str) -> None:
    over = _scope_at(char, MAX_SCOPE_QUERY_ENCODED) + "a"
    message = _error(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, scope_query=over, **INLINE)
    assert (
        f"GMAIL_SCOPE_QUERY is refused: it is {MAX_SCOPE_QUERY_ENCODED + 1:,} characters once percent-encoded for "
        f"the URL, the most is {MAX_SCOPE_QUERY_ENCODED:,}"
    ) in message
    assert "zq-client" not in message and char * 5 not in message


def test_an_ascii_scope_query_at_the_character_cap_loads_and_one_past_it_refuses() -> None:
    assert _load_scope(_SCOPE_PREFIX + "x" * (MAX_SCOPE_QUERY_CHARS - len(_SCOPE_PREFIX))).scope_query is not None
    assert _load_scope(":" * MAX_SCOPE_QUERY_CHARS).scope_query == ":" * MAX_SCOPE_QUERY_CHARS  # 4,500 encoded
    over = _SCOPE_PREFIX + "x" * (MAX_SCOPE_QUERY_CHARS + 1 - len(_SCOPE_PREFIX))
    message = _error(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, scope_query=over, **INLINE)
    assert f"GMAIL_SCOPE_QUERY is refused: it is {MAX_SCOPE_QUERY_CHARS + 1:,} characters, the most is " in message
    assert "zq-client" not in message and "x" * 20 not in message


def test_the_scope_query_the_review_found_breaking_every_search_refuses_to_load() -> None:
    # 1,500 4-byte characters (18,000 encoded) loaded under the character cap alone, and every
    # request then went past Gmail's 16,384-character limit.
    message = _error(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, scope_query=FOUR_BYTES * 1_500, **INLINE)
    assert "GMAIL_SCOPE_QUERY is refused: it is 18,000 characters once percent-encoded" in message


def test_an_overlong_scope_query_in_the_environment_fails_fast_without_echo(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in {
        "GMAIL_ACCOUNT": ACCOUNT,
        "GMAIL_REFRESH_TOKEN": FAKE_REFRESH_TOKEN,
        "GMAIL_CLIENT_ID": FAKE_CLIENT_ID,
        "GMAIL_CLIENT_SECRET": FAKE_CLIENT_SECRET,
        "GMAIL_SCOPE_QUERY": _scope_at(CJK, MAX_SCOPE_QUERY_ENCODED) + CJK,
    }.items():
        monkeypatch.setenv(name, value)

    with pytest.raises(ConfigError) as info:
        get_settings()

    assert f"GMAIL_SCOPE_QUERY is refused: it is {MAX_SCOPE_QUERY_ENCODED + 9:,} characters once" in str(info.value)
    assert "zq-client" not in str(info.value) and CJK not in str(info.value)


def test_a_scope_query_with_bytes_that_are_not_utf8_refuses_to_load(monkeypatch: pytest.MonkeyPatch) -> None:
    # An undecodable byte in the environment reaches Python as a lone surrogate, which no URL
    # can carry: every search would fail. The message names the variable, not the bytes.
    for name, value in {
        "GMAIL_ACCOUNT": ACCOUNT,
        "GMAIL_REFRESH_TOKEN": FAKE_REFRESH_TOKEN,
        "GMAIL_CLIENT_ID": FAKE_CLIENT_ID,
        "GMAIL_CLIENT_SECRET": FAKE_CLIENT_SECRET,
    }.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setitem(os.environb, b"GMAIL_SCOPE_QUERY", b"from:zq-client\xff")

    with pytest.raises(ConfigError) as info:
        get_settings()

    assert "GMAIL_SCOPE_QUERY is refused: it is not valid UTF-8 text" in str(info.value)
    assert "zq-client" not in str(info.value)


def test_an_overlong_and_unbalanced_scope_query_names_both_problems() -> None:
    message = _error(
        account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, scope_query="(" + "x" * MAX_SCOPE_QUERY_CHARS, **INLINE
    )
    assert "it is 1,501 characters, the most is" in message and "a group is opened and never closed" in message


@pytest.mark.parametrize("name", ["GMAIL_SCOPE_LABLE", "GMAIL_SCOPE", "gmail_scope_labels"])
def test_a_misspelt_scope_variable_refuses_to_load(monkeypatch: pytest.MonkeyPatch, name: str) -> None:
    monkeypatch.setenv(name, "Projects/Acme")
    message = _error(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, **INLINE)
    assert f"{name} is not a known variable" in message


def test_a_misspelt_scope_variable_in_dotenv_refuses_to_load() -> None:
    Path(".env").write_text("GMAIL_SCOPE_QUERRY=from:example.com\n", encoding="utf-8")
    message = _error(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, **INLINE)
    assert "GMAIL_SCOPE_QUERRY is not a known variable" in message


def test_the_real_scope_variables_load_in_any_case(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GMAIL_SCOPE_LABEL", "Projects/Acme")
    monkeypatch.setenv("gmail_scope_query", "from:example.com")
    settings = load_settings(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, **INLINE)
    assert settings.scope_label == "Projects/Acme"
    assert settings.scope_query == "from:example.com"


# Values that must never be echoed: a typo is named, not shown.
_TYPO_VALUE = "label:acme-rollout-zzq"


@pytest.mark.parametrize(
    ("name", "suggestion"),
    [
        ("GMAIL_LABEL_SCOPE", "GMAIL_SCOPE_LABEL"),  # the words in another order
        ("GMAIL_SCOP_LABEL", "GMAIL_SCOPE_LABEL"),
        ("GMAIL_QUERY_SCOPE", "GMAIL_SCOPE_QUERY"),
        ("GMAIL_BODY_MAX", "GMAIL_BODY_MAX_CHARS"),
        ("GMAIL_ATTACHMENTS_DIR", "GMAIL_ATTACHMENT_DIR"),
        ("gmail_refresh_tokens", "GMAIL_REFRESH_TOKEN"),
    ],
)
def test_any_unknown_gmail_variable_refuses_to_load_naming_it(
    monkeypatch: pytest.MonkeyPatch, name: str, suggestion: str
) -> None:
    monkeypatch.setenv(name, _TYPO_VALUE)
    message = _error(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, **INLINE)
    assert f"{name} is not a known variable (did you mean {suggestion}?)" in message
    assert _TYPO_VALUE not in message


def test_an_unknown_variable_with_no_near_name_lists_the_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GMAIL_SOMETHING_ELSE", _TYPO_VALUE)
    message = _error(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, **INLINE)
    assert "GMAIL_SOMETHING_ELSE is not a known variable (the settings are GMAIL_ACCOUNT, " in message
    assert "GMAIL_SCOPE_LABEL" in message and _TYPO_VALUE not in message


def test_an_unknown_variable_in_dotenv_refuses_to_load_too() -> None:
    Path(".env").write_text(f"GMAIL_LABEL_SCOPE={_TYPO_VALUE}\n", encoding="utf-8")
    message = _error(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, **INLINE)
    assert "GMAIL_LABEL_SCOPE is not a known variable (did you mean GMAIL_SCOPE_LABEL?)" in message
    assert _TYPO_VALUE not in message


def test_an_unknown_variable_holding_a_secret_never_echoes_it(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GMAIL_REFRESH", FAKE_REFRESH_TOKEN)
    message = _error(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, **INLINE)
    assert "GMAIL_REFRESH is not a known variable" in message
    assert FAKE_REFRESH_TOKEN not in message


def test_every_setting_is_a_known_variable(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    assert known_variables() == {
        "GMAIL_ACCOUNT",
        "GMAIL_REFRESH_TOKEN",
        "GMAIL_CLIENT_SECRET_FILE",
        "GMAIL_CLIENT_ID",
        "GMAIL_CLIENT_SECRET",
        "GMAIL_SCOPE_LABEL",
        "GMAIL_SCOPE_QUERY",
        "GMAIL_BODY_MAX_CHARS",
        "GMAIL_ATTACHMENT_DIR",
        "GMAIL_ATTACHMENT_MAX_BYTES",
    }
    assert unknown_variables(known_variables()) == []  # the isolated test environment has none


def test_variables_without_the_gmail_prefix_are_not_this_servers_business(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "x")
    monkeypatch.setenv("MY_GMAIL_ACCOUNT", "x")
    assert load_settings(account=ACCOUNT, refresh_token=FAKE_REFRESH_TOKEN, **INLINE).account == ACCOUNT


def test_no_error_message_carries_a_secret(tmp_path: Path) -> None:
    # Another variable is wrong; the secrets that DID load must not ride along.
    message = _error(account="not-an-email", refresh_token=FAKE_REFRESH_TOKEN, **INLINE)
    assert FAKE_REFRESH_TOKEN not in message
    assert FAKE_CLIENT_SECRET not in message


def test_get_settings_fails_fast_and_is_cached_once_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    with pytest.raises(ConfigError, match="GMAIL_ACCOUNT is not set"):
        get_settings()
    monkeypatch.setenv("GMAIL_ACCOUNT", ACCOUNT)
    monkeypatch.setenv("GMAIL_REFRESH_TOKEN", FAKE_REFRESH_TOKEN)
    monkeypatch.setenv("GMAIL_CLIENT_ID", FAKE_CLIENT_ID)
    monkeypatch.setenv("GMAIL_CLIENT_SECRET", FAKE_CLIENT_SECRET)

    first = get_settings()

    assert get_settings() is first


def test_load_client_credentials_is_usable_on_its_own(tmp_path: Path) -> None:
    # The login CLI (t4) reads a client file without the server's other variables.
    path = _client_file(tmp_path, _installed())
    credentials = load_client_credentials(secret_file=path, client_id=None, client_secret=None)
    assert credentials.client_id == FAKE_CLIENT_ID
    with pytest.raises(ValueError, match="no OAuth client configured"):
        load_client_credentials(secret_file=None, client_id=None, client_secret=None)


def test_settings_is_constructible_directly_and_validates() -> None:
    with pytest.raises(ValueError, match="GMAIL_ACCOUNT"):
        Settings()
