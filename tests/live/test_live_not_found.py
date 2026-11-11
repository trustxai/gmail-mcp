"""Live: an id that passes the validator but names no message reads as "not found".

Two ids the server's validator accepts (`[A-Za-z0-9]{6,64}`): 16 hex characters that do not
exist in this mailbox, and 16 characters Gmail cannot parse as an id at all. For each, the
test records what Gmail itself answers to `messages.get` (status and reason only, e.g.
`404 notFound`), then checks that gmail_get_message turns it into "… was not found in this
mailbox scope" (scope.means_not_found maps a 404 and the 400 `invalidArgument`). A status the
mapping does not know fails the test with that status, which is the finding.
"""

from __future__ import annotations

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from gmail_mcp import validators
from gmail_mcp.client import get_client
from gmail_mcp.errors import GmailApiError
from gmail_mcp.tools.messages import GetMessageInput, gmail_get_message

from ._support import LiveRecord, bounded, error_kind, status_and_reason

pytestmark = pytest.mark.live

NOT_FOUND = "not found in this mailbox scope"


@pytest.mark.parametrize(
    "ident",
    [
        pytest.param("0123456789abcdef", id="hex-that-does-not-exist"),
        pytest.param("zzzzzzzzzzzzzzzz", id="malformed"),
    ],
)
async def test_live_an_id_gmail_cannot_find_reads_as_not_found(ident: str, live_record: LiveRecord) -> None:
    validates = validators.message_id(ident) == ident
    assert validates, "the made-up id must pass the server's own validator, or the test proves nothing"

    async with bounded():
        try:
            await get_client().get(f"users/me/messages/{ident}", {"format": "full"})
        except GmailApiError as exc:
            answered = status_and_reason(exc.status, exc.reason)
        else:
            pytest.skip("the made-up id names a message in this mailbox: pick another to measure this")
        live_record("what Gmail answered messages.get", answered)

        try:
            await gmail_get_message(GetMessageInput(message_id=ident))
        except ToolError as exc:
            kind = error_kind(str(exc))
        else:
            kind = "an answer, not an error"

    assert kind == NOT_FOUND, f"gmail_get_message must say '{NOT_FOUND}'"
