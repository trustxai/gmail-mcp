"""Live: attachments by partId (ADR-0002) against the real mailbox.

- Does Gmail hand out a new attachmentId on every read? Measured, not asserted: the test
  passes either way and records "rotates" or "stable" (ADR-0002 rests on two sources that say
  "rotates"; this is the first measurement here).
- gmail_get_attachment, through the MCP session, saves the part named by its partId: the file
  exists under GMAIL_ATTACHMENT_DIR/<message_id>/, is 0600, holds exactly the part's body.size
  bytes, and hashes to the sha256 the result reports. The bytes are deleted after the test.

Both skip when no `has:attachment` message among the newest 50 in scope has a part with an
attachmentId (the download test also wants one of at most 5 MiB).
"""

from __future__ import annotations

import shutil
from collections.abc import Iterator
from pathlib import Path

import pytest

from gmail_mcp.config import get_settings

from ._support import (
    NO_ATTACHMENT,
    NO_SMALL_ATTACHMENT,
    LiveRecord,
    attachment_id_between_two_reads,
    bounded,
    call_tool,
    file_facts,
    find_attachment,
    mcp_session,
)

pytestmark = pytest.mark.live


@pytest.fixture
def attachment_dir(tmp_path: Path) -> Iterator[Path]:
    """GMAIL_ATTACHMENT_DIR in a temporary directory, removed (with what was saved) afterwards.

    Its own MonkeyPatch context, so undoing it touches nothing another fixture patched.
    """
    target = tmp_path / "attachments"
    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("GMAIL_ATTACHMENT_DIR", str(target))
        get_settings.cache_clear()
        try:
            yield target
        finally:
            shutil.rmtree(target, ignore_errors=True)  # a saved attachment never outlives the test
    get_settings.cache_clear()


async def test_live_an_attachment_id_rotates_or_stays_between_two_reads(live_record: LiveRecord) -> None:
    async with bounded():
        ref = await find_attachment(max_bytes=None)
        if ref is None:
            pytest.skip(NO_ATTACHMENT)
        result = await attachment_id_between_two_reads(ref)

    assert result is not None, "one of the two messages.get lost the part's attachmentId"
    live_record("attachmentId of one partId across two messages.get", result)


async def test_live_gmail_get_attachment_saves_the_part_named_by_its_part_id(attachment_dir: Path) -> None:
    async with bounded():
        ref = await find_attachment()
        if ref is None:
            pytest.skip(NO_SMALL_ATTACHMENT)
        async with mcp_session() as session:
            outcome = await call_tool(
                session,
                "gmail_get_attachment",
                {"params": {"message_id": ref.message_id, "part_id": ref.part_id}},
                "# Attachment saved",
            )

    error = outcome.error
    assert not outcome.is_error, f"gmail_get_attachment failed: {error}"
    assert outcome.starts_as_expected, "gmail_get_attachment did not answer with its '# Attachment saved' block"
    saved = outcome.saved
    assert saved is not None
    reported_size, reported_sha = saved.size, saved.sha256
    facts = file_facts(saved.path, attachment_dir, ref.message_id)
    is_file, in_message_dir = facts.is_file, facts.in_message_dir
    mode, size, sha256 = facts.mode, facts.size, facts.sha256
    body_size = ref.size

    assert is_file, "the path in the result is not a saved file"
    assert in_message_dir, "the file is not directly under GMAIL_ATTACHMENT_DIR/<message_id>/"
    assert mode == 0o600
    assert size == body_size, "the saved bytes are not the part's body.size"
    assert reported_size == size, "the size the result reports is not the file's"
    assert reported_sha == sha256, "the sha256 the result reports is not the file's"
