"""Live: every read tool answers once through an in-process MCP session, against the real mailbox.

The same path an MCP client takes (tools/call, argument validation, the redacting funnel in
server.py), in one session: gmail_health, gmail_list_labels, gmail_search_messages
(max_results 3), gmail_get_message on the first hit, gmail_search_threads (max_results 3),
gmail_get_thread (max_messages 2) on the first thread. None may come back as an error, and each
must start with its own heading. gmail_get_attachment goes through the session too, in
test_live_attachments.py. Skips when the scope has no message or thread to read.
"""

from __future__ import annotations

import pytest

from ._support import ToolOutcome, bounded, call_tool, mcp_session

pytestmark = pytest.mark.live

PAGE = 3
THREAD_MESSAGES = 2
TOOLS = (
    "gmail_health",
    "gmail_list_labels",
    "gmail_search_messages",
    "gmail_get_message",
    "gmail_search_threads",
    "gmail_get_thread",
)


async def test_live_every_read_tool_answers_through_an_mcp_session() -> None:
    outcomes: list[ToolOutcome] = []
    async with bounded(), mcp_session() as session:
        outcomes.append(await call_tool(session, "gmail_health", {}, "# Gmail health"))
        outcomes.append(await call_tool(session, "gmail_list_labels", {}, "# Gmail labels ("))
        search = await call_tool(session, "gmail_search_messages", {"params": {"max_results": PAGE}}, "# Gmail search")
        outcomes.append(search)
        if search.message_ids:
            message_id = search.message_ids[0]
            outcomes.append(
                await call_tool(
                    session,
                    "gmail_get_message",
                    {"params": {"message_id": message_id}},
                    f"# Gmail message `{message_id}`",
                )
            )
        threads = await call_tool(session, "gmail_search_threads", {"params": {"max_results": PAGE}}, "# Gmail threads")
        outcomes.append(threads)
        if threads.thread_ids:
            thread_id = threads.thread_ids[0]
            outcomes.append(
                await call_tool(
                    session,
                    "gmail_get_thread",
                    {"params": {"thread_id": thread_id, "max_messages": THREAD_MESSAGES}},
                    f"# Gmail thread `{thread_id}`",
                )
            )

    errors = [f"{outcome.tool}: {outcome.error}" for outcome in outcomes if outcome.is_error]
    assert not errors, "tools that answered with an error: " + "; ".join(errors)
    unexpected = [outcome.tool for outcome in outcomes if not outcome.starts_as_expected]
    assert not unexpected, "tools whose result does not start with their heading: " + ", ".join(unexpected)
    message_hits, thread_hits = len(search.message_ids), len(threads.thread_ids)
    assert message_hits <= PAGE, "gmail_search_messages listed more than max_results"
    assert thread_hits <= PAGE, "gmail_search_threads listed more than max_results"

    ran = [outcome.tool for outcome in outcomes]
    missing = [tool for tool in TOOLS if tool not in ran]
    if missing:
        pytest.skip(f"the scope has no message or thread to read, so {', '.join(missing)} could not run")
