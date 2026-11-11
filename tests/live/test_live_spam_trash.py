"""Live: spam and trash never reach a search, whatever the query asks for.

`includeSpamTrash=false` alone does not stop a query such as `in:anywhere`, `in:spam` or
`in:trash`, so the server also appends `-in:spam -in:trash` to every list query
(scope.apply). For each of those three queries, both the raw `messages.list` the server sends
and gmail_search_messages must return no hit labelled SPAM or TRASH — checked on each hit's
labelIds read back through `format=metadata`, not on what the result prints.

A control runs first and is recorded: how many of the newest hits for the same query are
labelled SPAM or TRASH when the server's exclusion is NOT applied. When that is zero the
mailbox has nothing there for the exclusion to keep out, so the checks above pass without
proving anything: the test still runs them, then skips and says so.
"""

from __future__ import annotations

import pytest

from ._support import LiveRecord, bounded, scoped_list, search_messages_check, unexcluded_list

pytestmark = pytest.mark.live

# Hits checked per query, by each list (each one's labels are read back through metadata).
SAMPLE = 25


@pytest.mark.parametrize("query", ["in:anywhere", "in:spam", "in:trash"])
async def test_live_spam_and_trash_stay_out_of_the_raw_list_and_the_search(query: str, live_record: LiveRecord) -> None:
    async with bounded():
        control = await unexcluded_list(query, SAMPLE)
        raw = await scoped_list(query, SAMPLE)
        search = await search_messages_check(query, SAMPLE)

    in_spam_or_trash = control.spam_or_trash
    live_record(f"of the newest {SAMPLE} hits without the exclusion, labelled SPAM or TRASH", str(in_spam_or_trash))
    raw_flagged = raw.spam_or_trash
    stated, parsed = search.page.stated, len(search.page.ids)
    listed_flagged, search_flagged = search.page.listed_spam_or_trash, search.spam_or_trash

    assert raw_flagged == 0, "the raw list the server sends returned hits labelled SPAM or TRASH"
    assert stated == parsed, "the hits read from gmail_search_messages are not the count it states"
    assert listed_flagged == 0, "gmail_search_messages printed labels SPAM or TRASH on a hit"
    assert search_flagged == 0, "gmail_search_messages returned hits whose metadata says SPAM or TRASH"
    if not in_spam_or_trash:
        pytest.skip(
            f"nothing to keep out: none of the newest {SAMPLE} hits for {query} is in spam or trash without the "
            "server's exclusion, so the checks passed without proving it"
        )
