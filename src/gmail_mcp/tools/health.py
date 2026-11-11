"""Health tool — the in-repo exemplar of the house tool style.

Wave workers: copy this module's shape (decorator, annotations, docstring sections, the
`try` / `raise tool_error(exc) from None` wrapper, `clip_response` on the way out). It reads
the profile the account pin matched (`client.pinned_profile()`, which also refreshes the
access token and therefore runs the gmail.readonly check), resolves the project scope, and
reports both, so the model knows up front which mailbox and which slice of it it can see.
It takes no arguments; every other tool takes ONE `params` model.
"""

from __future__ import annotations

from mcp.types import ToolAnnotations

import gmail_mcp
from gmail_mcp.auth import READONLY_SCOPE
from gmail_mcp.client import get_client
from gmail_mcp.config import get_settings
from gmail_mcp.errors import tool_error
from gmail_mcp.formatters import clip_response, fmt_size, one_line
from gmail_mcp.scope import ResolvedScope, get_scope
from gmail_mcp.server import mcp

# True in every mode, with no scope too: scope.apply() appends `-in:spam -in:trash` to every
# search, check_message() refuses a message in SPAM or TRASH, and a thread is shown without them.
SPAM_TRASH_LINE = (
    "- **spam and trash**: never shown — left out of every search (whatever the query), refused when read by id, "
    "and left out of every thread"
)


def _scope_lines(scope: ResolvedScope) -> list[str]:
    if scope.mode == "none":
        return ["- **scope**: none — every message in the mailbox except spam and trash", SPAM_TRASH_LINE]
    lines = [f"- **scope**: {scope.mode} — a filter on what tools show, not a security boundary"]
    if scope.label_id is not None:
        lines.append(f"- **scope label**: `{one_line(scope.label_name or scope.label_id)}` (id `{scope.label_id}`)")
    if scope.query is not None:
        lines.append(f"- **scope query**: `({one_line(scope.query)})`, ANDed with every search")
    lines.append(SPAM_TRASH_LINE)
    return lines


@mcp.tool(
    name="gmail_health",
    annotations=ToolAnnotations(
        title="Gmail Health",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def gmail_health() -> str:
    """Check the token, the pinned mailbox, the granted scopes and the active project scope.

    Refreshes the access token (which verifies the token is gmail.readonly only), reads the
    mailbox profile and checks it against GMAIL_ACCOUNT (the account pin), resolves the
    project scope (GMAIL_SCOPE_LABEL / GMAIL_SCOPE_QUERY), and reports the output bounds.

    When to Use:
    - As the first call after configuring the server, to confirm the token works.
    - To learn which mailbox this entry reads, and which slice of it (the scope).
    - To debug an auth, pin or scope error before trying other tools.

    When NOT to Use:
    - To search or read mail (use gmail_search_messages / gmail_get_message).
    - To list labels (use gmail_list_labels).

    Returns:
    A markdown block: the server version, the mailbox (email, messagesTotal,
    threadsTotal), the pin result, the granted scopes, the active scope (label name and
    id, query), and the body / attachment caps.

    Examples:
    - Call with no arguments: `gmail_health()` (the tool takes no `params`).

    Error Handling:
    A dead refresh token, a token that can do more than read, a token for another mailbox
    (pin mismatch) or an unknown GMAIL_SCOPE_LABEL fail the call with one line naming the
    cause and the fix; every other tool then fails the same way.
    """
    try:
        settings = get_settings()
        client = get_client()
        profile = await client.pinned_profile()
        scope = await get_scope().resolve()
        granted = client.auth.granted_scopes
        extra = sorted(set(granted) - {READONLY_SCOPE})
        lines = [
            "# Gmail health",
            "",
            f"- **server**: amazing-gmail-mcp {gmail_mcp.__version__} (stdio, read-only: GET requests only)",
            f"- **mailbox**: {one_line(str(profile.get('emailAddress') or ''))}",
            f"- **pin**: OK — the token belongs to GMAIL_ACCOUNT ({settings.account_email})",
            f"- **messagesTotal**: {profile.get('messagesTotal', 'N/A')}",
            f"- **threadsTotal**: {profile.get('threadsTotal', 'N/A')}",
            "- **granted scopes**: "
            + ", ".join(granted)
            + (f" (gmail.readonly plus identity only: {', '.join(extra)})" if extra else " (gmail.readonly only)"),
            *_scope_lines(scope),
            f"- **body cap**: {settings.body_max_chars} characters per call (page with `offset`)",
            f"- **attachments**: saved under {settings.attachment_path}, at most "
            f"{fmt_size(settings.attachment_max_bytes)} each",
        ]
        return clip_response("\n".join(lines))
    except Exception as exc:
        raise tool_error(exc) from None
