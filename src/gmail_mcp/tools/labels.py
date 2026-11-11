"""Label tool — `gmail_list_labels`.

One `labels.list` request lists every label of the pinned mailbox: its id (what Gmail's
`labelIds` take, and what GMAIL_SCOPE_LABEL may name), its name, and its type — `system`
for Gmail's own (INBOX, SENT, SPAM, CATEGORY_…), `user` for the ones people create. System
labels come first, then user labels, each group sorted by name (case-insensitive, then id).

The label GMAIL_SCOPE_LABEL resolves to is marked, so the model knows which label every
search is limited to. Label NAMES are not filtered by the scope: the scope narrows which
messages tools show (ADR D5), and a label definition is not a message. An unknown
GMAIL_SCOPE_LABEL still fails this call, like every other tool ("refuse to run").

It takes no arguments, like `gmail_health`.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from mcp.types import ToolAnnotations

from gmail_mcp.client import get_client
from gmail_mcp.errors import tool_error
from gmail_mcp.formatters import clip_response, one_line
from gmail_mcp.scope import ResolvedScope, get_scope
from gmail_mcp.server import mcp

SYSTEM = "system"
USER = "user"
EMPTY_LINE = "_No labels in this mailbox._"
SCOPE_MARK = "**scope label** (every search is limited to it)"


def label_type(label: Mapping[str, Any]) -> str:
    """`system` for Gmail's own labels, `user` for everything else (Gmail has only the two)."""
    return SYSTEM if str(label.get("type") or "").strip().lower() == SYSTEM else USER


def label_name(label: Mapping[str, Any]) -> str:
    """The label's name on one line (its id when Gmail sends no name)."""
    return one_line(str(label.get("name") or "")) or str(label["id"])


def sort_labels(labels: list[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """System labels first, then user labels; each group by name (case-insensitive), then id."""
    return sorted(
        labels,
        key=lambda label: (label_type(label) != SYSTEM, label_name(label).casefold(), str(label["id"])),
    )


def usable_labels(body: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """The `labels` of a `labels.list` answer that carry an id (Gmail omits an empty list)."""
    raw = body.get("labels")
    if not isinstance(raw, list):
        return []
    return [label for label in raw if isinstance(label, Mapping) and isinstance(label.get("id"), str) and label["id"]]


def _scope_line(scope: ResolvedScope) -> str:
    if scope.label_id is not None:
        name = one_line(scope.label_name or scope.label_id)
        return f"Scope label: `{name}` (id `{scope.label_id}`) — a filter on what tools show, not a security boundary."
    if scope.query is not None:
        return f"No scope label (the project scope is the query `({one_line(scope.query)})`)."
    return "No scope label: searches cover the whole mailbox (spam and trash excluded)."


def render_labels(labels: list[Mapping[str, Any]], scope: ResolvedScope) -> str:
    """The markdown block `gmail_list_labels` returns."""
    ordered = sort_labels(labels)
    system = sum(1 for label in ordered if label_type(label) == SYSTEM)
    lines = [
        f"# Gmail labels ({len(ordered)}: {system} system, {len(ordered) - system} user)",
        "",
        _scope_line(scope),
        "",
    ]
    if not ordered:
        lines.append(EMPTY_LINE)
    marked = False
    for label in ordered:
        line = f"- `{label_name(label)}` · id `{label['id']}` · {label_type(label)}"
        if scope.label_id is not None and label["id"] == scope.label_id:
            line += f" · {SCOPE_MARK}"
            marked = True
        lines.append(line)
    if scope.label_id is not None and not marked:
        lines += [
            "",
            f"Note: the scope label (id `{scope.label_id}`) is not in this list any more. The server resolved it when "
            "it started: fix GMAIL_SCOPE_LABEL (or recreate the label) and restart this entry.",
        ]
    return "\n".join(lines)


@mcp.tool(
    name="gmail_list_labels",
    annotations=ToolAnnotations(
        title="List Gmail Labels",
        readOnlyHint=True,
        destructiveHint=False,
        idempotentHint=True,
        openWorldHint=True,
    ),
)
async def gmail_list_labels() -> str:
    """List the mailbox's labels — id, name and type (system/user) — marking the scope label.

    Reads every label of the pinned mailbox with one `labels.list` request. System labels
    (INBOX, SENT, SPAM, CATEGORY_…) come first, then the user's own labels, each group
    sorted by name. When GMAIL_SCOPE_LABEL is set, the label it resolved to is marked:
    every search this server runs is limited to it.

    When to Use:
    - To find a label's id, or the exact name to use in a `label:` search.
    - To see which label the project scope (GMAIL_SCOPE_LABEL) limits searches to.
    - Before searching by a label whose exact spelling you do not know.

    When NOT to Use:
    - To search or read mail (use gmail_search_messages / gmail_get_message).
    - To check the token, the pinned mailbox or the whole active scope (use gmail_health).

    Returns:
    A markdown block: a count line (system / user), the scope label line, then one line
    per label — `name` · id `ID` · system|user — with the scope label marked. An empty
    mailbox gives a line saying there are no labels.

    Examples:
    - Call with no arguments: `gmail_list_labels()` (the tool takes no `params`).

    Error Handling:
    A dead refresh token, a token that can do more than read, a token for another mailbox
    (pin mismatch) or an unknown GMAIL_SCOPE_LABEL fail the call with one line naming the
    cause and the fix. Gmail errors (quota, 5xx after retries) come back the same way.
    """
    try:
        scope = await get_scope().resolve()
        body = await get_client().get("users/me/labels")
        return clip_response(render_labels(usable_labels(body), scope))
    except Exception as exc:
        raise tool_error(exc) from None
