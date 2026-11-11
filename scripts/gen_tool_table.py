"""Print the README's "Available Tools" table from the live registry.

Usage: `uv run python scripts/gen_tool_table.py [--check | --write]`

Groups tools by module in board order and takes each tool's first docstring line as its
description, so the README can never drift from the code. The table lives between
`<!-- TOOL TABLE START -->` / `<!-- TOOL TABLE END -->` markers in README.md: `--write`
replaces it in place, `--check` exits 1 when it is stale.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

from gmail_mcp.server import mcp

# Board order, with the README group titles.
MODULE_ORDER: list[tuple[str, str]] = [
    ("health", "Health"),
    ("messages", "Messages — search and read"),
    ("threads", "Threads — search and read whole conversations"),
    ("labels", "Labels"),
    ("attachments", "Attachments — saved to a file, never inlined"),
]

LEGEND = "Every tool is read-only: the server holds a gmail.readonly token and only ever sends GET."

START = "<!-- TOOL TABLE START -->"
END = "<!-- TOOL TABLE END -->"


def _first_line(doc: str | None) -> str:
    return (doc or "").strip().splitlines()[0].strip() if doc else ""


def build_table() -> str:
    tools = asyncio.run(mcp.list_tools())
    by_module: dict[str, list[tuple[str, str]]] = {}
    manager = mcp._tool_manager  # noqa: SLF001 — the SDK exposes no public per-tool module lookup
    for tool in tools:
        registered = manager.get_tool(tool.name)
        fn = getattr(registered, "fn", None)
        module = (getattr(fn, "__module__", "") or "").rsplit(".", 1)[-1]
        by_module.setdefault(module, []).append((tool.name, _first_line(tool.description)))

    lines = ["| Tool | Description |", "|---|---|"]
    total = 0
    for module, title in MODULE_ORDER:
        rows = sorted(by_module.pop(module, []))
        if not rows:
            continue
        lines.append(f"| **{title}** | |")
        for name, desc in rows:
            lines.append(f"| `{name}` | {desc} |")
            total += 1
    for module, rows in by_module.items():  # anything not in MODULE_ORDER — should be empty
        lines.append(f"| **{module}** | |")
        for name, desc in sorted(rows):
            lines.append(f"| `{name}` | {desc} |")
            total += 1
    noun = "tool" if total == 1 else "tools"
    header = f"All **{total} {noun}**, grouped by module. {LEGEND}"
    return header + "\n\n" + "\n".join(lines) + "\n"


def _splice(readme: str, table: str) -> str:
    head, start, rest = readme.partition(START)
    _, end, tail = rest.partition(END)
    if not start or not end:
        raise SystemExit(f"README.md lacks the {START} / {END} markers")
    return f"{head}{START}\n{table}{END}{tail}"


def main() -> int:
    table = build_table()
    readme_path = Path(__file__).resolve().parents[1] / "README.md"
    readme = readme_path.read_text()
    if "--check" in sys.argv:
        if _splice(readme, table) != readme:
            sys.stderr.write("README.md tool table is stale — run scripts/gen_tool_table.py --write\n")
            return 1
        return 0
    if "--write" in sys.argv:
        readme_path.write_text(_splice(readme, table))
        return 0
    sys.stdout.write(table)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
