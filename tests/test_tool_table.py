"""The README's tool table matches the registry (the same check CI runs with --check)."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "gen_tool_table.py"


def _load():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("gen_tool_table", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_readme_tool_table_is_current(monkeypatch: pytest.MonkeyPatch) -> None:
    gen = _load()
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "--check"])
    assert gen.main() == 0, "README.md tool table is stale — run scripts/gen_tool_table.py --write"


def test_the_table_lists_every_registered_module_in_board_order() -> None:
    gen = _load()
    table = gen.build_table()
    assert "| **Health** | |" in table
    assert "`gmail_health`" in table
    assert [module for module, _ in gen.MODULE_ORDER] == ["health", "messages", "threads", "labels", "attachments"]
