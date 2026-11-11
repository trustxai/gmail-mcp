"""Registry + entry-point tests for the Stage-0 spine."""

from __future__ import annotations

import importlib
import importlib.metadata
import os
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

import gmail_mcp
import gmail_mcp.server as server
from gmail_mcp.server import mcp

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MODULES = ["attachments", "health", "labels", "messages", "threads"]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())


def _clean_env(tmp_path: Path) -> dict[str, str]:
    return {"HOME": str(tmp_path), "PATH": os.environ.get("PATH", ""), "LANG": "en_US.UTF-8"}


def test_registry_imports_every_wave_module() -> None:
    for name in EXPECTED_MODULES:
        assert f"gmail_mcp.tools.{name}" in sys.modules, f"tools/{name}.py is not imported by register_all"


async def test_health_is_registered_with_the_house_annotations() -> None:
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    health = tools["gmail_health"]
    assert health.annotations is not None
    assert health.annotations.readOnlyHint is True
    assert health.annotations.destructiveHint is False
    assert health.annotations.idempotentHint is True
    assert health.annotations.openWorldHint is True
    assert (health.description or "").splitlines()[0].startswith("Check the token, the pinned mailbox")
    assert health.inputSchema.get("properties") == {}


async def test_the_exemplar_docstring_has_every_section_in_order() -> None:
    tools = {tool.name: tool for tool in await mcp.list_tools()}
    description = tools["gmail_health"].description or ""
    sections = ["When to Use:", "When NOT to Use:", "Returns:", "Examples:", "Error Handling:"]
    positions = [description.find(section) for section in sections]
    assert all(position > 0 for position in positions), dict(zip(sections, positions, strict=True))
    assert positions == sorted(positions)


async def test_every_registered_tool_follows_the_tool_contract() -> None:
    # Spec §Tool contract: prefix, read-only annotations, a description.
    for tool in await mcp.list_tools():
        assert tool.name.startswith("gmail_"), tool.name
        assert tool.annotations is not None, tool.name
        assert tool.annotations.readOnlyHint is True, tool.name
        assert tool.annotations.destructiveHint is False, tool.name
        assert tool.annotations.openWorldHint is True, tool.name
        assert tool.description, tool.name


def test_console_scripts_and_no_http_entry_point() -> None:
    project = PYPROJECT["project"]
    assert project["name"] == "amazing-gmail-mcp"
    assert project["scripts"] == {
        "amazing-gmail-mcp": "gmail_mcp.server:main_stdio",
        "amazing-gmail-mcp-login": "gmail_mcp.login:main",
    }
    assert not hasattr(server, "main_http")
    assert callable(server.main_stdio)


def test_dependencies_and_the_live_marker() -> None:
    deps = PYPROJECT["project"]["dependencies"]
    assert deps == ["mcp>=1.21.1,<2", "httpx>=0.27", "pydantic>=2.7", "pydantic-settings>=2.4", "python-dotenv>=1.0"]
    assert PYPROJECT["project"]["requires-python"] == ">=3.13"
    assert any(marker.startswith("live:") for marker in PYPROJECT["tool"]["pytest"]["ini_options"]["markers"])
    assert PYPROJECT["tool"]["mypy"]["strict"] is True


def test_version_comes_from_the_installed_distribution() -> None:
    assert gmail_mcp.__version__ == importlib.metadata.version("amazing-gmail-mcp")


def test_version_falls_back_when_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", missing)
    try:
        assert importlib.reload(gmail_mcp).__version__ == "0.0.0"
    finally:
        monkeypatch.undo()
        importlib.reload(gmail_mcp)
    assert gmail_mcp.__version__ == importlib.metadata.version("amazing-gmail-mcp")


def test_python_m_entry_point_runs_stdio() -> None:
    assert "main_stdio()" in (ROOT / "src" / "gmail_mcp" / "__main__.py").read_text()


def test_the_server_exits_at_once_naming_the_missing_variables(tmp_path: Path) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "gmail_mcp"],
        capture_output=True,
        text=True,
        env=_clean_env(tmp_path),
        cwd=tmp_path,
        stdin=subprocess.DEVNULL,
        timeout=60,
    )
    assert result.returncode == 2
    assert result.stderr.startswith("amazing-gmail-mcp: configuration error: ")
    for name in ("GMAIL_ACCOUNT", "GMAIL_REFRESH_TOKEN", "GMAIL_CLIENT_SECRET_FILE"):
        assert name in result.stderr
    assert "Traceback" not in result.stderr
