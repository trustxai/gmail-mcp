"""Read-only MCP server for one Gmail mailbox (gmail.readonly by construction; account pinned; stdio only)."""

from importlib.metadata import PackageNotFoundError, version

try:
    # Read from the installed distribution, so it never drifts from release-please's bump.
    __version__ = version("amazing-gmail-mcp")
except PackageNotFoundError:  # running from a source tree that is not installed
    __version__ = "0.0.0"
