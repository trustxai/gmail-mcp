"""FastMCP server definition and entry point for gmail_mcp (stdio only).

`RedactingFastMCP` is the one funnel every `tools/call`, `prompts/get` and
`resources/read` goes through, so what the SDK says on the server's behalf is redacted
too: an argument-validation failure (raised BEFORE a tool body runs) is re-rendered
without pydantic's `input_value` echo, and every message passes through
`errors.scrub`. The SDK's own log lines are scrubbed by `install_log_redaction`.
"""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING, Any

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError
from mcp.shared.exceptions import McpError
from pydantic import ValidationError

from gmail_mcp.config import get_settings
from gmail_mcp.errors import ConfigError, describe_validation_error, install_log_redaction, scrub

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from mcp.server.lowlevel.helper_types import ReadResourceContents
    from mcp.types import ContentBlock, GetPromptResult
    from pydantic import AnyUrl


def _same_type_scrubbed(exc: Exception) -> Exception:
    """`exc`'s type with a scrubbed message, so the SDK maps it exactly as before."""
    message = scrub(str(exc))
    try:
        return type(exc)(message)
    except Exception:  # a constructor that wants more than a message
        return RuntimeError(message)


class RedactingFastMCP(FastMCP):
    """FastMCP whose tool, prompt and resource errors never carry a credential or a raw echo."""

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Sequence[ContentBlock] | dict[str, Any]:
        try:
            return await super().call_tool(name, arguments)
        except McpError:
            # A JSON-RPC error the SDK must deliver as-is; never built from the arguments.
            raise
        except Exception as exc:  # ToolError in practice
            cause = exc.__cause__
            message = describe_validation_error(name, cause) if isinstance(cause, ValidationError) else scrub(str(exc))
            # `from None`: the unredacted original must not ride along in a traceback.
            raise ToolError(message) from None

    async def get_prompt(self, name: str, arguments: dict[str, Any] | None = None) -> GetPromptResult:
        try:
            return await super().get_prompt(name, arguments)
        except McpError:
            raise
        except Exception as exc:  # `Unknown prompt: <name>`
            raise _same_type_scrubbed(exc) from None

    async def read_resource(self, uri: AnyUrl | str) -> Iterable[ReadResourceContents]:
        try:
            return await super().read_resource(uri)
        except McpError:
            raise
        except Exception as exc:  # `Unknown resource: <uri>`
            raise _same_type_scrubbed(exc) from None


mcp = RedactingFastMCP("gmail_mcp")

# FastMCP configures root logging at INFO to stderr, which MCP clients persist to log
# files. At INFO, httpx logs one "HTTP Request: …" line per call (the URL names what the
# account just read), so quiet it down to WARNING; httpcore is pinned too.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
install_log_redaction()

# Register all tools (side-effect imports via decorators).
from gmail_mcp.tools import register_all  # noqa: E402

register_all(mcp)


def main_stdio() -> None:
    """Entry point for local / Docker stdio transport (`amazing-gmail-mcp`).

    The configuration is validated first, so a misconfigured entry exits at once (status 2)
    with a message naming the variable, instead of failing at the first tool call. There
    is deliberately no HTTP entry point: the refresh token reads a whole mailbox and never
    leaves the machine that runs it.
    """
    try:
        get_settings()
    except ConfigError as exc:
        sys.stderr.write(f"amazing-gmail-mcp: {scrub(str(exc))}\n")
        raise SystemExit(2) from None
    mcp.run()


if __name__ == "__main__":
    main_stdio()
