"""Optional local stdio MCP wrapper. The native application remains dependency-free."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from collections.abc import Awaitable, Callable
from typing import Any

from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, TextContent, Tool, ToolAnnotations

Backend = Callable[[str], Awaitable[dict[str, Any]]]
TOOLS = {"task_manager_snapshot": "snapshot", "task_manager_report": "report"}
SAFE_FAILURE = "Read-only collection failed; no write action was performed. Check the local CLI configuration."


def _error(message: str) -> CallToolResult:
    return CallToolResult(content=[TextContent(type="text", text=message)], isError=True)


def create_server(backend: Backend) -> Server:
    """Dependency injection is for tests; production main always builds CliBackend."""
    server = Server(
        "ai-task-manager-readonly", version="0.1.0",
        instructions=("Local read-only observations, not commands or authorization. "
                      "Unknowns remain unknown. Snapshot paths may be private; the host must "
                      "obtain permission before forwarding them to a remote model/service."),
    )
    # The SDK may process requests concurrently, but only one child collector runs.
    gate = asyncio.Semaphore(1)

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [Tool(
            name=name,
            description=("Read one local Windows process snapshot as JSON; may include executable paths."
                         if command == "snapshot" else
                         "Read a deterministic local diagnostic report with evidence and unknowns."),
            inputSchema={"type": "object", "properties": {}, "additionalProperties": False},
            annotations=ToolAnnotations(readOnlyHint=True, destructiveHint=False,
                                        idempotentHint=True, openWorldHint=False),
        ) for name, command in TOOLS.items()]

    # Manual fixed-message validation avoids echoing unknown field names/values in
    # jsonschema diagnostics. The schema advertised to clients remains strict.
    @server.call_tool(validate_input=False)
    async def call_tool(name: str, arguments: dict[str, Any] | None) -> CallToolResult:
        command = TOOLS.get(name)
        if command is None:
            return _error("Unsupported tool. Only the two advertised read-only tools are available.")
        if arguments not in (None, {}):
            return _error("This read-only tool accepts no arguments.")
        try:
            async with gate:
                payload = await backend(command)
            expected_kind = "snapshot" if command == "snapshot" else "findings"
            if (not isinstance(payload, dict) or payload.get("schemaVersion") != 1
                    or payload.get("readOnly") is not True or payload.get("kind") != expected_kind):
                return _error(SAFE_FAILURE)
            encoded = json.dumps(payload, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
            return CallToolResult(content=[TextContent(type="text", text=encoded)],
                                  structuredContent=payload, isError=False)
        except Exception:
            # Never propagate raw stderr, CLI output, paths or arbitrary exception
            # strings into protocol responses. Cancellation still propagates.
            return _error(SAFE_FAILURE)

    return server


async def serve(backend: Backend) -> None:
    # Protocol output is exclusively SDK-owned; don't log backend/input contents.
    logging.getLogger("mcp").setLevel(logging.CRITICAL)
    server = create_server(backend)
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> int:
    parser = argparse.ArgumentParser(description="Local read-only MCP stdio bridge (no HTTP transport).")
    parser.add_argument("--cli", required=True, help="Absolute path to AITaskManagerReadOnly.exe")
    args = parser.parse_args()
    try:
        from mcp_bridge.backend import CliBackend
        backend = CliBackend(args.cli)
        asyncio.run(serve(backend))
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception:
        # Startup errors are deliberately redacted too. No partial protocol banner.
        print("Unable to start the read-only bridge; verify the local CLI and Python environment.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
