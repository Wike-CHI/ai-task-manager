"""Real SDK stdio client/server test. Fixtures never execute a native CLI."""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tempfile
from datetime import timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp_bridge.server import SAFE_FAILURE, serve


async def fixture(error_report: bool) -> None:
    calls = 0

    async def fake(command: str) -> dict:
        nonlocal calls
        calls += 1
        if error_report and command == "report":
            raise RuntimeError("PRIVATE_BACKEND_STDERR_TOKEN_7ea")
        result = {"schemaVersion": 1, "readOnly": True,
                  "kind": "snapshot" if command == "snapshot" else "findings",
                  "sampling": {"startMs": "1", "endMs": "2", "complete": True,
                               "processEnumerationComplete": True},
                  "testCalls": calls}
        result["processes" if command == "snapshot" else "findings"] = []
        return result

    await serve(fake)


async def exercise(cli: str | None, error_report: bool = False) -> int:
    if cli:
        args = ["-m", "mcp_bridge.server", "--cli", str(Path(cli).resolve())]
    else:
        args = [str(Path(__file__).resolve()), "--fixture"]
        if error_report:
            args.append("--fixture-error")
    parameters = StdioServerParameters(command=sys.executable, args=args, cwd=str(ROOT))
    count = 0

    def check(condition: bool, label: str) -> None:
        nonlocal count
        if not condition:
            raise AssertionError(label)  # Never include returned snapshot/path data.
        count += 1
        print("PASS " + label)

    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as errors:
        async with stdio_client(parameters, errlog=errors) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=timedelta(seconds=30)) as session:
                initialized = await session.initialize()
                check(initialized.protocolVersion == "2025-11-25", "official SDK negotiates tested MCP 2025-11-25")
                check(initialized.capabilities.tools is not None, "tools capability advertised")
                check(initialized.capabilities.resources is None and initialized.capabilities.prompts is None
                      and initialized.capabilities.logging is None, "no extra data or action capabilities advertised")
                tools = (await session.list_tools()).tools
                check({tool.name for tool in tools} == {"task_manager_snapshot", "task_manager_report"},
                      "only two read-only tools are discoverable")
                check(all(t.inputSchema.get("additionalProperties") is False and t.inputSchema.get("properties") == {}
                          for t in tools), "tools advertise no-argument strict schemas")
                check(all(t.annotations and t.annotations.readOnlyHint is True
                          and t.annotations.destructiveHint is False and t.annotations.openWorldHint is False
                          for t in tools), "read-only closed-world annotations match implementation")
                await session.send_ping()
                check(True, "SDK ping works across real stdio subprocess")
                result = await session.call_tool("task_manager_snapshot", {})
                check(not result.isError and result.structuredContent is not None, "snapshot returns structured content")
                snapshot = result.structuredContent
                check(snapshot["schemaVersion"] == 1 and snapshot["readOnly"] is True and snapshot["kind"] == "snapshot",
                      "snapshot envelope preserved")
                check(len(result.content) == 1 and result.content[0].type == "text"
                      and json.loads(result.content[0].text) == snapshot, "text JSON and structuredContent agree")
                for name, arguments in [("kill", {}), ("task_manager_snapshot", {"PRIVATE_ARGUMENT_VALUE": "DO_NOT_ECHO"}),
                                        ("task_manager_report", {"command": "terminate"})]:
                    rejected = await session.call_tool(name, arguments)
                    encoded = rejected.model_dump_json()
                    check(bool(rejected.isError) and "DO_NOT_ECHO" not in encoded
                          and "PRIVATE_ARGUMENT_VALUE" not in encoded, "unknown/write/extra arguments rejected without echo")
                second = await session.call_tool("task_manager_snapshot")
                if not cli:
                    check(second.structuredContent["testCalls"] == 2, "rejected requests never invoke backend")
                else:
                    check(not second.isError, "native CLI can be called again without server-side writes")
                report = await session.call_tool("task_manager_report", {})
                if error_report:
                    check(bool(report.isError) and report.content[0].text == SAFE_FAILURE,
                          "backend exception is a fixed sanitized MCP tool error")
                else:
                    check(not report.isError and report.structuredContent["kind"] == "findings",
                          "report returns deterministic findings through real protocol")
                errors.flush()
        errors.seek(0)
        check("PRIVATE_BACKEND_STDERR_TOKEN_7ea" not in errors.read(), "raw backend exception never reaches stderr logs")
    return count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cli")
    parser.add_argument("--fixture", action="store_true")
    parser.add_argument("--fixture-error", action="store_true")
    args = parser.parse_args()
    if args.fixture:
        asyncio.run(fixture(args.fixture_error))
        return 0
    count = asyncio.run(exercise(args.cli))
    if not args.cli:
        count += asyncio.run(exercise(None, True))
    print(f"{count} MCP SDK stdio checks passed; no 2026 protocol claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
