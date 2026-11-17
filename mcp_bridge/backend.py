"""Bounded adapter to an explicitly selected, local read-only Windows CLI.

No request controls argv, executable, environment, transport or output destination.
Only the process started by this adapter may be terminated during cleanup.
"""
from __future__ import annotations
import asyncio
import json
from pathlib import Path
import sys
from typing import Any

MAX_STDOUT = 8 * 1024 * 1024
MAX_STDERR = 16 * 1024
CLI_TIMEOUT_SECONDS = 15

class BackendError(RuntimeError):
    """Safe public error: never contains child stderr, paths or raw JSON."""

async def _read_bounded(reader: asyncio.StreamReader, limit: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await reader.read(min(65536, limit - total + 1))
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > limit:
            raise BackendError("CLI output exceeded the configured limit")
        chunks.append(chunk)

async def _capture_process(argv: list[str]) -> tuple[int, bytes]:
    """Internal bounded runner. Never accepts tool-supplied argv."""
    process = None
    readers: list[asyncio.Task[bytes]] = []
    try:
        async with asyncio.timeout(CLI_TIMEOUT_SECONDS):
            process = await asyncio.create_subprocess_exec(
                *argv, stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            assert process.stdout is not None and process.stderr is not None
            readers = [asyncio.create_task(_read_bounded(process.stdout, MAX_STDOUT)),
                       asyncio.create_task(_read_bounded(process.stderr, MAX_STDERR))]
            stdout, _ = await asyncio.gather(*readers)
            status = await process.wait()
            return status, stdout
    except TimeoutError:
        raise BackendError("CLI observation timed out") from None
    except OSError:
        raise BackendError("CLI could not be started") from None
    finally:
        for task in readers:
            if not task.done():
                task.cancel()
        if readers:
            await asyncio.gather(*readers, return_exceptions=True)
        if process is not None and process.returncode is None:
            # Cleanup is confined to the owned child, never a PID supplied by a client.
            try:
                process.kill()
            except ProcessLookupError:
                pass
            try:
                # Drain only after killing the owned child; remaining pipe buffers
                # are finite. Do not let a stuck inherited pipe defeat the timeout.
                await asyncio.wait_for(process.communicate(), timeout=2)
            except TimeoutError:
                raise BackendError("CLI cleanup did not complete") from None


def _reject_constant(_: str) -> None:
    raise ValueError("nonfinite JSON")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def validate_payload(command: str, raw: bytes) -> dict[str, Any]:
    try:
        payload = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant,
                             object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError, RecursionError):
        raise BackendError("CLI returned invalid JSON") from None
    expected_kind = {"snapshot": "snapshot", "report": "findings"}.get(command)
    if not isinstance(payload, dict) or expected_kind is None:
        raise BackendError("CLI returned an invalid envelope")
    if type(payload.get("schemaVersion")) is not int or payload["schemaVersion"] != 1 or payload.get("readOnly") is not True or payload.get("kind") != expected_kind:
        raise BackendError("CLI returned an unsupported envelope")
    sample = payload.get("sampling")
    if not isinstance(sample, dict) or type(sample.get("complete")) is not bool or type(sample.get("processEnumerationComplete")) is not bool:
        raise BackendError("CLI omitted sampling completeness")
    for key in ("startMs", "endMs"):
        value = sample.get(key)
        if not isinstance(value, str) or not value.isascii() or not value.isdigit() or len(value) > 20:
            raise BackendError("CLI returned invalid sampling timestamps")
    if int(sample["endMs"]) < int(sample["startMs"]):
        raise BackendError("CLI returned reversed sampling timestamps")
    collection = payload.get("processes" if command == "snapshot" else "findings")
    if not isinstance(collection, list):
        raise BackendError("CLI omitted its evidence collection")
    return payload


class CliBackend:
    def __init__(self, cli: str):
        if sys.platform != "win32":
            raise BackendError("The native read-only CLI requires Windows")
        if cli.startswith(("\\\\", "//")):
            raise BackendError("Network and device paths are not supported")
        path = Path(cli)
        if not path.is_absolute() or path.suffix.lower() != ".exe" or not path.is_file():
            raise BackendError("Select an existing absolute path to the read-only .exe")
        resolved = path.resolve(strict=True)
        if str(resolved).startswith(("\\\\", "//")) or resolved.suffix.lower() != ".exe" or not resolved.is_file():
            raise BackendError("Resolved CLI path must remain a local .exe")
        self._cli = str(resolved)
        self._lock = asyncio.Lock()

    async def __call__(self, command: str) -> dict[str, Any]:
        if command not in ("snapshot", "report"):
            raise BackendError("Unsupported read-only command")
        # Serialize observations. No per-request path, arguments or environment.
        async with self._lock:
            status, raw = await _capture_process([self._cli, command])
        if status not in (0, 3):
            raise BackendError("CLI observation failed")
        payload = validate_payload(command, raw)
        # Exit 3 is a partial observation, not fabricated success or an empty list.
        if (status == 3) == payload["sampling"]["processEnumerationComplete"]:
            raise BackendError("CLI exit status disagrees with completeness")
        return payload
