"""stdlib tests: no remote connections, no user processes or real credentials."""
import asyncio
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from mcp_bridge import backend as b


def payload(kind="snapshot", complete=True):
    return {"schemaVersion": 1, "readOnly": True, "kind": kind,
            "sampling": {"startMs": "10", "endMs": "20", "complete": True,
                         "processEnumerationComplete": complete},
            "processes" if kind == "snapshot" else "findings": []}


class PayloadTests(unittest.TestCase):
    def test_valid_and_partial(self):
        for complete in (True, False):
            data = payload(complete=complete)
            self.assertEqual(b.validate_payload("snapshot", json.dumps(data).encode()), data)

    def test_reject_malformed_and_secret_errors(self):
        for raw in (b"not json SECRET", b"{\"schemaVersion\":1,\"schemaVersion\":1}", b"NaN", b"[]", b"\xff"):
            with self.assertRaises(b.BackendError) as caught:
                b.validate_payload("snapshot", raw)
            self.assertNotIn("SECRET", str(caught.exception))

    def test_envelope_and_timing_fail_closed(self):
        for key, value in (("schemaVersion", True), ("schemaVersion", 2), ("readOnly", False), ("kind", "write"), ("processes", {})):
            data = payload(); data[key] = value
            with self.assertRaises(b.BackendError): b.validate_payload("snapshot", json.dumps(data).encode())
        for key, value in (("startMs", 10), ("endMs", "9"), ("endMs", "NaN"), ("complete", "true")):
            data = payload(); data["sampling"][key] = value
            with self.assertRaises(b.BackendError): b.validate_payload("snapshot", json.dumps(data).encode())

    def test_report_kind(self):
        self.assertEqual(b.validate_payload("report", json.dumps(payload("findings")).encode())["kind"], "findings")
        with self.assertRaises(b.BackendError): b.validate_payload("report", json.dumps(payload()).encode())

    def test_executable_validation(self):
        with patch.object(sys, "platform", "win32"):
            for path in ("relative.exe", "https://example.invalid/a.exe", "missing.cmd", r"\\server\share\readonly.exe", "//server/share/readonly.exe"):
                with self.assertRaises(b.BackendError): b.CliBackend(path)
        with patch.object(sys, "platform", "linux"):
            with self.assertRaises(b.BackendError): b.CliBackend("anything.exe")


class AsyncTests(unittest.IsolatedAsyncioTestCase):
    async def test_exact_argv_rejection_and_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            exe = Path(directory) / "readonly.exe"; exe.write_bytes(b"test placeholder, never executed")
            with patch.object(sys, "platform", "win32"):
                runner = b.CliBackend(str(exe.resolve()))
            capture = AsyncMock(return_value=(3, json.dumps(payload(complete=False)).encode()))
            with patch.object(b, "_capture_process", capture):
                with self.assertRaises(b.BackendError): await runner("kill; SECRET")
                capture.assert_not_called()
                result = await runner("snapshot")
                self.assertFalse(result["sampling"]["processEnumerationComplete"])
                capture.assert_awaited_once_with([str(exe.resolve()), "snapshot"])

    async def test_inconsistent_exit_status(self):
        runner = object.__new__(b.CliBackend); runner._cli = "fixed.exe"; runner._lock = asyncio.Lock()
        for code in (1, 3):
            with patch.object(b, "_capture_process", AsyncMock(return_value=(code, json.dumps(payload()).encode()))):
                with self.assertRaises(b.BackendError): await runner("snapshot")

    async def test_success_must_not_hide_incomplete_enumeration(self):
        runner = object.__new__(b.CliBackend); runner._cli = "fixed.exe"; runner._lock = asyncio.Lock()
        with patch.object(b, "_capture_process", AsyncMock(return_value=(0, json.dumps(payload(complete=False)).encode()))):
            with self.assertRaises(b.BackendError): await runner("snapshot")

    async def test_owned_child_normal_stdout(self):
        code, raw = await b._capture_process([sys.executable, "-c", "print('ok')"])
        self.assertEqual(code, 0); self.assertEqual(raw.strip(), b"ok")

    async def test_output_limit_and_no_stderr_leak(self):
        for stream, limit in (("stdout", "MAX_STDOUT"), ("stderr", "MAX_STDERR")):
            with patch.object(b, limit, 128):
                with self.assertRaises(b.BackendError) as caught:
                    await asyncio.wait_for(b._capture_process([sys.executable, "-c", f"import sys; sys.{stream}.write('SECRET'*10000)"]), 5)
            self.assertNotIn("SECRET", str(caught.exception))

    async def test_timeout_and_cancellation_clean_owned_child(self):
        with patch.object(b, "CLI_TIMEOUT_SECONDS", .1):
            with self.assertRaises(b.BackendError):
                await asyncio.wait_for(b._capture_process([sys.executable, "-c", "import time;time.sleep(30)"]), 5)
        task = asyncio.create_task(b._capture_process([sys.executable, "-c", "import time;time.sleep(30)"]))
        await asyncio.sleep(.1); task.cancel()
        with self.assertRaises(asyncio.CancelledError): await asyncio.wait_for(task, 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
