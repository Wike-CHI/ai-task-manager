"""Real child lifecycle tests with offline, network-blocking worker fixtures."""
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from llm_adapter import transport

ENDPOINT = "http://127.0.0.1:8080/v1/chat/completions"


class Tests(unittest.TestCase):
    def setUp(self):
        self.children = []
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.marker = Path(self.temp.name) / "entered-blocking-stage"

    def tearDown(self):
        for child in self.children:
            # Assert the production finally block reaped it, not test cleanup.
            try:
                self.assertIsNotNone(child.poll())
                self.assertTrue(child.stdin.closed)
                self.assertTrue(child.stdout.closed)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=2)

    def spawn(self, mode):
        child = subprocess.Popen([sys.executable, "-I", str(Path(__file__).with_name("llm_worker_fixture.py")), mode, str(self.marker)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.children.append(child)
        return child

    def run_request(self, mode="success", timeout=2, cancel=None):
        endpoint = "https://example.com/v1/chat/completions" if mode == "dns" else ENDPOINT
        with patch.object(transport, "_spawn_worker", side_effect=lambda: self.spawn(mode)):
            return transport.explain_with_transport([], enabled=True,
                config=transport.TransportConfig(endpoint, "test", "remote" if mode == "dns" else "local", timeout),
                authorized_endpoint=endpoint, cancel_event=cancel)

    def test_success_real_ipc(self):
        result = self.run_request()
        self.assertEqual(result["untrustedExplanation"], "offline advice")
        self.assertFalse(result["writeAuthorized"])
        self.assertFalse(result["explanationTrusted"])

    def test_dns_deadline_reaps_worker(self):
        start = time.monotonic()
        self.assertEqual(self.run_request("dns", timeout=2)["status"], "providerError")
        self.assertTrue(self.marker.exists(), "Fixture must reach the DNS stall")
        self.assertLess(time.monotonic() - start, 4)

    def test_slow_body_deadline_reaps_worker(self):
        start = time.monotonic()
        self.assertEqual(self.run_request("body", timeout=2)["status"], "providerError")
        self.assertTrue(self.marker.exists(), "Fixture must reach the body stall")
        self.assertLess(time.monotonic() - start, 4)
        # The concurrency slot is restored after timeout.
        self.assertEqual(self.run_request()["status"], "explained")

    def test_cancel_before_start_never_spawns(self):
        cancel = threading.Event()
        cancel.set()
        self.assertEqual(self.run_request(cancel=cancel)["status"], "providerError")
        self.assertEqual(self.children, [])

    def test_cancel_running_reaps_worker(self):
        cancel = threading.Event()
        def cancel_when_blocked():
            until = time.monotonic() + 3
            while not self.marker.exists() and time.monotonic() < until:
                time.sleep(0.01)
            cancel.set()
        timer = threading.Thread(target=cancel_when_blocked)
        timer.start()
        try:
            start = time.monotonic()
            self.assertEqual(self.run_request("body", timeout=5, cancel=cancel)["status"], "providerError")
            self.assertTrue(self.marker.exists(), "Cancel only after the worker blocks")
            self.assertLess(time.monotonic() - start, 4)
        finally:
            timer.join()

    def test_failure_sanitized_and_reaped(self):
        result = self.run_request("error")
        self.assertEqual(result["status"], "providerError")
        self.assertNotIn("Network forbidden", str(result))

    def test_disabled_never_spawns(self):
        with patch.object(transport, "_spawn_worker", side_effect=AssertionError("Must not spawn")):
            self.assertEqual(transport.explain_with_transport([])["status"], "disabled")

    def test_busy_rejected_without_spawning(self):
        transport._WORKER_SLOT.acquire()
        try:
            self.assertEqual(self.run_request()["status"], "providerError")
            self.assertEqual(self.children, [])
        finally:
            transport._WORKER_SLOT.release()

    def test_spawn_failure_releases_slot(self):
        with patch.object(transport, "_spawn_worker", side_effect=OSError("private path")):
            result = transport.explain_with_transport([], enabled=True,
                config=transport.TransportConfig(ENDPOINT, "test"), authorized_endpoint=ENDPOINT)
        self.assertEqual(result["status"], "providerError")
        self.assertNotIn("private path", str(result))
        self.assertEqual(self.run_request()["status"], "explained")

    def test_cleanup_failure_blocks_future_workers(self):
        # Use a private test slot: production intentionally offers no reset API.
        with patch.object(transport, "_WORKER_SLOT", threading.BoundedSemaphore(1)):
            with patch.object(transport, "_run_worker", side_effect=transport._WorkerCleanupError("cleanup")):
                self.assertEqual(self.run_request()["status"], "providerError")
            self.assertEqual(self.run_request()["status"], "providerError")
            self.assertEqual(self.children, [])


if __name__ == "__main__":
    unittest.main()
