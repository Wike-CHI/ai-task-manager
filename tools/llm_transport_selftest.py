#!/usr/bin/env python3
"""Offline mocks only: no provider / DNS / network access."""
import json
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import MagicMock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from llm_adapter.boundary import BoundaryError
from llm_adapter.transport import TransportConfig, explain_with_transport, _connection, _PinnedHTTPSConnection, _request

ENDPOINT = "http://127.0.0.1:8080/v1/chat/completions"

class Tests(unittest.TestCase):
    def setUp(self):
        # HTTP unit tests run direct mocks; worker lifecycle has its own suite.
        self.worker = patch("llm_adapter.transport._request_isolated",
                            side_effect=lambda c, d, s, cancel=None: _request(c, d, s))
        self.worker.start()
        self.addCleanup(self.worker.stop)
        self.network = patch("socket.socket", side_effect=AssertionError("Real network forbidden"))
        self.network.start()
        self.addCleanup(self.network.stop)
        self.dns = patch("socket.getaddrinfo", side_effect=AssertionError("Real DNS forbidden"))
        self.dns.start()
        self.addCleanup(self.dns.stop)
        self.connection = MagicMock()
        response = self.connection.getresponse.return_value
        response.status = 200
        response.getheader.side_effect = lambda name, default=None: {"Content-Type": "application/json"}.get(name, default)
        response.read.return_value = json.dumps({"choices": [{"message": {"content": "Untrusted advice"}}]}).encode()

    def run_transport(self, **kwargs):
        return explain_with_transport([], enabled=True, config=TransportConfig(ENDPOINT, "test"), authorized_endpoint=ENDPOINT, **kwargs)

    def test_disabled_no_config_or_io(self):
        self.assertEqual(explain_with_transport([], config=object())["status"], "disabled")

    def test_explicit_authorization(self):
        for destination in (None, ENDPOINT + "/"):
            with self.assertRaises(BoundaryError):
                explain_with_transport([], enabled=True, config=TransportConfig(ENDPOINT, "test"), authorized_endpoint=destination)

    def test_urls(self):
        for url, mode in [("http://localhost/v1/chat/completions", "local"), ("http://example.com/v1/chat/completions", "remote"), ("https://u:p@example.com/v1/chat/completions", "remote"), (ENDPOINT+"?key=secret", "local"), (ENDPOINT+"#fragment", "local"), (ENDPOINT+"\n", "local"), (ENDPOINT+"/../admin", "local")]:
            with self.subTest(url=url), self.assertRaises(BoundaryError):
                explain_with_transport([], enabled=True, config=TransportConfig(url, "test", mode), authorized_endpoint=url)

    def test_noncanonical_urls_and_zero_port_rejected(self):
        for url in ("http://127.0.0.1:0/v1/chat/completions",
                    "https://example.com:0/v1/chat/completions",
                    "http://127.0.0.1:/v1/chat/completions",
                    "http://127.0.0.1:080/v1/chat/completions",
                    "http://127.0.0.1//v1/chat/completions",
                    "http://127.0.0.1/v1%2fchat/completions",
                    "http://127.0.0.1/v1/./chat/completions",
                    "http://127.0.0.1/v1/chat/completions?",
                    "http://127.0.0.1/v1/chat/completions#",
                    "http://127.0.0.1\\evil/v1/chat/completions"):
            mode = "remote" if url.startswith("https") else "local"
            with self.subTest(url=url), self.assertRaises(BoundaryError):
                explain_with_transport([], enabled=True,
                    config=TransportConfig(url, "test", mode), authorized_endpoint=url)

    def test_strict_json_duplicate_keys_and_nonfinite(self):
        valid_choice = '"choices":[{"message":{"content":"safe"}}]'
        for raw in ('{' + valid_choice + ',"choices":[]}',
                    '{"choices":[{"message":{"content":"first","content":"second"}}]}',
                    *('{' + valid_choice + ',"metadata":' + value + '}'
                      for value in ("NaN", "Infinity", "-Infinity", "1e999", "-1e999"))):
            self.connection.getresponse.return_value.read.return_value = raw.encode()
            with self.subTest(raw=raw), patch("llm_adapter.transport._connection", return_value=self.connection):
                result = self.run_transport()
            self.assertEqual(result["status"], "providerError")
            self.assertIsNone(result["untrustedExplanation"])

    def test_timeout_validation(self):
        for timeout in (0, 16, float("nan"), float("inf"), float("-inf"), True):
            with self.assertRaises(BoundaryError):
                explain_with_transport([], enabled=True, config=TransportConfig(ENDPOINT, "test", timeout_seconds=timeout), authorized_endpoint=ENDPOINT)

    def test_success_no_tools_no_fact_overwrite(self):
        with patch("llm_adapter.transport._connection", return_value=self.connection):
            result = self.run_transport()
        self.assertEqual(result["status"], "explained")
        self.assertFalse(result["writeAuthorized"])
        body = json.loads(self.connection.request.call_args.kwargs["body"])
        self.assertFalse(body["stream"])
        self.assertNotIn("tools", body)
        self.connection.close.assert_called_once()

    def test_redirect_not_followed(self):
        for status in (301, 302, 307, 308, 401, 500):
            self.connection.getresponse.return_value.status = status
            with patch("llm_adapter.transport._connection", return_value=self.connection) as factory:
                self.assertEqual(self.run_transport()["status"], "providerError")
                factory.assert_called_once()

    def test_errors_sanitized(self):
        for error in (TimeoutError("secret-token"), OSError("private-host")):
            with patch("llm_adapter.transport._connection", side_effect=error):
                result = self.run_transport()
            self.assertEqual(result["status"], "providerError")
            self.assertNotIn(str(error), str(result))

    def test_bad_or_oversized_outputs(self):
        for raw in (b"x"*32769, b"secret-invalid-json", json.dumps({"choices":[{"message":{"content":"x"*4097}}]}).encode(), json.dumps({"choices":[{"message":{"content":"kill 123", "tool_calls":[{}]}}]}).encode()):
            self.connection.getresponse.return_value.read.return_value = raw
            with patch("llm_adapter.transport._connection", return_value=self.connection):
                result = self.run_transport()
            self.assertEqual(result["status"], "providerError")
            self.assertIsNone(result["untrustedExplanation"])
        self.connection.getresponse.return_value.read.assert_called_with(32769)

    def test_sensitive_text_not_in_http_body(self):
        finding = {"id": "physical_memory", "state": "risk", "confidenceBasis": "directMeasurement",
                   "conclusion": "PRIVATE_PATH", "unknowns": ["SECRET_PID"], "nextSteps": ["RAW_LOG"],
                   "evidence": [{"metric": "ratio", "value": "91", "unit": "%", "source": "PRIVATE_SOURCE"}]}
        with patch("llm_adapter.transport._connection", return_value=self.connection):
            result = explain_with_transport([finding], enabled=True,
                config=TransportConfig(ENDPOINT, "test", bearer_token="test-secret"), authorized_endpoint=ENDPOINT)
        body = self.connection.request.call_args.kwargs["body"].decode()
        for private in ("PRIVATE_PATH", "SECRET_PID", "RAW_LOG", "PRIVATE_SOURCE", "test-secret"):
            self.assertNotIn(private, body)
        self.assertEqual(result["facts"], [finding])
        self.assertNotIn("test-secret", repr(TransportConfig(ENDPOINT, "test", bearer_token="test-secret")))

    def test_encoded_or_wrong_content_type_rejected(self):
        for headers in ({"Content-Encoding": "gzip", "Content-Type": "application/json"}, {"Content-Type": "text/html"}):
            self.connection.getresponse.return_value.getheader.side_effect = lambda name, default=None: headers.get(name, default)
            with patch("llm_adapter.transport._connection", return_value=self.connection):
                self.assertEqual(self.run_transport()["status"], "providerError")

    def test_proxy_ignored_local_timeout(self):
        with patch.dict("os.environ", {"HTTP_PROXY":"http://evil:80", "HTTPS_PROXY":"http://evil:80"}), patch("http.client.HTTPConnection") as cls:
            _connection(TransportConfig(ENDPOINT,"test",timeout_seconds=3), "127.0.0.1",8080)
            cls.assert_called_once_with("127.0.0.1",8080,timeout=3)

    def test_remote_private_and_mixed_dns_rejected(self):
        for addresses in (["127.0.0.1"], ["10.1.1.1"], ["169.254.169.254"], ["2606:4700::1111", "::1"]):
            records = [(socket.AF_INET,socket.SOCK_STREAM,6,"",(ip,443)) for ip in addresses]
            with patch("socket.getaddrinfo",return_value=records), self.assertRaises(ValueError):
                _connection(TransportConfig("https://example.com/v1/chat/completions","test","remote"),"example.com",443)

    def test_remote_dns_pinned_and_tls_host_verified(self):
        records=[(socket.AF_INET,socket.SOCK_STREAM,6,"",("1.1.1.1",443))]
        with patch("socket.getaddrinfo",return_value=records), patch("llm_adapter.transport._PinnedHTTPSConnection") as cls:
            _connection(TransportConfig("https://example.com/v1/chat/completions","test","remote"),"example.com",443)
            cls.assert_called_once_with("example.com",443,10.0,"1.1.1.1")
        context=MagicMock()
        with patch("ssl.create_default_context",return_value=context), patch("socket.create_connection") as connect:
            conn=_PinnedHTTPSConnection("example.com",443,3,"1.1.1.1")
            conn.connect()
            connect.assert_called_once_with(("1.1.1.1",443),3)
            context.wrap_socket.assert_called_once_with(connect.return_value,server_hostname="example.com")

if __name__ == "__main__":
    unittest.main()
