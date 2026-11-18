"""Explicitly authorized, non-streaming OpenAI-compatible explanation transport.

No environment/config/key discovery; no retries, redirects, proxies or tool calls.
Only explain_with_transport exposes deterministic findings to this transport.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from dataclasses import asdict
from pathlib import Path
import http.client
import ipaddress
import json
import math
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

from .boundary import BoundaryError, explain_findings, MAX_EXPLANATION_CHARS

MAX_RESPONSE_BYTES = 32768
MAX_REQUEST_BYTES = 16384
_WORKER_SLOT = threading.BoundedSemaphore(1)


class _WorkerCleanupError(RuntimeError):
    """Fail closed: do not admit more workers until this parent restarts."""


@dataclass(frozen=True)
class TransportConfig:
    endpoint: str
    model: str
    mode: str = "local"
    timeout_seconds: float = 10.0
    # Explicit injection only. Never discovered, logged or included in repr.
    bearer_token: str | None = field(default=None, repr=False)


def _validate(config, authorized_endpoint):
    if type(config) is not TransportConfig:
        raise BoundaryError("Invalid transport configuration")
    endpoint = config.endpoint
    if type(endpoint) is not str or len(endpoint) > 2048 or not endpoint.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in endpoint):
        raise BoundaryError("Invalid endpoint")
    if type(authorized_endpoint) is not str or endpoint != authorized_endpoint:
        raise BoundaryError("Exact endpoint authorization required")
    try:
        url = urlsplit(endpoint)
        port = url.port
    except ValueError:
        raise BoundaryError("Invalid endpoint") from None
    if port == 0:
        raise BoundaryError("Endpoint port must be positive")
    if "\\" in endpoint:
        raise BoundaryError("Noncanonical endpoint")
    if url.username is not None or url.password is not None or url.query or url.fragment or url.path != "/v1/chat/completions":
        raise BoundaryError("Unsupported endpoint components")
    if config.mode not in ("local", "remote") or type(config.mode) is not str or not url.hostname:
        raise BoundaryError("Invalid transport mode or host")
    host = url.hostname
    authority = ("[" + host + "]") if ":" in host else host
    if port is not None:
        authority += ":" + str(port)
    if endpoint != url.scheme + "://" + authority + "/v1/chat/completions":
        raise BoundaryError("Noncanonical endpoint")
    if config.mode == "local":
        if url.scheme != "http" or host not in ("127.0.0.1", "::1"):
            raise BoundaryError("Local endpoint must use literal loopback HTTP")
    elif url.scheme != "https":
        raise BoundaryError("Remote endpoint requires HTTPS")
    if type(config.model) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}", config.model):
        raise BoundaryError("Invalid model identifier")
    if type(config.timeout_seconds) not in (int, float) or not 0 < config.timeout_seconds <= 15:
        raise BoundaryError("Timeout must be positive and at most 15 seconds")
    token = config.bearer_token
    if token is not None and (type(token) is not str or not re.fullmatch(r"[\x21-\x7e]{1,4096}", token)):
        raise BoundaryError("Invalid credential format")
    return host, port if port is not None else (443 if url.scheme == "https" else 80), url.path


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, timeout, address):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._address = address

    def connect(self):
        # The vetted address is pinned: no second hostname resolution / DNS rebinding.
        raw = socket.create_connection((self._address, self.port), self.timeout)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


def _connection(config, host, port):
    if config.mode == "local":
        return http.client.HTTPConnection(host, port, timeout=config.timeout_seconds)
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    if not addresses:
        raise ValueError("No public address")
    ips = [ipaddress.ip_address(record[4][0]) for record in addresses]
    if any(not ip.is_global or ip.is_multicast for ip in ips):
        raise ValueError("Non-public address")
    return _PinnedHTTPSConnection(host, port, config.timeout_seconds, str(ips[0]))


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _reject_json_constant(value):
    raise ValueError("Nonfinite JSON value")


def _json_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Nonfinite JSON number")
    return number


def _request(config, destination, summary):
    host, port, path = destination
    body = json.dumps({
        "model": config.model, "stream": False, "max_tokens": 512,
        "messages": [
            {"role": "system", "content": "Explain the numeric observations only. Do not infer missing facts, authorize actions, or give executable commands. Your explanation is untrusted advice."},
            {"role": "user", "content": json.dumps(summary, allow_nan=False, separators=(",", ":"))},
        ],
    }, allow_nan=False).encode("utf-8")
    if len(body) > MAX_REQUEST_BYTES:
        raise ValueError("Request too large")
    headers = {"Content-Type": "application/json", "Accept": "application/json", "Accept-Encoding": "identity"}
    if config.bearer_token is not None:
        headers["Authorization"] = "Bearer " + config.bearer_token
    conn = _connection(config, host, port)
    try:
        conn.request("POST", path, body=body, headers=headers)
        response = conn.getresponse()
        # All non-200 statuses rejected, including redirects; never follow Location.
        if response.status != 200 or response.getheader("Content-Encoding", "identity") != "identity":
            raise ValueError("Response rejected")
        if response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise ValueError("Unsupported response type")
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        if len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("Response too large")
        data = json.loads(raw, object_pairs_hook=_json_object,
                          parse_constant=_reject_json_constant, parse_float=_json_float)
        choices = data["choices"]
        if type(choices) is not list or len(choices) != 1:
            raise ValueError("Invalid choices")
        message = choices[0]["message"]
        if message.get("tool_calls") or message.get("function_call"):
            raise ValueError("Tool output rejected")
        text = message["content"]
        if type(text) is not str or not text.strip() or len(text) > MAX_EXPLANATION_CHARS:
            raise ValueError("Invalid explanation")
        return text
    finally:
        conn.close()


def _spawn_worker():
    # No shell, endpoint, credential or evidence in argv. -I ignores PYTHONPATH
    # and user site packages. The sibling script is trusted installed code.
    return subprocess.Popen(
        [sys.executable, "-I", str(Path(__file__).with_name("worker.py"))],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
    )


def _request_isolated(config, destination, summary, cancel_event=None):
    # Reject concurrent optional explanations instead of queuing unbounded work.
    if not _WORKER_SLOT.acquire(blocking=False):
        raise ValueError("Explanation worker busy")
    reusable = True
    try:
        return _run_worker(config, summary, cancel_event)
    except _WorkerCleanupError:
        reusable = False
        raise
    finally:
        if reusable:
            _WORKER_SLOT.release()


def _run_worker(config, summary, cancel_event):
    deadline = time.monotonic() + config.timeout_seconds
    if cancel_event is not None and cancel_event.is_set():
        raise ValueError("Explanation cancelled")
    payload = json.dumps({"config": asdict(config), "summary": summary},
                         allow_nan=False).encode("utf-8")
    worker = _spawn_worker()
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or (cancel_event is not None and cancel_event.is_set()):
                raise ValueError("Explanation timed out or cancelled")
            try:
                raw, _ = worker.communicate(input=payload, timeout=min(remaining, 0.05))
                break
            except subprocess.TimeoutExpired:
                # communicate retains partially sent input across retries.
                payload = None
        if time.monotonic() >= deadline or (cancel_event is not None and cancel_event.is_set()):
            raise ValueError("Explanation timed out or cancelled")
        if worker.returncode != 0 or len(raw) > MAX_RESPONSE_BYTES:
            raise ValueError("Explanation worker failed")
        result = json.loads(raw)
        if type(result) is not str or not result.strip() or len(result) > MAX_EXPLANATION_CHARS:
            raise ValueError("Explanation worker output rejected")
        return result
    finally:
        # Terminate only the child handle we created, never a rediscovered PID.
        # Killing interrupts stuck resolver/SSL/slow-body operations, unlike a
        # thread timeout. The worker never creates descendants.
        try:
            if worker.poll() is None:
                worker.kill()
            worker.communicate(timeout=1.0)
        except BaseException:
            raise _WorkerCleanupError("Explanation worker cleanup failed") from None
        finally:
            for stream in (worker.stdin, worker.stdout):
                if stream is not None:
                    stream.close()


def explain_with_transport(findings, *, enabled=False, config=None, authorized_endpoint=None,
                           cancel_event=None):
    """Opt-in AND exact endpoint approval required; approval supplied by trusted UI.

    Endpoint string is a guard, not proof of human consent. Calling integration must
    obtain destination/data/credential permission. Disabled never reads config/DNS.
    """
    if type(enabled) is not bool:
        raise BoundaryError("Explicit boolean opt-in is required")
    if not enabled:
        return explain_findings(findings)
    destination = _validate(config, authorized_endpoint)
    return explain_findings(findings, enabled=True,
                            provider=lambda summary: _request_isolated(config, destination, summary, cancel_event))
