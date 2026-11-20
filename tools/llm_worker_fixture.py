"""Trusted offline subprocess fixture; never connects to a network."""
from pathlib import Path
import socket
import sys
import time
from unittest.mock import MagicMock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from llm_adapter import transport, worker


def forbidden(*args, **kwargs):
    raise AssertionError("Network forbidden in worker fixture")


def stuck(*args, **kwargs):
    Path(sys.argv[2]).write_text("blocked", encoding="ascii")
    time.sleep(60)
    raise AssertionError("Timeout should terminate fixture")


socket.socket = forbidden
socket.getaddrinfo = forbidden
mode = sys.argv[1]
if mode == "dns":
    socket.getaddrinfo = stuck
elif mode == "error":
    transport._connection = forbidden
else:
    conn = MagicMock()
    response = conn.getresponse.return_value
    response.status = 200
    response.getheader.side_effect = lambda name, default=None: {"Content-Type": "application/json"}.get(name, default)
    response.read.return_value = b'{"choices":[{"message":{"content":"offline advice"}}]}'
    if mode == "body":
        response.read.side_effect = stuck
    transport._connection = lambda *args: conn
sys.exit(worker.main())
