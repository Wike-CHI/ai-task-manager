# P2b: local read-only stdio MCP bridge

This optional Python layer wraps the existing native read-only CLI. It does not
change the native single-executable build or introduce Python into the GUI.

## Run explicitly on the same Windows machine

Use a dedicated Python environment (Python 3.12 is tested):

```powershell
python -m pip install -r requirements-mcp.txt
# Run from this repository root; choose absolute paths yourself.
python -m mcp_bridge.server --cli 'C:\absolute\path\AITaskManagerReadOnly.exe'
```

The second command is a stdio protocol process, not an interactive shell. An MCP
host must launch it with this repository as its working directory (or make the
package importable). No host configuration, connector, login or persistent service
is installed automatically. Hosts differ in working-directory configuration; do
not paste a generic config unless that host supports it.

Only two tools are advertised:

- `task_manager_snapshot`: local snapshot JSON, including executable paths.
- `task_manager_report`: deterministic findings and explicit unknowns.

Both accept only an empty arguments object and advertise read-only, non-destructive,
closed-world annotations. The implementation enforces a fixed command mapping;
annotations alone are not security controls. Extra arguments, write verbs and
unknown tools never call the backend. One backend call runs at a time. No roots,
resources, prompts, logging subscription, LLM sampling, HTTP listener or write tools
are provided. Results include matching `structuredContent` and JSON text for clients.

Backend failure produces a fixed tool error, not raw CLI stdout/stderr, path or
exception text. Partial valid collection output remains marked by the CLI/backend;
read-only does not mean complete or certain. Client cancellation does not authorize
any write action. Process/output/time limits belong to the separately tested backend.

## Privacy and permission boundary

The wrapper sends results only over its local stdio connection. It does not connect
to a model/provider or upload data. **The MCP host may itself forward results to a
remote model.** Enabling this bridge exposes local process paths and observations to
that host; review the host's storage and forwarding policy and obtain the relevant
permission before enabling remote use. It does not collect command lines, environment
variables, credentials or raw user logs. Do not insert secrets into configuration.

The bridge does not grant permission to kill processes, trim working sets, rewrite
settings, deploy or otherwise act on observations. There is no write-operation route.

## Tested protocol scope, not a latest-version claim

`requirements-mcp.txt` pins the official Python SDK **1.29.0**, a maintained v1 line.
Its installed protocol constants support 2024-11-05, 2025-03-26, 2025-06-18 and
2025-11-25; the end-to-end test specifically negotiates **2025-11-25**. This patch
does not claim 2026 protocol or SDK v2 compatibility. Upgrade the pin only with
independent lifecycle, discovery, result-shape and security-boundary tests.

Protocol framing, initialization, notifications and shutdown are SDK-owned rather
than a handwritten JSON-RPC implementation. Primary references:

- [Official Python SDK v1.29.0](https://github.com/modelcontextprotocol/python-sdk/blob/v1.29.0/README.md)
- [MCP 2025-11-25 stdio transport](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)

## Verification

```powershell
# Real official ClientSession + stdio_client talking to a child test server:
python tools/mcp_protocol_selftest.py
# Same real protocol talking to the production wrapper + native CLI:
python tools/mcp_protocol_selftest.py --cli 'C:\absolute\path\AITaskManagerReadOnly.exe'
```

The fixture mode exists only inside the test program, not in production arguments.
Tests cover initialize, capabilities, list, ping, both tools, JSON/structured content
agreement, strict no-argument rejection, no backend invocation for rejected calls,
and safe backend failure. They print pass/fail labels, never local snapshots.
Linux fixture success is not proof that the Windows native backend ran; that is a
separate CI check. No release or host installation is performed by these tests.

## Backend limits

Python 3.11+ is required (`asyncio.timeout`); CI uses 3.12. Select a trusted existing
absolute local `.exe`; relative, UNC/network and device paths and non-`.exe` targets
are rejected. A configured executable is trusted local code, not a security sandbox
for arbitrary programs. Tool requests cannot choose or replace that path.

Each collector invocation has a 15-second deadline, 8 MiB stdout cap and 16 KiB
stderr cap. Cancellation/limit/timeout cleanup targets only the child this adapter
started, never a client PID. Child stderr is discarded rather than passed to the
host. JSON rejects duplicate keys, nonfinite literals, invalid UTF-8/envelopes and
contradictory completeness/exit status. Output is observations, not instructions.
