# P2 optional explanation transport (library only)

`llm_adapter.transport.explain_with_transport` adds a synchronous, non-streaming
OpenAI-compatible `/v1/chat/completions` HTTP client. It is **not wired into the
Win32 application, CLI or MCP**. No configured provider, keys, real model invocation,
network interoperability test, or remote data transmission is included in this PR.

## Opt-in and destination permission

Default `enabled=False` validates/copies findings locally without reading config,
resolving DNS or opening a connection. Enabling requires both a `TransportConfig`
and an `authorized_endpoint` string exactly equal to its full endpoint. The trusted
calling application must obtain actual user authorization for that destination,
transmitted numeric data, and credential use before supplying this string. A string
comparison is a guard, not an authentication/consent UI. Model/config cannot be taken
from model output or untrusted process data.

Local mode accepts HTTP only on literal `127.0.0.1` or `::1` (no `localhost` DNS).
Remote mode requires HTTPS with default certificate/hostname verification. All DNS
answers must be globally routable, non-multicast addresses; one validated address is
pinned for the connection, while TLS authenticates the original host. Private,
loopback, link-local and mixed public/private remote answers are rejected. This is
not a general SSRF sandbox: the caller still must approve the exact remote service.
Local loopback endpoints can themselves forward requests elsewhere; approving a
local URL does not prove local-only inference. Review the local server separately.

Endpoint credentials, query strings, fragments and alternative paths are rejected.
Canonical URL spelling is required: zero/empty/zero-padded ports, backslashes,
duplicate or escaped path separators, dot segments and empty query/fragment
markers are rejected rather than silently normalized.
No redirects, retries, environment proxies, proxy discovery, environment API keys,
configuration discovery, streaming, tool calls or credential-file operations are implemented.
An optional bearer token is injected by the authorized caller, excluded from config
repr, and sent only to the approved endpoint. It is not logged or returned. Never
include credentials in examples or commit them to source control.

## Fact and output boundary

The transport reuses `boundary.explain_findings`. Only fixed finding ID/state and
bounded numeric metric/unit pairs leave the process; arbitrary conclusions, paths,
PIDs, process names, raw logs, evidence-source text and sample timestamps stay local.
The request also includes a fixed system prompt and explicitly configured model ID.
The original deterministic facts are independently copied and never replaced by
model output. Any returned explanation remains `untrustedExplanation`, with
`explanationTrusted=False` and `writeAuthorized=False`. There is no action executor.

Requests are capped at 16 KiB; responses are read with a 32 KiB plus one-byte cap.
Only HTTP 200 JSON with identity encoding is accepted. Other statuses, compressed
responses, tool/function outputs, invalid JSON (including duplicate keys, NaN,
Infinity and floating-point overflow anywhere in the response), missing content and explanations
over 4,096 characters fail closed. Errors are fixed boundary messages, not HTTP
response bodies, exceptions, credentials or endpoint strings. Connections close
on success and failure; TLS wrapping failures close the raw socket.

## Overall deadline, cancellation and integration gate

The optional transport now runs each HTTP request in a separate trusted Python
worker. The parent enforces `timeout_seconds` (positive, at most 15 seconds) over
worker startup, DNS, TLS, request sending, response reading and IPC. A socket timeout
still limits individual operations, but a slow peer cannot reset the parent budget.
On expiry or a caller-supplied `threading.Event` cancellation, the parent kills and
reaps only its own child handle; it never looks up or terminates an unrelated PID.
Only one request per parent process is allowed; concurrent calls fail closed rather
than queue. If cleanup fails, the slot stays blocked until the parent restarts;
subsequent calls cannot accumulate possibly surviving workers. Failures/cancellation preserve the deterministic facts and return the
same sanitized `providerError`, with no partial explanation.

The process command contains only Python and the fixed sibling worker script;
configuration, injected credential and numeric summary travel via a private stdin
pipe, not argv, disk or logs. Worker stderr is discarded and errors are fixed.
The trusted worker emits only a bounded explanation; the parent buffers stdout
before checking its length. This is not a bounded-output sandbox for malicious
replacement worker code. Python isolated mode ignores `PYTHONPATH` and user site packages. This is lifecycle
isolation of trusted code, not an OS security sandbox or a way to run model code.
The worker does not create descendants. The internal worker script is not a public
CLI/MCP endpoint and does not establish consent; authorization is validated by the
trusted public API before any worker starts.

Cancellation is polled at most every 50 ms while waiting. Deadline expiry is checked
before accepting output. Cleanup has a separate one-second budget. OS process
creation, scheduling and termination cannot offer a real-time guarantee, so total
elapsed time can exceed the request budget by cleanup/scheduling overhead. Do not
run the synchronous API on the UI thread. A future UI needs an asynchronous caller
and a cancellation event; no GUI/CLI/MCP wiring or live model setup is added here.

Other gates: real consent/configuration UI; approved credential storage and lifecycle;
chosen provider's response compatibility and retention review; independent privacy
review; local/remote integration tests with explicit network authorization. Some
providers do not support this endpoint or `max_tokens`; failures remain optional
explanation failures and do not invalidate deterministic facts. This is a transport
implementation, not evidence that any actual LLM provider currently works.

## Offline verification

Run `python -B tools/llm_transport_selftest.py` and
`python -B tools/llm_boundary_selftest.py`. The transport suite blocks real sockets
and DNS, mocks HTTP/TLS, and checks default-off behavior, exact URL authorization,
URL restrictions, timeout validation, proxy bypass, DNS pinning/private-address
rejection, redirects, response bounds, error redaction, and no write authorization.
All tests use fabricated summaries and replies. No real endpoint is contacted.

`python -B tools/llm_deadline_selftest.py` additionally starts real Python child
processes with fabricated HTTP/DNS implementations and explicit network blockers.
It checks successful IPC, stalled DNS/body cutoff, pre-start and running cancellation,
child reaping, default-off behavior, busy rejection and slot recovery after failures.
These are lifecycle tests, not live-provider or Windows UI interoperability evidence.
