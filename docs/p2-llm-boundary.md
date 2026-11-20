# P2c preparation: optional explanation boundary (offline only)

`llm_adapter/boundary.py` is a **boundary library, not an installed local/remote LLM
integration**. It is not connected to the CLI or MCP bridge. It does not read API
keys, environment variables, configuration or files, and contains no HTTP client,
model invocation, process control or action dispatcher. No real model is tested.

`explain_findings(findings, enabled=False, provider=None)` returns a deep copy of
the original deterministic facts. By default it never calls a provider. An exact
boolean `enabled=True` and an explicit application callback are both required.
Invalid inputs fail before any callback. This opt-in is not authorization to select
a remote destination, configure credentials or transmit user data.

The callback receives only fixed finding IDs/states and finite, bounded numeric
`used`/`capacity` (GB), `ratio`/`threshold` (%) evidence. Unknown detector states
stay unknown. Source text, conclusions, next-step text, unknown-reason text, sample
timestamps, process names/PIDs/paths, command lines and raw logs are never passed.
Unknown fields/IDs/metrics, duplicate identifiers, invalid units, numeric injection
and nonfinite/out-of-range values are rejected. Inputs must be plain bounded JSON
shapes. Format validation does not establish that the underlying measurements are
true; their provenance remains the deterministic engine's responsibility.

Provider output is a bounded string in `untrustedExplanation`, separate from facts.
`explanationTrusted` and `writeAuthorized` are always false. Provider errors and
rejected outputs use fixed safe messages, without echoing exception details. An
explanation containing a write command remains text; there is no execution path.
Facts and callback input do not share mutable references. This is reference/data
isolation, **not a sandbox for arbitrary Python callbacks**: provider code must be
trusted application code. A callback could otherwise perform its own side effects,
introspect the process or block forever. Deadline/isolation and networking policy
must be supplied and tested before any real provider is integrated.

A future local or remote adapter requires a separate implementation, explicit
provider/destination choice and data-sharing authorization, credential handling,
timeouts, transport tests and a UI that renders model text as untrusted. Do not wire
this library into a client automatically or let model text change facts, commands,
permissions or confirmation requirements. The current tests use only fake in-memory
callbacks; they do not establish local-model or remote-service compatibility.

## Subsequent transport preparation

The separate [opt-in transport library](p2-llm-transport.md) now implements a
mock-tested HTTP path using this boundary. It is still not connected to the GUI,
CLI or MCP, does not configure a provider, and has not contacted a real model.
The production integration and authorization gates above still apply.
