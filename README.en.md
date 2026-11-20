# AI Task Manager

[中文](README.md) · Windows desktop diagnostics with explicit evidence and conservative actions.

This README describes the development branch, **not a claim that these changes have
been merged or released**. The native GUI remains a Win32/C++17 executable with no
third-party runtime dependency. Size is not a correctness or performance target.
Optional Python interfaces are separate from the GUI.

## What is implemented

- Process snapshots, creation-time/full-path identity, parent observations and
  identity-bound CPU/process-I/O deltas. Missing data stays unknown.
- Deterministic findings with source, confidence basis, missing evidence and next
  steps. High memory usage does not prove OOM, leakage, paging or reclaimable memory.
- Snapshot timing/freshness and bounded resource-change observations. These are not
  complete process lifecycle or audit events.
- On-demand TCP IPv4/IPv6 listener evidence with process identity and endpoint
  rechecks. A listener is not proof of a bind conflict; tables are not atomic.
- Explicit sanitized error-text input. Runtime-like Node/CUDA/bind error formats
  are reported as **text signals**, not authenticated current-process failures.
- Default process action requests normal close. Force requires a separate default-No
  confirmation and identity revalidation. No executable name grants batch-safe
  termination. No global working-set trimming is performed.

## Build and read-only integration

Use a Visual Studio Developer Command Prompt with the Windows SDK. `build.bat`
builds the GUI. The optional one-shot read-only CLI is built separately:

```cmd
cl /nologo /std:c++17 /EHsc /O2 /utf-8 /W3 src\readonly_cli.cpp /Fe:AITaskManagerReadOnly.exe psapi.lib
AITaskManagerReadOnly.exe snapshot
AITaskManagerReadOnly.exe report
```

The CLI exports JSON v1. Large identity/time integers are strings; unavailable
metrics are null/unknown. It has no write commands, server, LLM, automatic uploads
or user-log collection. It does not collect GPU/temperature or system-total CPU.
Executable paths can reveal private local work: protect output before sharing it.
See [CLI contract](docs/p2-readonly-cli.md) and [JSON schema notes](docs/p2-json.md).

An **optional** local stdio MCP wrapper uses a pinned official Python SDK. It exposes
only two no-argument read-only tools, validates the configured local executable,
and bounds child runtime/output. It does not install a host connection or an HTTP
service. Tested protocol: `2025-11-25`; no 2026-protocol compatibility claim.
An MCP host may forward tool results remotely; that is a separate permission choice.
See [MCP setup and limits](docs/p2-mcp.md).

The [optional explanation boundary](docs/p2-llm-boundary.md) is disabled by default
and is **not a connected local/remote LLM**. Its offline tests verify that a provider
would receive only selected numeric evidence and could not rewrite retained facts
or authorize actions. Real provider transport, credentials, isolation and evaluation
are not implemented.

## Useful GUI queries

- `证据` / `诊断`: deterministic findings and missing evidence.
- `IO` / `磁盘`: process I/O observations, **not** physical-disk throughput.
- `事件` / `新鲜度`: most recent bounded comparison and sample age.
- `端口 3000` / `port 3000`: read-only TCP listener evidence.
- `日志证据: Error: listen EADDRINUSE: address already in use`: explicit single-line
  text evidence. The original line is not echoed; sanitize before entering it.

## Verification and limits

Windows CI builds with MSVC and runs identity/termination, normal-close helper,
confirmation barrier, resource event, I/O, TCP, JSON/CLI and optional MCP tests.
Process-action tests target only disposable children created by their own harness.
TCP tests use owned loopback sockets. No test should target a real editor or system
process. CI benchmark smoke validates the harness, **not product performance**.

Run the [bounded bind-failure demonstration](docs/p3-readiness.md#controlled-fault-demonstration)
only as a local test. See [benchmark protocol](docs/benchmark.md) for pinned binaries,
raw samples and repeated A/B/B/A comparisons. No real Argus comparison, performance
win, complete multi-theme UI acceptance or real-world fault attribution is claimed.
Hard-fault ETW events, physical-disk latency and authenticated runtime error
correlation remain work in progress.

## Distribution status

CI artifacts are unsigned test builds, not Stable/Nightly releases. There is no
installer/signing/provenance guarantee yet. The existing main-push workflow can
publish automatically: merging is not a harmless release-neutral action.
[P3 readiness and proposed channels](docs/p3-readiness.md) document the changes and
approvals still required. This branch does not alter repository settings, publish a
release, configure signing credentials or merge any PR.
