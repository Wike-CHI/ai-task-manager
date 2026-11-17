# Phased delivery and evidence gaps

## P0 (this patch, stacked on PR #3)

- PID + creation time + full executable path are checked on the same opened process handle before normal close and again before explicit force. Parent PID is snapshot evidence, not proof of parent identity/project membership.
- Signature evidence is on-demand, offline embedded Authenticode verification of the current disk file. No network revocation or catalog verification. No claim that loaded memory or application purpose is trusted.
- No executable name grants default batch-safe termination. Reasons disclose name heuristics.
- Default action requests WM_CLOSE and observes up to a shared 1.5s budget. Missing window/unsaved prompts/non-cooperation does not authorize force. Separate default-No approval is required for remaining frozen identities; force then revalidates them. Normal exits cannot be rolled back by cancelling the later force stage.
- Work-set trimming is removed, not silently enabled through another entry point.
- Windows automated helper tests do not replace real multi-theme GUI/save-dialog acceptance. HWND messaging is the standard best-effort Win32 close mechanism, not an atomic process termination transaction; process handles are retained and window owner PID/thread are checked again immediately before posting. Windows provides no atomic external HWND ownership lock, so HWND reuse between that check and posting remains a platform limitation; this is not presented as fully eliminated.

## P1 next: deterministic diagnostic foundations

Existing: collector/types/diagnosis/policy modules, PID ancestry with creation-time validation, heuristic workload grouping. UI/hardware adapters remain in main.cpp.

Still needed: separate process identity service and UI adapter; hard-fault and per-process disk I/O collection; typed resource-change events; evidence/confidence/unknown schema; Node.js OOM, port conflict, GPU allocation failure and anomalous background-process detectors. Do not infer OOM solely from RSS or pagefile use. Port ownership needs exact socket/process evidence; GPU free memory alone is not allocation-failure proof.

Implementation order: typed diagnostic evidence and fixture tests; read-only collector additions; individual deterministic detectors with negative/unknown cases; UI rendering. No LLM dependency needed.

## P2 after evidence schema

Not implemented: opt-in local/remote LLM adapter; read-only local CLI/MCP snapshot/report transport. Deterministic engine owns facts and safety. Do not send process paths or telemetry remotely by default. Keep write operations out of read-only transport and require separate explicit authorization; LLM output never authorizes an operation.

## P3 distribution and reproducibility

Existing: Windows CI, helper safety tests, pinned binary read-only benchmark harness and protocol. No actual Argus ABBA comparison results or real fault demonstrations yet.

Still needed: Stable/Nightly channels, English README, signed/trustworthy distribution or installer with provenance, comparable repeated Windows benchmark evidence, fault demos. Single-exe portability is a goal, not a 100 KB constraint.

IMPORTANT: current main-push CI auto-publishes releases. This PR must not be merged automatically. Separating Stable/Nightly and changing release policy requires deliberate workflow changes and review; this patch does not disable or trigger main releases.
