# P1a: structured evidence, not unsupported diagnoses

Each finding has a stable ID, state (Observed/Risk/Unknown), confidence basis
(None/DirectMeasurement/Heuristic), source-labeled evidence, missing facts and next
steps. Confidence is a provenance category, not a fabricated probability.

Memory/commit/GPU thresholds describe one snapshot, not causality. Missing, negative,
nonfinite or inconsistent capacities stay unknown. Commit is the existing
GlobalMemoryStatusEx PageFile-field difference, explicitly an estimate. GPU is device
aggregate data, never attributed to an individual model without per-process evidence.
Snapshot freshness is not guaranteed because this schema has no timestamp yet.

Node.js OOM, bind/port conflict, GPU allocation failure, anomalous background processes
and hard-fault/disk bottlenecks remain Unknown until their specific evidence sources
exist. High RSS, an unfamiliar executable or high VRAM are not sufficient.

The default diagnosis and the `证据` / `诊断` / `OOM` / `端口` / `异常` queries use this
same deterministic engine. No LLM, network transmission or new write action is added.

This is P1a only: process I/O metrics, hard-fault events, disk latency, timestamped
resource events, full UI/identity extraction and proven fault detectors are separate
work. Portable fixture tests and Windows compilation do not replace interactive UI
acceptance or real-world fault reproduction.
