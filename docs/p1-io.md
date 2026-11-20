# P1b: identity-bound process I/O observations

Stacked on P1a, not a disk-bottleneck or hard-fault detector.

The collector reads GetProcessIoCounters read/write transfer counts. Rates use
per-process GetTickCount64 timestamps and match PID + creation time. First samples,
access failures, identity changes, decreasing counters and invalid intervals remain
unknown. A failed read breaks the baseline; recovery needs two valid samples.

The `IO` / `磁盘` query shows the five largest measured process rates with evidence
and a count of unavailable processes. The word 磁盘 is just a query alias: process
I/O may include cached/device transfers and is never labeled physical disk traffic,
latency, hard faults, causal performance diagnosis or reclaimable memory.

Portable delta fixtures and a Windows own-process collector smoke test are included.
No process is created or terminated by the IO smoke test. ETW hard-fault events,
physical disk counters, timestamped resource-change events, fault detectors and
real-workload benchmark validation remain separate P1 work.
