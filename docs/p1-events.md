# P1c: bounded resource observations and snapshot freshness

Snapshots record monotonic start/end timestamps and completion. Completion means the
collector returned, not that every metric or process was readable. Toolhelp process
enumeration has a separate completion flag and only succeeds when iteration reaches
`ERROR_NO_MORE_FILES`. Memory samples have a per-process validity flag.

The latest two snapshots are compared on the UI thread before replacing the previous
snapshot. Existing `g_busy` serialization keeps collectors from running concurrently.
Failed posting frees the undelivered snapshot and releases that busy guard. No new
periodic/background worker or write action is added.

A comparable pair needs completed snapshots, complete process enumeration, nonoverlapping
monotonic windows no longer than 10 seconds each, and at most 30 seconds between ends.
The first sample, incomplete data, invalid clocks or longer gaps produce no events and
retain an explicit comparison state. Unknown process identity never supplies a zero
memory sample, start, exit or a cross-PID memory delta.

Events are `ObservedNew`, `NoLongerObserved`, and `WorkingSetChanged`. PID + creation time
identify each object; image/path consistency is required for memory comparison. These
are observations in two enumerations, **not confirmed process starts/exits, crashes,
leaks, reclaimed memory, or causality**. PID reuse creates two separate observations.
Working-set change requires both 128 MiB absolute and 25% relative change, with valid
nonnegative finite samples. Shared pages remain included.

Only the latest comparison is retained, capped at 100 events. The number omitted is
reported separately. There is no persistent lifecycle history or audit log.

Freshness is Unknown for incomplete, reversed-clock or overlong samples; otherwise
Fresh means the completed snapshot is at most 10 seconds old, Stale means older.
It does not guarantee freshness of independently cached hardware readings or validity
of all metrics. Monotonic values are local to this run/boot, not UTC timestamps.

Portable fixtures cover first/failed/stale samples, missing identity, PID reuse,
working-set changes, duplicate evidence and bounded output. Real ETW lifecycle events,
hard faults, physical disk latency and confirmed failure evidence remain separate work.
