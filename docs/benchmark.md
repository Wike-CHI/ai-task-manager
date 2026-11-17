# Reproducible Windows performance and safety protocol

Status: tooling/protocol, **not a measured performance claim**. No Argus result has been collected here. Use the same Windows machine and user session for both binaries. These scripts never download, launch, kill or reconfigure either application.

## Pin inputs and conditions

1. Build AITaskManager at the tested commit. Obtain Argus separately from its official project; record release/tag and commit. Record SHA256 of both executables with `Get-FileHash -Algorithm SHA256`. Do not substitute an unreviewed download or label an unknown build as the latest release.
2. Save Windows build, power mode, display resolution/DPI, theme, polling interval, visible/minimized/tray state, hardware, background apps and workload versions in a local run note. Hardware/build and executable hash/version are also automatically recorded. Configure comparable features where possible; document mismatches rather than hiding them.
3. Only run one task manager under test at a time. Wait 30 seconds after launch before sampling. Keep the same deterministic workload running. Avoid updates, virus scans, thermal transitions and interactive use during measurement.
4. Collect at least five runs per scenario in alternating A/B/B/A order. Use a fresh directory each run. Never overwrite earlier evidence. Compare distributions and variance, not one favorable minimum.

## Scenarios

- Idle desktop, fixed set of background applications.
- Developer workload: a pinned repository, fixed build command and fixed parallelism; separate build and idle-editor samples. Keep npm/Python caches and dependency versions identical.
- Process churn: a separately reviewed test harness creates only disposable child processes at a recorded rate. Do not kill unrelated processes to create load.
- Display states: visible list, minimized/tray. Different states are different scenarios, not interchangeable measurements.

The sampler reports **root process only**, not aggregate process-tree cost. If Argus uses a multi-process architecture, root RSS/CPU must not be presented as total application overhead. Capture its full tree with a separate approved profiler for an app-total comparison. Working set is not reclaimable memory, and summed working sets can double-count shared pages.

## Capture

Start the target manually; identify its PID. Supply the expected digest independently, not a digest silently calculated from whatever PID happened to exist.

```powershell
.\tools\benchmark.ps1 -ProcessId 1234 -Label AITaskManager `
  -ExpectedSha256 '<64 hex chars>' -Revision '<commit SHA>' `
  -Scenario 'idle-visible-dark-1s' -OutputDirectory '.\evidence\aitm-01'
# After manually closing it, launch the pinned Argus binary and use its PID:
.\tools\benchmark.ps1 -ProcessId 5678 -Label Argus `
  -ExpectedSha256 '<64 hex chars>' -Revision '<tag/commit>' `
  -Scenario 'idle-visible-dark-1s' -OutputDirectory '.\evidence\argus-01'
.\tools\benchmark-compare.ps1 -AITaskManagerDirectory '.\evidence\aitm-01' `
  -ArgusDirectory '.\evidence\argus-01' -Verbose
```

Run in Windows PowerShell 5.1+ or PowerShell 7 on Windows. No administrative privilege is requested. Unreadable identity/counters or an exited/recycled PID fail the run rather than substituting zeros. Failed runs retain partial CSV and `FAILED` metadata and cannot be compared by the comparison script.

Outputs:
- `metadata.json`: binary digest/revision, process creation time, OS/CPU/RAM, sampling settings, status and failure reason.
- `samples.csv`: raw elapsed time, CPU delta, machine-normalized CPU%, working set, private bytes, handles and threads.
- `summary.json`: median and p95 via nearest-rank for complete runs only. CPU uses actual measured interval and logical processor count, not assumed sleep duration.

These are overhead measurements, not UI responsiveness benchmarks. Measure cold startup, refresh latency and input latency separately with an instrumented build or Windows Performance Recorder and retain traces. No latency result is fabricated from sampler intervals.

## Safety acceptance (separate from performance)

Run `tools/safety_selftest.cpp` in Windows CI and a disposable local session. Tests must use only processes created by the test itself. Verify valid identity, wrong creation time, wrong image/path, unknown identity, self/system protection, already-exited target and denied access/failure-closed handling where supported. Never test termination against real system/editor/agent workloads.

Manual UI checklist: cancel/No and default Enter terminate nothing; confirmation lists the frozen target set; refresh during the modal dialog does not change approved targets; a process created after confirmation is not added; repeating an action does not terminate a recycled PID. Confirm groups that may contain unsaved work are not classified as automatically safe.

Keep build/test logs and exact commit with each benchmark. Passing CPU/RSS sampling is not proof of safety or a passed Windows UI test. Report each unrun case explicitly. A claimed improvement needs repeated comparable results; no speedup threshold is asserted before collecting a baseline.

### Automated approval-barrier coverage

`tools/confirmation_selftest.cpp` exercises the same `RunConfirmedTermination` used by
both UI termination actions, with injected prompt/execution callbacks. It verifies
all-approvals-before-execution, cancellation, invalid/duplicate identities and a
refresh of the external snapshot during confirmation. The Windows safety test also
asserts `MB_YESNO | MB_DEFBUTTON2` configuration. These are controller/configuration
tests, **not real MessageBox interaction or three-theme visual acceptance**.

The barrier owns a value copy of targets and rejects empty/incomplete/duplicate
identities before asking. Execution still uses `KillPids` to revalidate the same
opened handle. Approval is all-or-nothing; termination itself is not atomic and OS
failures can produce partial results, which remain reported per target.
