# P3 readiness: evidence and distribution, not a release announcement

## Current and proposed channels

See [artifact candidate channels](p3-artifact-channels.md) for the subsequent implementation
in this Draft branch. It removes publishing here but has not changed main. The following
readiness gates remain applicable.

Baseline before that patch: development PR checks and unsigned CI artifacts. The existing build workflow
also publishes from main pushes. No Stable/Nightly separation is active. This document
**does not change that workflow or repository settings**.

Proposed, requiring a separately reviewed workflow change before activation:

| Channel | Trigger | Required evidence | Publication boundary |
| --- | --- | --- | --- |
| PR build | pull request | native + portable + protocol tests | artifacts only; read-only token where possible |
| Nightly | explicitly approved schedule/manual run | pinned source SHA, tests, manifest, known gaps | prerelease only, no silent stable promotion |
| Stable | explicitly approved version/tag | reviewed immutable SHA, full tests, UI acceptance, provenance/signature plan | owner approves publication and release notes |

Before any merge intended to be release-neutral, review/remove or gate the existing
main-push auto-release behavior in a separate change. Do not assume a GitHub environment
approval exists; check its actual configuration before relying on it. No environment,
repository permissions, workflow schedule, tag or release is changed by this patch.

## Supply-chain and packaging gates

- Produce separate GUI and read-only CLI archives with SHA256 manifest, exact source
  commit and reproducible build command/toolchain version. Hashes establish identity,
  not publisher trust or safety.
- Choose a signing/provenance mechanism and authorized certificate/key storage before
  claiming trusted distribution. Do not invent a signer or bypass SmartScreen.
- Keep optional Python/MCP dependencies separate. The tested MCP SDK is pinned, but
  a complete transitive dependency lock/hashes and upgrade testing remain needed.
- Preserve portable single-exe native usage; an installer is optional, not a reason
  to silently add services, elevation, startup tasks or automatic updates.
- A future packaged release must include license/dependency notices and explicit
  unknowns. No installer/signing pipeline is implemented here.

## Controlled fault demonstration

`tools/demo_port_conflict.cpp` creates an exclusive **owned loopback** listener on an
OS-selected ephemeral port, attempts a second bind to that exact endpoint, records
the actual Windows rejection, and checks the listener's current process identity.
After closing the original listener it retries the bind. Both sockets are owned by
this process and closed on exit. It does not contact a remote endpoint, change a
firewall, terminate another process or reserve a fixed user's port.

```cmd
cl /nologo /std:c++17 /EHsc /O2 /utf-8 /W3 tools\demo_port_conflict.cpp /Fe:build\demo_port_conflict.exe
build\demo_port_conflict.exe
```

The demo accepts Windows' address-in-use or exclusive-bind access-denied result and
prints the exact numeric code. It is a bounded reproducible bind-failure fixture,
not proof that an arbitrary historical EADDRINUSE log belongs to a current listener,
not a Node.js/GPU OOM demo, and not a production conflict-remediation feature.

## Benchmark status

The existing read-only benchmark sampler records pinned executable hashes, raw
samples and median/p95. A real comparison requires a specific official Argus version,
matching workloads and repeated same-machine runs. No Argus binary, recorded real
comparison or performance superiority is supplied by this change. Follow
[the benchmark protocol](benchmark.md); retain failed and unfavorable runs too.
Root-process-only samples must not be represented as multi-process application cost.

## Remaining acceptance gates

1. Real Windows GUI/save-dialog/default-No/cancellation and multi-theme inspection.
2. Hard-fault/disk latency sources and authenticated runtime fault correlation.
3. Optional LLM provider transport, explicit data destination authorization and isolation.
4. Real workload benchmark and additional bounded fault demonstrations.
5. Approved release policy, immutable manifests, signing/provenance and channel validation.
