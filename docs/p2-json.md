# Read-only JSON schema v1

`readonly_json.h` is a portable, side-effect-free serializer. It has no filesystem,
network, environment, credential, subprocess, configuration or process-action calls.
Public APIs:

- `SerializeSnapshotJson(const Snapshot&)`
- `SerializeFindingsJson(const std::vector<DiagnosticFinding>&)`

Both produce one ASCII JSON object with `schemaVersion: 1`, `readOnly: true`, `kind`,
`source` and `limitations`. This field is descriptive, not an authorization token.
Changing/exporting these objects never grants write access to a caller.

## Snapshot fields

- `sampling`: `startMs`, `endMs`, `complete`, `processEnumerationComplete`.
- `resources`: RAM used/total/percent, commit used/total/percent, system CPU,
  process count, GPU availability/utilization/VRAM/temperature, model observation
  and working set. Invalid capacities are null; unavailable GPU is null. System
  CPU is null because the Snapshot has no validity flag for that measurement.
- `processes`: identity, observed parent PID, working set, memory validity, CPU
  (null until a valid same-identity baseline), and `io` with source, counters-valid,
  PID/creation/tick, read/write cumulative bytes, state, rates and interval.
- `groups`: name, count, working-set sum, null CPU, age, classification,
  `coverage: partialOrUnknown`, classification basis, identities. Aggregates may
  omit unreadable processes and include shared pages. They are not reclaimable
  memory or proof that every member was measured. Legacy classification values
  never imply permission to terminate.
- `resourceEventState`, `resourceEventsOmitted`, `resourceEvents`: kind, identity,
  prior/current sample time and working-set observation. Events are not proof of
  starts/exits/leaks. Only the collector's bounded recent comparison is represented.

Identity fields are `pid`, `creationTime`, `exePath`, `image`, `parentPid`.
All identifiers, 64-bit counters and clocks are decimal strings, not JSON numbers,
so JavaScript consumers do not lose integer precision. Ordinary counts and finite
floating-point measurements are JSON numbers. Nonfinite values become null;
missing IO and per-process memory do not become measured zero. Zero/empty identity
fields retain the model's unknown convention, never a verified identity.

## Finding fields

Each item in `findings` contains `id`, `conclusion`, `state`, `confidenceBasis`,
`evidence` (metric/value/unit/source), `unknowns`, and `nextSteps`. Confidence is an
evidence category, not a numeric failure probability. Provided-log findings must
already be normalized by the evidence parser: this schema has no raw-log field.
It does not inspect or sanitize arbitrary strings inserted by a future caller.

## Encoding and privacy

Quotes, backslashes and controls are escaped. Unicode is emitted as `\uXXXX`, with
valid supplementary scalars/UTF-16 pairs represented by paired surrogate escapes.
Unpaired surrogates and invalid scalar values become U+FFFD. The complete output is
ASCII, also valid UTF-8. Floating numbers explicitly use the classic locale even
when the process locale uses comma decimal separators.

Paths and executable names can identify private projects or users. The caller owns
stdout/redirection and must decide where to store or share output. This serializer
never uploads anything and never reads passwords/tokens/environment variables.
Do not insert secrets or raw logs into normalized evidence fields; there is no
magical secret-detection guarantee. Exporting output to another service needs its
own explicit authorization.

Pure fixtures cover both wchar representations, escaping, invalid numbers,
unknown-vs-zero, schema keys and 64-bit precision. They do not prove Windows
collector correctness or interactive UI behavior.
