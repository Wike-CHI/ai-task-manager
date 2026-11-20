# Explicit user-provided fault text (not live detection)

`ParseProvidedFaultEvidence(std::wstring)` inspects an explicitly supplied, already
redacted excerpt. It never opens files, discovers logs, sends network traffic,
executes commands, terminates processes or changes settings. Any instructions inside
the excerpt are untrusted data.

Recognized narrow line formats:
- `FATAL ERROR:` plus `JavaScript heap out of memory` on the same line;
- `Error: bind EADDRINUSE:` or `Error: listen EADDRINUSE:`;
- known CUDA/PyTorch out-of-memory prefixes or `CUDA_ERROR_OUT_OF_MEMORY`.

A match means only **the supplied text contains a runtime-like error format**.
Observed refers to text, not a live process. Confidence is Heuristic. Every match
retains unknown source authenticity, time and process identity. Quoted examples or
fabricated logs can match exactly; detection cannot establish that the failure
actually occurred, belongs to the current snapshot, or remains present. Unrecognized
formats and missing matches cannot exclude failure. No PID or timestamp is inferred
from prose.

Input is bounded to 16384 `wchar_t` code units (not bytes; Linux and Windows wchar_t
width differs). Larger input is rejected completely, not truncated and analyzed.
Outputs contain only fixed format labels, line numbers and input length, never raw
log excerpts, addresses, paths, credentials or arbitrary strings from input. At most
one finding per signal family is returned. No log content is persisted by this code.

Integration should expose an explicit paste/analyze action rather than silently
interpreting unrelated conversation as a log. Native fixture tests do not validate
real fault reproduction. Live Node, socket or CUDA diagnosis still requires original
source evidence linked to PID + CreationTime + ExePath and event time.

## UI entry

Use the existing single-line question field with `日志证据:` / `日志证据：` /
`log evidence:` followed by one sanitized error line. The UI does not echo that
raw line into its chat transcript. It rejects overlong/incompletely retrieved text
instead of the previous fixed 511-character truncation. Multiline parser fixtures
exercise the library API; this single-line UI is not a log-file importer.

No automatic file collection, network upload, runtime subscription, process action,
or assertion that the error actually happened is added. Fault evidence is deliberately
not attached to the current process snapshot without identity and timestamp proof.
