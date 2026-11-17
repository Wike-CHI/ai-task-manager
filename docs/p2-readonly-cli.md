# P2a: local, one-shot, read-only CLI

Build with MSVC C++17:

```cmd
cl /nologo /std:c++17 /EHsc /O2 /utf-8 /W3 src\readonly_cli.cpp /Fe:AITaskManagerReadOnly.exe psapi.lib
AITaskManagerReadOnly.exe snapshot
AITaskManagerReadOnly.exe report
```

`--help` (or no arguments) prints usage. Only one exact command is accepted. Unknown
commands, extra arguments, write verbs, URLs, config and server/MCP flags fail with
exit code 2 before collecting data. Exit 0 means collection completed with process
enumeration success; individual unavailable metrics still remain unknown. Exit 3
means process enumeration failed; inspect JSON unknown/completeness fields rather
than treating missing entries as exited/zero. Exit 4 reports stdout failure. Output is ASCII-escaped JSON v1. Both CLI commands include top-level `sampling` completeness and exact-string timestamps.

The binary takes two local samples separated by 100ms for CPU/I/O deltas and bounded
resource observations. It does not start the GUI, launch child commands, read user
logs, invoke nvidia-smi/LLMs, write files/configuration, serve a network endpoint,
connect to remote hosts or upload output. GPU/temperature/runtime errors remain
unknown. JSON is an interface for an explicitly invoked local Coding Agent, not
permission to execute actions or forward data elsewhere.

Snapshot output contains executable paths and process identity metadata. Keep stdout
local or redact it before sharing. No command lines, environment variables, tokens,
raw logs or credentials are collected. Redirecting stdout is the caller's action;
the CLI never creates an output file itself.

This is **not an MCP server** and does not expose write tools. A future MCP wrapper
or optional LLM adapter needs a separate design, permission boundary and tests. No
write-operation API or implicit authorization is provided here. Deterministic
findings keep their unknowns; JSON does not turn observations into diagnosis.
