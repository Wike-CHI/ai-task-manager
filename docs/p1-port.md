# P1e: read-only TCP listener evidence

Explicit aliases are `端口 3000` and `port 3000`. A single ASCII space and decimal
port in 1..65535 are required. No hostnames, ranges, commands or UDP lookup are
accepted. `ParsePortQuery` is portable; the Windows interface is
`QueryTcpListenerEvidence(uint16_t)` (rendered text) or `QueryTcpListeners` (data).

The IP Helper API `GetExtendedTcpTable` uses `TCP_TABLE_OWNER_PID_LISTENER` for
both AF_INET and AF_INET6. Each family reports its own status, including failure;
a failed query is not an empty successful result. Bounded 8 MiB buffers and three
retries limit table-growth handling. Reports contain at most 128 matching rows and
state omitted counts. Addresses include IPv6 scope IDs when relevant.

A second table observation matches address/family/port/scope/PID before reading
that process's creation time and executable path. Process identity is unreadable
or unknown if permissions, exit or timing prevent inspection. Creation newer than
the table's pre-query FILETIME boundary is rejected rather than attributed to a
potentially recycled PID. Table and process reads are not atomic: reobservation
reduces a race but cannot prove uninterrupted endpoint ownership.

This is current listener evidence, **not diagnosis of port conflict**. It does not
link an earlier EADDRINUSE line to the current listener, establish the original
bind address/protocol/options, or prove that a free-looking port can be bound.
UDP, reserved/excluded port ranges, firewalls and failed bind attempts are not
collected. Lookup itself does not connect to a remote system, bind a port, close
an endpoint, terminate a process or write settings. Tests alone create temporary
loopback sockets owned by the test executable; IPv6 absence is explicitly skipped.

## Build integration

Include `port_evidence.h` before non-lean `windows.h`, or define
`WIN32_LEAN_AND_MEAN` consistently before Windows headers. `main.cpp` already does
so; standalone tests that first include collector/Windows headers need the same
preprocessor definition. The header links `iphlpapi.lib` and `ws2_32.lib` via pragma.
Portable parser tests: `tools/port_query_selftest.cpp`. Native Windows API/fixture
tests: `tools/port_evidence_selftest.cpp`. Native tests do not certify real-world
bind conflict attribution or interactive UI behavior.

References: [GetExtendedTcpTable](https://learn.microsoft.com/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable),
[MIB_TCP6TABLE_OWNER_PID](https://learn.microsoft.com/windows/win32/api/tcpmib/ns-tcpmib-mib_tcp6table_owner_pid).
