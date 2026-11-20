# P1f: process identity service and endpoint association

`process_identity.h` owns FILETIME conversion, case-normalized path/image identity
reads, same-handle tuple verification and tri-state critical-process status. It
never opens a PID, terminates a process, authorizes an action or silently converts
read failure into a valid identity. The caller owns the supplied process handle.
Reading an identity alone does not establish liveness or parent/project identity.
Case normalization is not filesystem canonicalization or executable trust.

The collector and termination engine share this module. Collection still rejects
processes created after the enumeration boundary. CPU counters are checked against
the identity creation time. Protection policy, all-approvals barrier and independent
force authorization are unchanged.

TCP evidence now re-queries the matching endpoint while holding the identified
process handle, then checks the same handle's liveness and identity again. The
report records association timestamp/status. This is a direct observation of that
endpoint/PID tuple and process identity during one query, not atomic kernel evidence
or proof of historical bind failure. Failed/changed association remains unknown.
No user-provided error text is promoted to verified runtime evidence.

Windows tests use the test process itself with read-only permissions. Existing
safety and loopback suites remain required. Hard-fault tracing, authentic runtime
error collection and timestamp/identity-bound historical fault correlation are
still separate work.
