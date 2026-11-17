# P0: read-only memory observation

The floating memory indicator and tray menu no longer trim working sets.

- A single floating-ball click opens the main window and refreshes the snapshot.
- The ball's context menu and tray's **查看内存详情** do the same.
- No `EmptyWorkingSet`, `SetProcessWorkingSetSize`, system-wide process trim,
  trim worker thread, or trim completion message remains in `src/main.cpp`.
- The old trim animation/toast and its “memory released” claims were removed.
- Working set measurements remain observations, not promises of reclaimable RAM.

This change deliberately removes the operation rather than merely hiding it behind
an option. Closing a process is a separate explicitly confirmed workflow; the
observation controls do not invoke it.

Validation: source inspection and `git diff --check`. Native Windows build and
manual click/drag/tray acceptance must be verified separately; a source check is
not a completed interactive test.
