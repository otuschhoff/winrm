# Phase C Command Cancellation and Lifecycle

Date: 2026-09-10

Specification: [Code review and remediation plan](code-review-2026-09-10.md#phase-c-command-cancellation-and-lifecycle)

Status: complete for Phase C tasks C1-C3. This phase addresses internal output ownership, context-aware serialized admission, and client/shell/command lifecycle cleanup. It does not claim to interrupt a caller-owned `io.Writer` whose `Write` method never returns, or complete the separately scoped protocol and legacy encrypted-NTLM work.

## C1: Output Failure and Cancellation

- Propagate stdout and stderr pipe-write failures from the fetch loop instead of discarding them.
- When a destination writer returns an error, close the corresponding internal pipe reader and cancel the command so a later response cannot block on an abandoned stream.
- Watch command cancellation and close both internal output readers, allowing unread low-level streams to unblock the fetch loop.
- Close command output writers, unregister ownership, close `done`, and cancel the child context exactly once on terminal completion.
- Preserve the original destination error through the high-level Run APIs.
- Tests cover two non-final responses for stdout and stderr failures, unread stdout and stderr, command completion, active-command cleanup, and server-side EOF.

An arbitrary caller-owned `Write` implementation that never returns cannot be interrupted by this library. Phase C guarantees cleanup once the destination returns an error and guarantees cancellation of the library-owned pipe boundaries.

## C2: Context-Aware Serialized Admission

- Replaced the Kerberos session mutex admission with a single-token context-aware permit while retaining serialization across negotiation, HTTP exchange, and GSS wrap/unwrap state.
- Added context-aware admission to command Signal requests so a cleanup caller does not wait indefinitely behind another Signal.
- Added bounded Kerberos session close and retained idempotent credential and idle-connection cleanup.
- Give an already-canceled context priority before and immediately after permit acquisition so cancellation cannot consume a Signal, shell close, or Kerberos operation attempt.
- Tests cover canceled Kerberos waiters while the owner remains busy, close deadlines, Signal admission deadlines, and retry after canceled cleanup. Existing concurrent encrypted-command tests continue to verify one shared GSS context without overlap or replay.

## C3: Client, Shell, and Command Ownership

- Added explicit client open, closing, and closed states with cancelable admission for remote shell and command creation.
- `Client.Close` atomically stops new creation, cancels and waits for already-admitted operations within one cleanup budget, then snapshots and cleans owned commands and shells before closing the transport.
- Concurrent and repeated client close calls wait for and return the same result; transport close runs once.
- Track shells as client-owned resources. Shell Execute and Delete use context-aware serialized admission, reject use after close, and make Delete idempotent.
- A command or shell whose remote creation completes during shutdown is registered before the admitted operation ends, so client close owns and cleans it. If creation outlives the close budget, the late completion takes a bounded direct Signal/Delete cleanup path instead of registering after the cleanup snapshot.
- Surface Signal and Delete failures through command, client-close, and high-level Run results with `errors.Join`.
- Cancel command child contexts on normal completion rather than retaining the parent relationship until later cleanup.
- Tests cover close during shell and command creation, post-close creation and Execute, concurrent client close, repeated shell close, child-context release, bounded shell close, and joined Signal/Delete failures.

## Recursive Audit

The initial C1 regression reproduced a fetch-loop hang on the second non-final response after a destination writer failed. Closing the library-owned read side and propagating fetch write errors removed the block.

The first implementation audit found two rare shutdown edges: cleanup stopped iterating after one Signal error, and a creation operation that exceeded the close budget could register after the cleanup snapshot. Cleanup now continues across errors, and timeout transitions close registration before snapshotting so late completion performs direct cleanup.

A second manual audit found a canceled-context selection race where a ready permit could win over `ctx.Done`, consuming a one-shot cleanup attempt. Admission now checks cancellation on both sides of permit acquisition, with direct retry regressions for Signal and Delete.

An independent read-only audit found all C1-C3 acceptance criteria satisfied before the final cancellation-priority hardening. A fresh final audit against the completed tree explicitly concluded `NO PHASE C FINDINGS REMAIN` after checking cancellation races, close ordering, late registration, cleanup errors, gate safety, and API compatibility.

## Validation

The completed Phase C tree passed:

```sh
CGO_ENABLED=0 go test -count=1 ./...
go vet ./...
go test -race -shuffle=on -count=1 -timeout=120s ./...
go test -race -shuffle=on -count=20 -timeout=120s -run '<Phase C lifecycle tests>' .
```

All focused lifecycle tests passed for twenty shuffled race-enabled repetitions. Whitespace checks passed, and editor diagnostics reported no errors in the changed production and test files.

No live Windows, KDC, or pywinrm integration gate is required for these local ownership changes, and none is claimed here.
