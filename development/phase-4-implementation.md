# Phase 4 Implementation: Command and Session Parity

Date: 2026-09-07.
Status: Complete.

## Implemented behavior

- Reuses one mutually authenticated, connection-bound Kerberos context across sequential and concurrent commands.
- Preserves cmd and encoded PowerShell behavior, stdout/stderr separation, nonzero exit codes, UTF-8 output, stdin EOF, and output spanning multiple Receive responses.
- Sends finite high-level stdin and its EOF before starting Receive. This is required because encrypted requests share one serialized HTTP connection.
- Propagates contexts through the default HTTP transport and command Receive, Send, Signal, and shell cleanup paths.
- Cancels blocked negotiation, stdin, and Receive work, then performs bounded Signal/Delete cleanup.
- Tracks active commands so client shutdown cancels and joins them before closing the transport.
- Synchronizes command result and cleanup state for concurrent callers.
- Treats malformed base64, invalid exit codes, short writes, destination failures, and input-send failures as errors instead of silently returning partial success.
- Invalidates an expired or failed GSS context without replaying the protected SOAP request. A later operation performs a fresh bootstrap.

## Test evidence

Deterministic tests cover:

- Three sequential encrypted command lifecycles with cmd, PowerShell, Unicode, separate streams, exit code 23, stdin EOF, and 180 KB output split across Receive responses.
- Eight concurrent commands sharing one encrypted session and RFC 4121 sequence state.
- Negotiation, input, and Receive cancellation; server EOF; client shutdown; one-time Signal/Delete cleanup; stdin and output failures; and GSS-context expiry followed by fresh authentication without replay.
- Default HTTP request cancellation and strict stream/exit-code parsing.

The opt-in `TestKerberosPhase4ComparisonWithPywinrm` gate runs six read-only or ephemeral scenarios through one Go client and one pywinrm session. It compares the complete raw result matrix and independently checks expected semantics. On 2026-09-07 it passed against the configured HTTP 5985 target with `CGO_ENABLED=0`, including a 200 KB output case.

Validated commands:

```sh
CGO_ENABLED=0 go test ./... -count=1
go test -race ./... -count=1
WINRM_PYTHON="$PWD/.venv/bin/python" WINRM_KERBEROS_PHASE4_COMPARISON=1 \
  CGO_ENABLED=0 go test . -run '^TestKerberosPhase4ComparisonWithPywinrm$' -count=1 -v
.venv/bin/python -m unittest -v development/test_compare_pywinrm.py
```

## Expiry boundary

The gokrb5 GSS context interface does not expose context lifetime. Expiry is therefore detected when a protected operation fails. The session is invalidated, the failed SOAP request is not replayed, and the next operation establishes a fresh context. The deterministic test injects the same `Wrap` failure contract; it does not claim that wall-clock ticket expiry was forced on the live domain.
