# Phase E Protocol Semantics and Input Sizing

Date: 2026-09-10

Specification: [Code review and remediation plan](code-review-2026-09-10.md#phase-e-protocol-semantics-and-input-sizing)

Status: complete for Phase E tasks E1-E2 in the offline implementation and test scope. This phase addresses SOAP response semantics, command-fault retry classification, and serialized stdin envelope sizing. Live Windows/Kerberos large-input parity was not run and is not claimed.

## E1: Protocol Semantics

- Added `SOAPFaultError` with SOAP code, subcode, reason, and WS-Management code fields, plus `ErrOperationTimeout` support through `errors.Is`.
- Parse authenticated SOAP faults from default HTTP errors and Kerberos plaintext or encrypted responses without placing the complete response body in the new public fault error.
- Retry Receive only for the explicitly classified WS-Management operation-timeout fault. Network timeouts and permanent SOAP faults terminate the command.
- Require response actions, nonempty shell and command IDs, and an exit code whenever command state is Done.
- Validate every output stream and command-state identity against the command being polled.
- Restrict the public single-stream parser to the fixed `stdout` and `stderr` selectors, removing caller-controlled XPath construction.
- Preserve existing parser signatures and `ExecuteCommandError` wrapping while making typed faults available through `errors.As`.
- Tests cover permanent faults, repeated operation-timeout faults from HTTP errors and encrypted HTTP-200 Kerberos responses, unsupported actions, missing IDs and exit codes, wrong command identity, malformed exit codes, and malicious stream selectors.

## E2: Serialized Input Sizing

- Replaced the fixed raw-byte allowance with a binary search over actual serialized `NewSendInputRequest` messages.
- Account for base64 expansion, XML framing, URL, shell ID, command ID, locale, timeout, UUID, and the final EOF attribute in the authoritative request size.
- Recheck the exact serialized request immediately before transport and reject any request larger than `Parameters.EnvelopeSize`.
- Preflight the smallest final request so impossible metadata fails before any input bytes are sent.
- Mark stdin closed only after the EOF request succeeds, allowing callers to retry a failed EOF send.
- Tests reconstruct and decode every captured request to prove bounded envelopes, maximal chunks, bytes delivered once and in order, and exactly one EOF marker.
- Boundary coverage includes direct `WriteClose`, `strings.Reader` `WriterTo`, seven-byte `io.CopyBuffer`, long metadata, impossible envelopes, partial transport failures through existing tests, and empty input.

## Recursive Audit

The first focused implementation exposed historical synthetic Receive responses without action headers and final fixtures whose command IDs did not match their command-creation response. Those fixtures were made protocol-complete rather than weakening validation.

The first independent audit found broad EOF string matching, overly broad `ExecuteCommandError.Is` behavior, and missing repeated-timeout coverage. EOF handling now uses wrapped sentinel errors, the invalid equality override was removed, and repeated default-HTTP timeout faults are covered.

The second independent audit found that a typed operation-timeout fault returned in an HTTP-200 SOAP body was terminal. The parser-error path now retries `ErrOperationTimeout`, and an encrypted Kerberos regression proves three such faults are retried before successful completion.

A final independent audit after all fixes and executable gates concluded `NO PHASE E FINDINGS REMAIN` after checking timeout paths, status and body propagation, required semantics, panic resistance, command identity, partial sends, EOF state, binary-search termination, resource release, API compatibility, and test realism.

## Validation

The Phase E tree is validated with:

```sh
CGO_ENABLED=0 go test -count=1 ./...
go vet ./...
go test -race -shuffle=on -count=1 -timeout=120s ./...
go test -race -shuffle=on -count=20 -timeout=120s -run '<Phase E focused tests>' .
CGO_ENABLED=0 go test -run '^$' -fuzz '^FuzzParseCommandResponses$' -fuzztime=10s -parallel=2 .
CGO_ENABLED=0 go test -run '^$' -fuzz '^FuzzParseOutputResponses$' -fuzztime=10s -parallel=2 .
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
```

Focused parser, command, stdin-boundary, and encrypted Kerberos timeout tests passed for twenty shuffled race-enabled repetitions. Both fuzz targets passed their semantic seeds and ten-second campaigns. Govulncheck reported no called vulnerabilities; it reported one module-only vulnerability in a required module whose affected package is not imported or called. Whitespace checks and editor diagnostics are clean.

No live Windows, KDC, or pywinrm run was available. The opt-in live large-stdin/output parity gate remains an interoperability check rather than an unverified completion claim.
