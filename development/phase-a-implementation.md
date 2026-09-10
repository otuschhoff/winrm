# Phase A Security Containment Implementation

Date: 2026-09-10

Specification: [Code review and remediation plan](code-review-2026-09-10.md#phase-a-immediate-security-containment)

Status: complete for Phase A tasks A1-A3. This phase contains immediate security containment; it does not claim completion of the separately scoped Phase B HTTP semantics, Phase D legacy encrypted-NTLM hardening, or Phase G maintenance work.

## A1: Azure NTLM Challenge Parser

- Upgraded `github.com/Azure/go-ntlmssp` from the vulnerable 2022 pseudo-version to `v0.1.1` without unrelated module changes.
- Added an end-to-end malformed-challenge regression using an overflowing NTLM security-buffer offset. Before the upgrade it panicked in the dependency with `slice bounds out of range [4294967292:4]`; after the upgrade it returns an ordinary request error.
- The pinned `govulncheck v1.8.0` scan no longer reports reachable `GO-2026-5543`.

## A2: Safe Diagnostic Defaults

Safe mode is the default for HTTP, SOAP, stderr capture, and file capture diagnostics:

- Authentication, proxy-authentication, cookie, token, secret, credential, password, API-key, private-key, access-key, redirect-location, and referrer headers are replaced with `[REDACTED]`.
- URL user information, query strings, and fragments are removed.
- Payload bytes are omitted from JSON records; records retain byte counts and non-secret protocol/GSS metadata and are marked `redacted=true`.
- Plaintext HTTP/SOAP bodies are represented only by byte count. Encrypted HTTP bodies are summarized without packet bytes.
- Arbitrary HTTP error text is omitted in safe mode; only the error type is retained.
- New capture files use mode `0600`; existing files are tightened to `0600` before append where the platform supports Unix permission bits.
- Disabled capture emits nothing and creates no file.

Raw diagnostics require explicit unsafe selection:

- `SetHTTPDebugUnsafe(true)` enables raw HTTP headers, errors, plaintext, and escaped encrypted packet bytes for process-wide HTTP debugging.
- `OPSCTL_DEBUG_WINRM_UNSAFE=1` or `true` enables raw data for environment-controlled HTTP, SOAP, and JSON capture diagnostics that are otherwise enabled.
- Unsafe JSON captures include raw URLs, headers, base64 payloads, and UTF-8 body text. They can contain credentials, authentication tokens, commands, and command streams.

Tests cover helper behavior and the actual HTTP/SOAP stderr wiring, safe and unsafe JSON records, disabled capture, file creation permissions, existing-file tightening, URL/header/body redaction, unsafe raw output, and response/error redaction.

## A3: Fail-Closed Legacy Encrypted NTLM

- Removed the fallback from failed encrypted-NTLM bootstrap to the non-message-encrypting NTLM transport.
- Propagated NTLM client, HTTP client, security-session, wrap, and bootstrap errors.
- Required exact `multipart/encrypted` media type and the expected NTLM protocol parameter for encrypted responses.
- Rejected plaintext responses without reading their bodies and closed rejected bodies.
- Added a fake-server regression proving a failed bootstrap sends exactly one empty bootstrap request and no plaintext SOAP retry.
- Added a regression proving an unexpected plaintext response is rejected, closed, and not read.

The legacy `Encryption` transport remains a compatibility path. Its custom transport/TLS routing, context cancellation, concurrency ownership, response limits, malformed encrypted framing, and HTTP/SOAP status semantics remain assigned to Phases B and D and are documented in the README. No claim of live NTLM message-encryption interoperability is made by this containment phase.

## Recursive Audit

Three implementation audits were performed after the initial focused tests:

1. Added end-to-end stderr tests after finding that helper-only redaction tests did not prove HTTP/SOAP wiring.
2. Corrected unsafe HTTP mode to include encrypted packet bytes, redacted arbitrary safe-mode error strings, added password-style header matching, and fixed test restoration of the atomic unsafe state.
3. Marked every safe record as redacted even when its payload is empty, strengthened disabled-mode and header variants, and verified rejected plaintext bodies are closed without being read.

An independent read-only audit confirmed A1 and A2 and the A3 no-fallback/plaintext-rejection behavior. It also identified the legacy transport configuration bypass, encrypted non-200 response semantics, and dead protocol placeholders. These are existing findings already assigned to Phase D task D1, Phase B/E fault handling, and Phase G cleanup respectively; Phase A explicitly requires documenting rather than implementing those broader changes.

## Validation

The final Phase A tree passed:

```sh
CGO_ENABLED=0 go test -count=1 ./...
go vet ./...
go test -race -shuffle=on -count=1 -timeout=120s ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 -show verbose ./...
```

- The pure-Go suite passed in both packages.
- `go vet` passed.
- The shuffled race suite passed in both packages without race reports.
- All Phase A regressions passed for 20 shuffled repetitions.
- The pinned vulnerability scan exited successfully with no symbol- or package-level vulnerabilities and no `GO-2026-5543` result.
- Local links in this implementation record and the review report validated, and editor diagnostics reported no errors in the changed Go files or development reports.

The vulnerability scan reports `GO-2026-5932` as a module-only advisory for the unmaintained `golang.org/x/crypto/openpgp` package. The reviewed code does not import or call that affected package, and the advisory reports no fixed version. It is not a substitute for resolving future reachable advisories.

No live Windows, KDC, or pywinrm integration gate is required for these containment changes, and none is claimed here.
