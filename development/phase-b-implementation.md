# Phase B HTTP Ownership and Error Semantics

Date: 2026-09-10

Specification: [Code review and remediation plan](code-review-2026-09-10.md#phase-b-http-ownership-and-error-semantics)

Status: complete for Phase B tasks B1-B3. This phase addresses built-in HTTP response ownership, diagnostic read parity, and context/deadline cleanup. It does not claim completion of SOAP fault semantics, command lifecycle, or legacy encrypted-NTLM parser and transport work assigned to later phases.

## B1: Response Ownership and Errors

- Replaced the duplicated default and certificate response parsers with one bounded SOAP response reader.
- Parse the response media type with `mime.ParseMediaType` and require exact `application/soap+xml`, rejecting disguised MIME values without reading their bodies.
- Limit body consumption to `Parameters.EnvelopeSize + 1` bytes so oversized responses are detected after bounded consumption rather than read in full.
- Close each response body exactly once on success and every error path. Read and close failures are joined so neither cause is discarded.
- Return explicit errors for HTTP 401, 500, and other non-200 statuses. Bounded SOAP fault content is retained internally for the existing operation-timeout retry classification but is not included in public error text.
- Tests cover HTTP 200/401/500, SOAP and non-SOAP responses, disguised MIME, oversize consumption, partial read failures, close failures, and unread invalid-MIME bodies.

## B2: Bounded Diagnostic Reads

- Removed response-body reads from `debugHTTPRoundTrip`; it now logs only request and response metadata.
- Added response-body diagnostics that receive bytes and errors from the authoritative bounded reader instead of reading or replacing `response.Body`.
- Routed default, certificate, and Kerberos response diagnostics through already-bounded bytes.
- Updated Kerberos bounded reads to close once and preserve close errors.
- Tests prove debug enabled and disabled produce the same size-limit and partial-read errors, consume only the configured limit plus one byte, and close the original body once.

## B3: Context, Deadline, and Cleanup

- Added `PostContext` to certificate authentication while retaining its legacy `Post` method.
- Use context-aware dialing for built-in transports while preserving legacy custom dial functions.
- Apply `Endpoint.Timeout` to the complete default, NTLM, and certificate HTTP exchange, including response-body reads, rather than only response headers.
- Added `Close` implementations that release idle connections; `Client.Close` already delegates to these hooks. Embedded NTLM transports inherit the context and cleanup behavior.
- Normalize timeout errors while preserving wrapped causes, avoiding timing-dependent differences between total-request and response-header deadlines.
- Documented that third-party `Post`-only transports remain compatible but cannot receive caller cancellation or cleanup hooks.
- Tests cover canceled certificate requests, a local server that sends headers and stalls its body, and idle cleanup for both built-in transport implementations.

## Recursive Audit

The first implementation audit found that preserving safe HTTP error text removed the SOAP body substring previously used to classify WS-Man operation timeouts. A bounded internal typed error now carries that body without exposing it through `Error`, and the existing retry behavior is covered by the command tests.

The first shuffled race gate then found a timing-dependent error string: either the response-header timeout or the whole-request timeout could win. Built-in transports now add stable lowercase timeout context while retaining the original wrapped error. The affected timeout test passed five consecutive race-enabled runs before the complete race gate was repeated.

A read-only source audit found no remaining B1-B3 gaps. Findings for SOAP fault typing, context-aware serialized command/Kerberos admission, and legacy encrypted-NTLM parsing and transport configuration remain assigned to Phases C-E.

## Validation

The final Phase B tree passed:

```sh
CGO_ENABLED=0 go test -count=1 ./...
go vet ./...
go test -race -shuffle=on -count=1 -timeout=120s ./...
go test -race -count=5 -timeout=30s -check.f '^TestConnectionTimeout$' .
```

Focused B1-B3 tests also passed for status/MIME handling, bounded consumption, partial reads, close errors, diagnostic parity, caller cancellation, whole-response deadlines, and idle cleanup. Editor diagnostics reported no errors in the changed Go files; existing repository-wide README lint findings predate this phase.

No live Windows or server interoperability gate is required for these local HTTP ownership changes, and none is claimed here.
