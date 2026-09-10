# Code Review: 2026-09-10

## Recommendation

Prioritize diagnostic-data protection, the vulnerable NTLM dependency, legacy encryption fail-closed behavior, and command cancellation before expanding concurrent or untrusted-endpoint use. Kerberos has useful separation between session establishment, message framing, and GSS protection, but those protections are not consistent across transports. Passing tests currently miss demonstrable hangs, panics, and false-success responses.

This is a review and remediation specification, not an implementation or a new live Windows certification. Production code and dependencies were not changed. Findings apply to revision `838e73a9efd4f69b37e23e4bf5b7b84e8576b43d` (`v0.1.1`), with gokrb5 `v8.5.3`. The initial worktree was clean. Review date: **2026-09-10**.

Remediation update: Phase A tasks A1-A3 were implemented and recursively audited on 2026-09-10. See [Phase A security containment implementation](phase-a-implementation.md). R2 and R4 are resolved by that work; R5 is contained against plaintext fallback and unexpected plaintext responses, while its remaining transport/concurrency work and R6 parser hardening remain assigned to Phase D. This report otherwise preserves the baseline findings against revision `838e73a`.

## Scope and Method

- Reviewed production lifecycle, transports, framing, request/response parsing, SOAP helpers, neighboring tests, dependency declarations, CI configuration, and usage documentation.
- Ran the existing offline suite, statement coverage, vet, shuffled race tests, four short fuzz campaigns, and a Go vulnerability scan.
- Ran 10 temporary synthetic probe tests using local fixtures. A passing probe meant the undesirable behavior was reproduced, not that the feature was correct. No real credentials were used. The probe harness was removed after collecting evidence; reproduction recipes are below.
- Ran temporary parser/debug allocation benchmarks three times per case. These do not measure live encrypted WinRM throughput or peak RAM.
- Did not run live Windows/KDC or pywinrm comparisons, production load tests, real-workload CPU/heap profiles, or hosted CI. Did not inspect ignored credential files. Reviewed dependency advisories and adapter usage, not dependency cryptographic internals.
- Confidence labels: **runtime-confirmed** means a synthetic probe reproduced the behavior; **source-confirmed** means the controlling code establishes it; **scanner-reported** means a tool identified it; **risk** means deployment impact needs measurement.

## Findings

### R1. High: Output writer failure can hang a command despite cancellation

**Evidence: runtime-confirmed.** [command.go](../command.go#L183) writes synchronously to pipe writers and ignores their errors. [client.go](../client.go#L282) lets a failed destination terminate `io.Copy` without closing the corresponding internal reader or promptly canceling the command. A second output response then blocks the fetch goroutine; `Wait` never observes completion, even after cancellation.

The probe returned non-final stdout twice to an immediately failing destination, canceled after the second Receive, and observed no completion for 100 ms. Closing the internal readers released the run. This is not merely an arbitrary user writer blocking. An unread low-level stream has a related backpressure/cancellation problem. The existing output-failure test in [command_context_test.go](../command_context_test.go) supplies only one final response.

**Impact:** stalled commands, retained goroutines/shells, and exhausted concurrency slots. **Fix:** coordinate internal reader closure, cancellation, and terminal state on destination failure; cancellation must interrupt internal pipe writes. Preserve the writer error and bound cleanup. Do not promise interruption of arbitrary caller-owned `Write` implementations that never return.

### R2. High: Opt-in diagnostics disclose authentication and command data

**Evidence: runtime- and source-confirmed.** [debug_capture.go](../debug_capture.go#L128) copies headers and records base64 plus UTF-8 plaintext payloads. [debug_capture.go](../debug_capture.go#L160) opens files with `0644`; the probe observed mode `0644` and an unredacted synthetic Authorization header. [debug_http.go](../debug_http.go#L163) dumps all headers, including Basic authentication values supplied by the default transport. Base64 is not redaction.

**Impact:** credentials, tokens, commands, input, and output enter stderr or potentially other-user-readable files. Existing-file permissions are not tightened by `OpenFile`. Opt-in behavior limits exposure but does not make captures safe to share. Capture is intentional functionality; deleting it outright would change compatibility.

**Fix:** redact authentication/cookie headers by default; create capture files with restrictive permissions (`0600` on Unix), define existing-file behavior, and require a separate explicit unsafe mode for raw payload/token capture. Document stderr sensitivity and retention. Test safe, unsafe, and disabled modes independently.

### R3. High: HTTP debugging bypasses bounded reads and loses body ownership

**Evidence: runtime- and source-confirmed.** [debug_http.go](../debug_http.go#L151) performs unbounded `io.ReadAll`, replaces the response body without closing the original, and does not restore partial data on a read error. [kerberos_session.go](../kerberos_session.go#L169) calls it before encrypted-response bounds; plaintext requests do likewise. Bootstrap has an additional outer bounded-reader wrapper, so this unbounded claim does not apply identically there.

The helper consumed an entire synthetic 1 MiB response; closing its replacement did not close the original. **Impact:** diagnostic mode changes memory limits and error semantics, can consume attacker-controlled data before rejection, and can retain transport resources. **Fix:** debug authoritative already-bounded bytes, retain close ownership, and propagate read failures. Test oversize input, partial-read errors, and exactly-once close with debug on/off.

### R4. High: Reachable vulnerability in the Azure NTLM dependency

**Evidence: scanner-reported.** `govulncheck v1.8.0` reported [GO-2026-5543](https://pkg.go.dev/vuln/GO-2026-5543): malformed NTLM challenges can panic in `github.com/Azure/go-ntlmssp`, pinned to `v0.0.0-20221128193559-754e69321358` in [go.mod](../go.mod#L6). The reported fixed version is `v0.1.1`. The removed negotiator was implemented in `ntlm.go`.

**Impact:** malformed authentication challenges can crash users of the Azure NTLM path. The scanner's example trace passes through a generic `RoundTripper` call in the Kerberos wrapper; this interface-analysis trace does not prove that configured Kerberos-only authentication uses Azure NTLM.

**Fix:** upgrade to a reviewed compatible fixed version in an isolated dependency change, retain malformed-challenge coverage, and rerun NTLM tests and the scanner. Treat the separate module-only OpenPGP result below distinctly from reachable application behavior.

### R5. High: Legacy NTLM encryption silently downgrades and ignores transport settings

**Evidence: source-confirmed.** The removed `encryption.go` created a bare `http.Client` but configured TLS/routing on a different embedded transport. Encrypted requests therefore did not use that configured CA, insecurity setting, or endpoint timeout. It ignored constructor errors, replaced shared authentication state on each Post, retried bootstrap failures through non-message-encrypting NTLM, and accepted responses lacking the expected encrypted protocol as plaintext.

**Impact:** selecting encryption does not guarantee encrypted SOAP over HTTP. Configuration differs between paths, and concurrent use of one `Encryption` instance races shared authentication state. Existing race tests do not execute this implementation (0% statement coverage).

**Fix:** fail closed, propagate initialization/wrap errors, use the configured HTTP transport, and define serialized session ownership plus cancellation. Never share NTLM sequence state across concurrent exchanges or silently downgrade message protection.

### R6. High: Malformed legacy encrypted responses panic and lack resource bounds

**Evidence: runtime- and source-confirmed.** The removed `encryption.go` assumed paired MIME parts and `Length=` metadata, read without a limit, ignored read errors, did not close the encrypted response body, and sliced signature data without checking available lengths. A synthetic body `invalid` panicked with index out of range before any crypto operation.

**Impact:** endpoint-controlled crash, unlimited response allocation, and resource leakage. This is independent of the upstream challenge-parser vulnerability in R4. **Fix:** bounded reads, checked part/header/slice lengths, strict protocol/length validation, guaranteed close, and error propagation. Reuse Kerberos framing principles without conflating NTLM and Kerberos token formats. Add direct legacy-parser fuzzing.

### R7. High: Legacy HTTP lacks consistent body, lifetime, and cancellation bounds

**Evidence: runtime- and source-confirmed.** [http.go](../http.go#L20) and [auth.go](../auth.go#L64) use unbounded reads and substring MIME checks. Both return without closing a mismatched-content-type body; probes confirmed this. Their deferred close-error assignments cannot change unnamed return values.

The default HTTP client has no total timeout; `ResponseHeaderTimeout` does not bound body streaming. Default/NTLM requests support caller contexts, but the built-in certificate transport [auth.go](../auth.go#L86) lacks `PostContext`, so compatibility dispatch drops cancellation. Default/certificate transports lack explicit Close hooks and configure no idle-connection lifetime. Legacy encrypted transport has additional issues in R5/R6.

**Impact:** stalled reads, unbounded RAM growth, non-interruptible certificate requests, and idle-resource retention in long-lived/many-client workloads. **Fix:** shared response-ownership policy, exact MIME parsing, body limits, effective request/body deadlines, built-in `PostContext`, and idle cleanup. Preserve the documented limitation of third-party transports implementing only legacy `Post`.

### R8. High: HTTP and SOAP faults can appear successful or repeatedly poll

**Evidence: runtime- and source-confirmed.** [http.go](../http.go#L114) and [auth.go](../auth.go#L108) try to replace return values in deferred closures despite unnamed returns. Both returned HTTP 500 SOAP and nil error in the probe. [kerberos_session.go](../kerberos_session.go#L169) does not check encrypted-response status after successful unwrap. [response.go](../response.go#L114) does not identify SOAP Faults; a valid fault parsed as `finished=false`, exit 0, nil error.

**Impact:** failures disappear, and Receive can repeatedly poll permanent faults such as access denied. Fast fault responses can create CPU/network load. [command.go](../command.go#L183) also classifies timeouts/EOF partly by string matching and retries transport timeouts, not only expected WS-Man idle-output faults.

**Fix:** evaluate HTTP status before return, authenticate/decode protected SOAP faults into typed errors, and retry only explicitly classified conditions. Preserve status and wrapped cause without exposing full sensitive response bodies. Test fatal faults versus expected operation timeouts, non-SOAP errors, and retry termination.

### R9. High: Kerberos queueing defeats cancellation and cleanup deadlines

**Evidence: runtime- and source-confirmed.** [kerberos_session.go](../kerberos_session.go#L154) holds a plain mutex across negotiation, HTTP I/O, and diagnostics. An already-canceled caller remained blocked for the entire 100 ms probe until the lock was released. [kerberos_session.go](../kerberos_session.go#L342) Close waits on the same mutex without a context. [command.go](../command.go#L170) holds an ordinary mutex across Signal I/O too.

**Impact:** short-deadline callers queue behind long Receive operations; five-second cleanup contexts do not bound lock acquisition. After its wait timer expires, Client.Close can still block in transport Close. Pending shell creation is not in the active-command set. Endpoint network deadlines do not cover queueing or blocked diagnostic output.

**Fix:** context-aware serialized admission and explicit shutdown/cancellation of in-flight operations, with bounded waiting for concurrent Signal calls. Preserve connection-bound GSS sequence serialization; simply removing a mutex is not a valid fix. Test canceled waiters and shutdown during Create/Receive.

### R10. Medium: Stdin chunking exceeds the advertised SOAP envelope

**Evidence: runtime-confirmed.** [command.go](../command.go#L280) budgets `EnvelopeSize - 1000` raw bytes, but [request.go](../request.go#L119) adds base64 expansion and XML. With the default 153,600-byte limit, a 152,600-byte chunk serialized to **204,731 bytes**. Kerberos framing rejects it, and legacy servers can reject it too.

**Impact:** large direct writes and string readers using `WriteTo` can fail although small-buffer reads succeed. **Fix:** budget serialized overhead and base64 expansion, including endpoint/ID/locale lengths, then assert final request size. Test boundaries, long metadata, partial writes, empty input, and EOF. Do not substitute another unexplained fixed overhead constant.

### R11. Medium: Client and shell lifecycle ownership is incomplete

**Evidence: runtime- and source-confirmed.** [client.go](../client.go#L122) does not reject requests after Close; a fixture-backed closed client successfully created a shell. [shell.go](../shell.go#L28) sends Command before registering it, so concurrent Close can allow remote execution followed by rejected local ownership. Shell Close tracks no closed state despite documenting that no further commands can be issued.

[client.go](../client.go#L287) discards shell-delete and later command-close errors. [command.go](../command.go#L129) finishes without canceling its child context; low-level commands not explicitly closed can leave child contexts attached to a long-lived cancellable parent until parent cancellation. High-level Run calls Close afterward. That retention impact is source-derived, not measured.

**Fix:** define open/closing/closed admission separately from cleanup, account for creation races, cancel contexts on terminal completion, and join meaningful cleanup errors. Test concurrent/idempotent Close and creation/registration interleavings. A blanket closed check must not block legitimate Signal/Delete cleanup.

### R12. Medium: Incomplete response state is accepted and public XPath input can panic

**Evidence: runtime-confirmed.** [response.go](../response.go#L38) returns empty string and nil error for missing nodes; an empty ShellId also succeeds. Done without ExitCode becomes exit 0. [response.go](../response.go#L170) interpolates `streamType` into XPath and passes it to `MustParse`; a single quote panicked in the public parser.

**Impact:** invalid IDs reach requests, malformed completion appears successful, and caller-controlled stream selectors can crash the process. **Fix:** validate required IDs/completion fields, action and relevant command identity; use fixed supported selectors or an error-returning parser. Test well-formed XML with invalid semantics, not only broken XML/base64.

### R13. Medium: Diagnostic and parser allocation costs are material and unbudgeted

**Evidence: measured and source-confirmed; production capacity impact remains a risk.** [debug_http.go](../debug_http.go#L77) allocates while formatting individual non-ASCII bytes. Synthetic 64 KiB binary input cost 6.15-6.56 ms, about 2.20 MB allocated, and 131,079 allocations. This deliberately exercises the non-summary path, not the recognized encrypted-packet summary path.

[response.go](../response.go#L60) repeatedly compiles XPath over a DOM; parsing 64 KiB decoded stdout allocated about 562 KB. [command.go](../command.go#L215) buffers decoded streams again. [debug_capture.go](../debug_capture.go#L128) can retain base64, text, and JSON representations, opens/closes per record, and appends synchronously under a global mutex while the session is held. It has no rotation/total-byte budget. String-returning client helpers accumulate all output without an aggregate limit.

**Fix:** add persistent benchmarks and workload budgets, eliminate per-byte debug allocation, cap/rotate diagnostics, and reduce measured redundant copies. Consider immutable precompiled selectors before a parser rewrite. Prefer streaming for unbounded-output workloads; introduce opt-in output limits rather than silently truncating existing APIs.

### R14. Medium: CI, examples, and architecture documentation have drifted

**Evidence: source-confirmed; hosted lint not executed.** [.golangci.yml](../.golangci.yml#L1) uses Go 1.21 settings and obsolete linter names; [go.mod](../go.mod#L3) requires Go 1.26. The [lint workflow](../.github/workflows/lint.yaml#L25) combines action v3 with floating `latest`, not a reproducible tool/config pairing. It ignores dependency/configuration-only PRs. The [test workflow](../.github/workflows/go.yml#L28) runs `make ci` without explicit pure-Go, race, fuzz, or vulnerability gates.

[Makefile](../Makefile#L11) fetches dependencies during tests and uses obsolete flags in its update target. [README.md](../README.md#L439) gives outdated cancellation guidance, names nonexistent `command.Stop`, and later says Go 1.5+. Examples mutate shared `DefaultParameters`, omit imports/qualifiers, or disable verification. Commented-out protocol placeholders in the removed `encryption.go` obscured actual support.

**Impact:** misleading usage guidance, unreproducible checks, global configuration coupling, and overconfidence in release gates. **Fix:** pin compatible tooling, expand workflow triggers/gates, compile examples, copy defaults before customization, document transport-specific contracts, and remove dead placeholders separately from behavioral fixes.

## Quality and Structure Assessment

| Area | Assessment |
| --- | --- |
| Code quality | Kerberos code is comparatively small and explicit; unchecked legacy errors, misleading defer assignments, and ignored pipe failures are concrete correctness debt. |
| Structure | GSS adapter, framer, and session are useful boundaries. Request builders and response parsing are separated. Duplicated HTTP response handling causes divergent guarantees. |
| Maintainability | Stable public transport interface supports customization, but optional context/close interfaces are inconsistently implemented by built-ins. Global debug/default settings and `OPSCTL_*` names couple policy to an embedding application. Preserve existing knobs through additive API migration. |
| Security | Normal Kerberos mutual auth, confidentiality, strict framing, and explicit modes are strengths. Diagnostics and both NTLM paths need the high-priority work above. Basic over HTTP and explicitly insecure TLS remain configuration risks, not newly proven exploits. |
| Scalability | One active HTTP exchange per Kerberos session is intentional. Concurrent API calls do not imply parallel remote I/O. Long polls, non-cancelable admission, and global capture I/O cause head-of-line blocking. No client admission limit or session pool exists. |
| CPU/RAM | Kerberos wire limits are not aggregate heap bounds. DOM/base64/copies, uncapped legacy reads, unlimited string output and capture representations drive allocation. |
| Error handling | Wrapped Kerberos errors, stream decode checks, and joined high-level errors help. Status/fault handling, close errors, lifecycle admission, and shape validation remain inconsistent. |
| Tests | Good Kerberos fixture coverage and legacy request-builder coverage. Statement coverage does not prove backpressure, resource ownership, failure sequencing, or hostile-input safety. |

### Resource and Concurrency Model

- Default envelope: 153,600 bytes. Encrypted-response read budget: 157,952 bytes (envelope + 256 wrap overhead + 4,096 metadata). Bootstrap body: 4,096 bytes, at most five exchanges.
- Message strings, wire buffers, crypto tokens, DOM nodes, decoded buffers, and caller output can coexist. Wire budget is not a per-command heap cap.
- One established Kerberos session processes at most one HTTP exchange at a time. At average service time `T`, capacity cannot exceed approximately `1/T` exchanges/second before orchestration. A command needs multiple exchanges. This is a model, not measured throughput.
- Queued callers/output consumers grow with command count; string helpers grow with total output. No process-wide command/output/capture budget exists. No evidence supports a safe maximum concurrency or RSS ceiling yet.
- High-level stdin is fully sent before Receive starts, regardless of transport. This avoids Receive blocking Send on a serialized connection but risks input/output backpressure for large echoing or interactive programs. No live finite-buffer stress test was run; duplex support needs an explicit design decision.
- Any future pool needs independent authenticated connections/contexts and shell affinity. Sharing one GSS context across connections is not a scaling strategy.

## Measured Metrics

Physical lines include comments/blank lines and are not a complexity score. Baseline metrics exclude temporary probes.

| Metric | Result |
| --- | --- |
| Production | 22 Go files, 3,605 physical lines, 2 packages |
| Tests | 25 Go files, 4,501 physical lines; test/source ratio 1.25 |
| Static test entry points | 113 Go/gocheck function/method declarations; not an execution count and excludes subtest expansion |
| Persistent fuzz / benchmark functions | 4 / 0 |
| Large production files | Kerberos session 469 lines; legacy encryption 438; client 359; command 353 |
| Module graph | 45 modules including root; scanner loaded 21 including root plus standard library |
| Pure-Go graph | No Cgo/SWIG file-bearing package reported with `CGO_ENABLED=0` |
| Overall statement coverage | **1,260 / 1,701 = 74.1%** |
| Root / SOAP coverage | 72.6% / 95.5% |
| Environment | Go 1.27.1, Linux amd64, QEMU Virtual CPU version 2.5+, benchmark GOMAXPROCS 8 |

### Coverage by Risk Surface

| File | Covered statements | Coverage |
| --- | --- | --- |
| `encryption.go` (removed) | 0 / 187 | **0.0%** |
| [auth.go](../auth.go) | 14 / 53 | **26.4%**; Post/response parser 0% |
| [debug_http.go](../debug_http.go) | 22 / 94 | **23.4%**; response reader/header dump 0% |
| [debug_capture.go](../debug_capture.go) | 69 / 90 | 76.7%; permissions/redaction not asserted |
| [http.go](../http.go) | 45 / 52 | 86.5%; does not disprove R7/R8 |
| [command.go](../command.go) | 154 / 176 | 87.5%; multi-response sink failure absent |
| [client.go](../client.go) | 143 / 156 | 91.7% |
| [kerberos_session.go](../kerberos_session.go) | 232 / 264 | 87.9% |
| [kerberos_message.go](../kerberos_message.go) | 99 / 108 | 91.7% |
| [kerberos_gss.go](../kerberos_gss.go) | 42 / 50 | 84.0% |
| [response.go](../response.go) | 83 / 99 | 83.8%; semantic gaps remain |

### CPU and Allocation Microbenchmarks

Three samples per case, `CGO_ENABLED=0`, 500 ms target per sample. Fixtures were outside the timed loop; parser output went to `io.Discard`. Allocated bytes/op are **not peak/live RAM**. These are not production latency, CPU-utilization percentages, or encrypted WinRM throughput measurements.

| Operation | Time range | Allocated bytes/op | Allocs/op |
| --- | --- | --- | --- |
| Parse final Receive, 1 KiB decoded stdout | 207-248 us | 53,864-53,872 | 736 |
| Parse final Receive, 64 KiB decoded stdout | 2.15-2.24 ms | 561,905-561,909 | 742 |
| Format 64 KiB `0xff` debug bytes | 6.15-6.56 ms | 2,195,463-2,195,466 | 131,079 |

### Validation Results

| Check | Result |
| --- | --- |
| `CGO_ENABLED=0 go test -count=1 -coverprofile=<temporary-profile> ./...` | Pass; opt-in integrations not enabled |
| `go vet ./...` | Pass |
| `go test -race -shuffle=on -count=1 -timeout=120s ./...` | Pass; baseline suite before probes |
| Temporary probes | 10 passed by reproducing undesirable behavior; initial fixture-ID assumption corrected before final result |
| Four fuzz smoke runs, `-fuzztime=2s -parallel=2` each | Pass; GSS 2,337 executions; framing 3,439; command parser 10; output parser 8,997 |
| `go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 -show verbose ./...` | **Exit 3: reachable GO-2026-5543**, fixed Azure NTLM version `v0.1.1` |
| Additional advisory | [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932), unmaintained OpenPGP in `golang.org/x/crypto v0.56.0`: module-only; no affected imported-package/call result; no fixed version reported |
| Hosted lint, live Windows, sustained load | Not run; no clean-gate or capacity claim |

Short fuzz campaigns are smoke checks, not exhaustive evidence. Ten command-parser executions provide very little assurance; investigate corpus cost/timeouts and semantic seeds before relying on that target. Advisory results are a dated database snapshot, not a guarantee that all vulnerabilities were found.

## Phased Remediation for LLM Implementation

These phases are separate from historical feature phases in other documents. Phase A is implemented; later phases remain proposed. Track task IDs against finding IDs.

### Execution Contract

1. Start each task at its owning function and adjacent tests. Re-read current files and worktree status; do not assume this revision is unchanged.
2. Add a minimal regression asserting desired behavior; run it and retain the initial failure. The temporary review probes asserted bugs, so invert those assertions for permanent tests.
3. Fix only that ownership boundary, immediately rerun the same regression, then neighboring tests. Do not batch unrelated transport/lifecycle rewrites.
4. Preserve public APIs, `errors.Is`/`errors.As`, authentication guarantees, and user edits. Prefer additive options; request a decision before removing transports, changing streaming semantics, or weakening constraints.
5. Synchronize concurrency tests with channels and bounded contexts, not arbitrary sleeps. Restore global/default state; avoid parallel tests that mutate it.
6. Finish each task with changed files, actual commands/results, remaining risks, and resolved/open finding IDs. Coverage or a happy-path pass alone does not close a finding. Do not commit/tag/push unless separately requested.

### Phase A: Immediate Security Containment

**Dependencies:** none. **Findings:** R2, R4, containment for R5/R6.

**Status:** complete on 2026-09-10. Implementation and final gate evidence are recorded in [Phase A security containment implementation](phase-a-implementation.md).

| Task | Owning slice | Implementation and acceptance |
| --- | --- | --- |
| A1 | [go.mod](../go.mod), [go.sum](../go.sum), `ntlm_test.go` (removed) | Upgrade Azure NTLM to a reviewed compatible fixed version without unrelated churn. Add malformed-challenge regression. NTLM/pure-Go tests pass; scanner no longer reports reachable GO-2026-5543. Record module-only advisories separately. |
| A2 | [debug_capture.go](../debug_capture.go), [debug_http.go](../debug_http.go), adjacent tests | Define default redaction and explicit unsafe mode; create new Unix files at 0600 and decide existing-file policy. Synthetic secrets absent in safe mode; auth/cookie headers redacted; disabled mode creates no files. Verify supported-platform behavior. |
| A3 | `encryption.go` (removed), transport docs | Remove silent error fallback and reject unexpected plaintext for encrypted exchanges. Fake bootstrap failure must cause no plaintext SOAP retry. Document limits until Phase D; disabling/removing the public transport needs an explicit compatibility decision. |

**Gate:** focused security tests, pure-Go suite, pinned vulnerability scan. Base64 is not safe capture. Do not auto-upload raw diagnostic data to CI.

### Phase B: HTTP Ownership and Error Semantics

**Dependencies:** A2 for diagnostics policy; A3 before encrypted behavior expansion. **Findings:** R3, R7, HTTP portion of R8.

**Status:** complete on 2026-09-10. Implementation and final gate evidence are recorded in [Phase B HTTP ownership and error semantics](phase-b-implementation.md).

| Task | Owning slice | Implementation and acceptance |
| --- | --- | --- |
| B1 | [http.go](../http.go), [auth.go](../auth.go), adjacent tests | Remove deferred return mutation; explicit status/MIME checks, bounded reads, exactly-once close. Factor a small helper only for demonstrated duplication. Test 200/401/500, SOAP/non-SOAP, disguised MIME, oversize, partial reads and close errors. |
| B2 | [debug_http.go](../debug_http.go), [kerberos_session.go](../kerberos_session.go) | Debug authoritative bounded bytes and preserve read errors/closer ownership. Debug on/off yields the same size/error result; no full read before enforcement; original body closes once. |
| B3 | [auth.go](../auth.go), [http.go](../http.go), [client.go](../client.go) | Context/deadline and idle-close support for built-ins. Prefer context-aware dialing while retaining legacy custom-dial APIs. Local server sends headers then stalls body: verify deadline and cleanup. Document external Post-only fallback. |

**Gate:** focused HTTP/Auth/Debug/Capture/Body/Kerberos tests, then pure-Go suite. Demonstrate bounded consumption, not merely an eventual error.

### Phase C: Command Cancellation and Lifecycle

**Dependencies:** B for consistent transport cleanup. **Findings:** R1, R9, R11.

**Status:** complete on 2026-09-10. Implementation and final gate evidence are recorded in [Phase C command cancellation and lifecycle](phase-c-implementation.md).

| Task | Owning slice | Implementation and acceptance |
| --- | --- | --- |
| C1 | [client.go](../client.go), [command.go](../command.go), [command_context_test.go](../command_context_test.go) | Close/cancel internal stream ownership on sink failure/cancellation. Test two non-final responses, stdout/stderr failure and unread streams. Return original error; done closes; active-command set returns to baseline; no blocked fetch remains. |
| C2 | [kerberos_session.go](../kerberos_session.go), [command.go](../command.go) | Context-aware serialized admission and shutdown of active I/O. Canceled waiter returns while owner remains blocked; Close/Signal obey overall budget. Assert no GSS overlap, replay, or cross-connection context sharing. |
| C3 | [client.go](../client.go), [shell.go](../shell.go), [command.go](../command.go) | Separate closed-state admission from cleanup. Test Close during remote creation/registration, repeated/concurrent Close, post-close Execute, child-context release, and surfaced Signal/Delete failures. No remote creation left unowned. |

**Gate:** lifecycle regressions with `-count=20 -timeout=120s`, then full shuffled race suite. Use ownership-aware leak checks rather than unstable raw goroutine counts. Request an API decision if a bound requires interrupting arbitrary caller-owned blocking I/O.

### Phase D: Legacy Encrypted NTLM Hardening

**Dependencies:** A1/A3 and B; apply C ownership rules. **Findings:** remainder of R5, R6.

**Status:** superseded on 2026-09-10 by [NTLM removal and AES-only Kerberos](ntlm-removal-2026-09-10.md).

| Task | Owning slice | Implementation and acceptance |
| --- | --- | --- |
| D1 | `encryption.go` (removed), focused encryption tests | Use configured transport, propagate constructor/wrap failures, context/close support, serialized authentication/sequence state. Test custom CA, routing, timeout and concurrent failure through the encrypted path, not fallback. |
| D2 | Legacy multipart/signature parser | Bounded parsing with checked counts/lengths/exact metadata; close on every exit. Malformed-input tables and direct fuzz targets: no panic, oversized allocation, or plaintext acceptance. |

**Gate:** targeted race tests, malformed corpus, each new fuzz target for at least 30 seconds, pure-Go suite. A separately approved live NTLM-encryption success gate is required before claiming server interoperability.

### Phase E: Protocol Semantics and Input Sizing

**Dependencies:** B/C for propagation/cancellation; D is not required to start parser/Kerberos tasks. **Findings:** SOAP portion of R8, R10, R12.

**Status:** complete on 2026-09-10 for the offline implementation and test scope. Evidence and the explicit live-interoperability limitation are recorded in [Phase E protocol semantics and input sizing](phase-e-implementation.md).

| Task | Owning slice | Implementation and acceptance |
| --- | --- | --- |
| E1 | [response.go](../response.go), [command.go](../command.go), [kerberos_session.go](../kerberos_session.go) | Typed faults/required fields. Test permanent fault vs expected operation timeout, empty IDs, missing exit, unsupported action, wrong command identity where available, malicious selectors. No panic, silent exit 0, or permanent-fault loop. |
| E2 | [command.go](../command.go), [request.go](../request.go) | Derive input budget from serialized framing/base64. Boundary/long-metadata cases assert all envelopes fit, bytes arrive once/in-order and EOF once. Cover direct Write, strings.Reader WriteTo, and small-buffer io.Copy. |

**Gate:** request/parser/command tests, semantic fuzz seeds, then approved live large-stdin/output parity. Decide interactive/duplex expectations explicitly; fixing chunk sizes alone does not solve send-all-input-before-output backpressure.

### Phase F: Measured CPU, RAM, and Capacity Work

**Dependencies:** B-E correctness before performance refactoring. **Finding:** R13 and resource-model risks.

**Status:** complete on 2026-09-10 for the local pure-Go measurement and implementation scope. Evidence, budgets, and the explicit live-capacity limitation are recorded in [Phase F measured CPU, RAM, and capacity work](phase-f-implementation.md).

| Task | Owning slice | Implementation and acceptance |
| --- | --- | --- |
| F1 | Benchmarks beside [response_test.go](../response_test.go), [debug_http_test.go](../debug_http_test.go) | Retain recipes below; add actual GSS/framing and capture workloads. Collect CPU/heap profiles and RSS/live heap separately from allocations; record runtime, CPU, concurrency, payload and debug modes. |
| F2 | [debug_http.go](../debug_http.go), [debug_capture.go](../debug_capture.go) | Remove per-byte allocations; cap events/payload, define bounded sink buffering/rotation/error semantics. Saturated diagnostics cannot hold an authenticated session indefinitely. Preserve explicit unsafe capabilities under chosen policy. |
| F3 | [response.go](../response.go), admission only if justified | Benchmark immutable selectors/fewer copies before parser replacement. Sweep 1/8/32 commands and short/long output, debug off/on; record p50/p95 latency, allocations, heap/RSS, goroutines/connections. Define budgets. Add independent-session pooling only when measurements justify affinity/API complexity. |

**Gate:** same-machine before/after benchmarks (at least five samples), unchanged semantic fixtures, clean race suite, agreed budgets. The formatter allocation target was met and is enforced by a regression budget. Local capacity and RSS figures are characterization data, not live Windows/KDC limits.

### Phase G: Maintainability, CI, and Release Evidence

**Dependencies:** CI repairs may start earlier; final gate depends on applicable A-F work. **Finding:** R14 and prevention of test gaps.

1. Pin compatible Go/linter/action/config; remove obsolete entries and run the exact invocation. Include dependency/config/workflow changes in triggers. Use download/verify rather than updating dependencies inside test targets.
2. Add pure-Go, vet, shuffled race and pinned vulnerability gates. Schedule bounded fuzz separately from fast PR tests. Keep live tests opt-in and credential-safe; do not commit raw captures or environment-specific targets.
3. Compile examples, copy defaults before edits, correct minimum Go and transport-specific cancellation/cleanup docs, and describe debug safety, concurrency, memory and duplex limitations accurately.
4. Remove dead placeholders separately from behavioral changes. Keep transport policy in transport ownership; avoid rewriting stable APIs solely for style.
5. Cover each R1-R12 behavior explicitly and prohibit unexplained statement-coverage regression. Hardened encryption/body paths need success plus all documented rejection branches, not merely a global percentage.
6. Record exact tested revision, tool versions, commands, advisory status, live skips, and exceptions before release. Never rewrite historical release evidence to imply it tested new code.

## Reproduction Guide

### Baseline Commands

Run at the repository root, with live integration flags disabled unless explicitly approved.

```sh
CGO_ENABLED=0 go test -count=1 -coverprofile=/tmp/winrm-review.cover ./...
go tool cover -func=/tmp/winrm-review.cover
go vet ./...
go test -race -shuffle=on -count=1 -timeout=120s ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 -show verbose ./...
```

For each of `FuzzKerberosGSSAdapterUnwrap`, `FuzzKerberosMessageFramerOpen`, `FuzzParseCommandResponses`, and `FuzzParseOutputResponses`, use `CGO_ENABLED=0 go test -run '^$' -fuzz '^TARGET$' -fuzztime=2s -parallel=2 .`. Future longer gates are specified separately above.

### Minimal Defect Recipes

| Probe | Setup and desired regression assertion |
| --- | --- |
| HTTP status | Fake RoundTripper: 500, SOAP MIME, `<fault/>`; default/certificate Post must return error. |
| Body ownership | Tracking ReadCloser with invalid MIME closes; debug with 1 MiB input honors configured bounds and closes original. |
| Capture safety | Temporary file and synthetic Authorization/body: restrictive mode, no synthetic secrets in safe output. |
| NTLM parser | `NewEncryption("ntlm")`, malformed body `invalid`: error, not panic. |
| Envelope size | Send `EnvelopeSize - 1000` raw bytes via writer; every serialized request must fit the limit. |
| SOAP semantics | Valid Fault yields typed error; Done without ExitCode must not imply success. |
| Closed client | Close fixture-backed client then CreateShell; no transport call for new work. |
| IDs/selector | Remove actual shell ID from create fixture and use a single quote streamType: errors, not empty-success/panic. |
| Session queue | Hold admission owner, issue already-canceled Post; it returns before owner release. |
| Output failure | At least two non-final stdout responses, immediately failing destination, cancellation after second Receive: prompt completion, original error, no retained command. Repeat for stderr. |

Reuse existing fixture transports and `kerberosPhase4Receive`. For bug-observation probes that intentionally block, release held locks/close internal readers in cleanup to avoid leaking review goroutines. Permanent tests should assert the fixed behavior, with bounded timeout guards.

### Benchmark Recipe

Prepare `kerberosPhase4Receive(bytes.Repeat([]byte("x"), size), nil, true, 0)` with sizes 1,024 and 65,536 before resetting the timer. Loop over `ParseSlurpOutputErrResponse(response, io.Discard, io.Discard)` and check errors. For debug, prepare `bytes.Repeat([]byte{0xff}, 65536)` outside timing and loop over `formatDebugBody(payload)`. Use `ReportAllocs` and `SetBytes`; exclude fixture generation and network/file I/O from timing.

The review used `CGO_ENABLED=0 go test -run '^$' -bench '^BenchmarkReview' -benchmem -benchtime=500ms -count=3 .` with those temporary functions. Phase F should add permanent versions before comparative profiling. No benchmark implementation was left in the review diff.

## Completion Criteria

The assessment is complete with unresolved findings listed. Remediation is complete only when each finding has a linked regression, implemented change or approved compatibility decision, and applicable gate evidence. Passing offline tests, a short fuzz run, or historical release notes do not alone certify interoperability, bounded concurrency, secure diagnostics, or release readiness.
