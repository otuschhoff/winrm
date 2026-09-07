# Pure-Go WinRM: Design and Implementation Plan

Status: Phase 5 complete; release evidence remains Phase 6 work.
Date: 2026-09-07.

Phase 0 is complete; see the [Phase 0 implementation note](phase-0-implementation.md).
Phase 1 is complete; see the [Phase 1 implementation note](phase-1-implementation.md).
Phase 2 is complete; see the [Phase 2 implementation note](phase-2-implementation.md).
Phase 3 is complete; see the [Phase 3 implementation note](phase-3-implementation.md).
Phase 4 is complete; see the [Phase 4 implementation note](phase-4-implementation.md).
Phase 5 is complete; see the [Phase 5 implementation note](phase-5-implementation.md).

## 1. Goal and Release Contract

Implement a pure-Go WinRM client with the behavior of the working pywinrm
Kerberos baseline. Preserve the current shell, command, PowerShell, streaming,
and transport APIs where possible. Python is a test oracle, never a production
dependency or fallback.

The first release milestone is Kerberos WinRM parity, not a claim of complete
pywinrm authentication coverage. Completion requires a successful native-Go
connection and command execution on the actual target. Read the target FQDN
from the repository-root `target` file, trimming its line ending. The file must
contain one DNS name with at least a host label and a domain. Derive all target
values from that FQDN; do not duplicate environment-specific names in code or
documentation.

| Property | Required value |
| --- | --- |
| Target FQDN | Trimmed contents of repository-root `target` |
| Target shortname | First label of the target FQDN |
| Endpoint | `http://<target FQDN>:5985/wsman` |
| Realm | Domain portion of the target FQDN, converted to uppercase |
| Service principal | `HTTP/<target FQDN>` |
| Identity | Principal read from repository-root `user` |
| Secret | Password read from repository-root `pw` |
| Kerberos configuration | `/etc/krb5.conf`, or explicit test override |
| Expected command | `hostname` |
| Expected result | Exit code 0, stdout equal to the target shortname, empty stderr |
| Protection | Kerberos authentication and message encryption over HTTP |
| Native runtime | `CGO_ENABLED=0`; no Python, kinit, libkrb5, or libgssapi |

Neither a successful TCP connection, a TGT, a service ticket, an HTTP bootstrap,
nor matching Go/Python failures satisfies this gate. Do not enable
`AllowUnencrypted`, switch to HTTPS, substitute another identity, or weaken
server policy to make the gate pass. A missing credential file or unavailable
host is a blocked gate, not a pass.

## 2. Evidence and Current State

Repository anchors:

- [kerberos.go](../kerberos.go) and [kerberos_session.go](../kerberos_session.go):
  retain credentials and an established connection-bound GSS context, bootstrap
  with an empty POST, and protect SOAP using the established context.
- [encryption.go](../encryption.go): NTLM-specific encryption implementation;
  Kerberos support is explicitly unimplemented. Do not copy its plaintext
  fallback behavior into the new Kerberos implementation.
- [http.go](../http.go): shared HTTP/TLS/proxy/dial configuration.
- [client.go](../client.go): shell and command entry points and transport contract.
- [kerberos_integration_test.go](../kerberos_integration_test.go): native,
  Python-only, and comparison test entry points.
- [compare_pywinrm.py](compare_pywinrm.py): working Python baseline using a
  temporary credential cache, empty auth tuple, and default message encryption.

Observed on 2026-09-07:

- Stock pywinrm 0.5.0 succeeds using the updated user/password and returns the
  expected hostname. The opsctl capture fork is not required for connectivity.
- Python previously returned HTTP 500 with `message_encryption="never"`.
  Aligning the session with opsctl's default `auto` encryption and cache-based
  identity selection made the same host work. These settings changed together;
  do not claim an isolated experiment proved the effect of each individually.
- The opsctl capture shows an empty HTTP bootstrap receiving 200, then
  `multipart/encrypted` SOAP exchanges receiving 200 on port 5985.
- Native Go verifies and retains server context establishment, encrypts SOAP on
  HTTP, and reuses that context for sequential and concurrent command lifecycles.
- The earlier machine-account keytab received 401 and has since been removed.
  Keytab authorization on this host is not a release gate.
- The success comparison gates require both clients to succeed. Equal failures
  are accepted only by the separately named diagnostic test.

An HTTP 500 alone does not prove a server configuration defect. The successful
encrypted Python baseline is evidence to investigate client protocol behavior.

## 3. Parity Scope

| Capability | Kerberos milestone | Broader parity |
| --- | --- | --- |
| Password AS exchange and HTTP service ticket | Required | Maintain |
| Keytab and FILE credential cache | Preserve; synthetic tests | Authorized live fixture when available |
| SPNEGO, mutual authentication, session sealing | Required | Maintain |
| HTTP 5985 with encrypted SOAP | Mandatory live gate | Maintain |
| HTTPS with certificate validation | Local TLS tests required | Live TLS fixture when available |
| `auto`, `always`, `never` message encryption | Required; secure defaults | Maintain |
| Shell lifecycle, cmd, PowerShell, streams, exit codes | Required | Extend oracle cases |
| Cancellation, deadlines, concurrent calls | Required | Maintain |
| Existing Basic, NTLM, certificate transports | No regression | Separate parity assessment |
| CredSSP, delegation, channel binding, other mechanisms | Not implied by this milestone | Separate specifications and interoperability gates |

Keep broader parity work out of the critical path. If any unsupported feature
is requested explicitly, return a precise error instead of silently selecting
another authentication mechanism. Do not advertise complete pywinrm parity
until the broader matrix has its own passing evidence.

## 4. Dependency and Compatibility Policy

- Prefer `net/http`, `net`, `net/url`, `context`, `sync`, `io`, `bytes`,
  `mime`, `mime/multipart`, `encoding/binary`, `encoding/base64`, and
  `crypto/tls` for orchestration, transport, framing, and TLS.
- Keep existing SOAP generation/parsing initially. Use `encoding/xml` for new
  narrowly scoped parsing where appropriate; do not rewrite the SOAP stack.
- Keep `github.com/otuschhoff/gokrb5/v8` for Kerberos, SPNEGO, and GSS protection.
  The standard library does not implement these protocols. Do not invent
  cryptographic algorithms or substitute a generic cipher for GSS Wrap tokens.
- Pin the dependency. Verify the actual exported API and tests for context
  establishment, acceptor subkeys, Wrap/Unwrap, sequence numbers, and destruction
  before designing the adapter. Proposed interfaces below are not claims about
  APIs currently provided by the fork.
- If the fork lacks a required operation, document the exact gap and add a
  separately reviewed pure-Go dependency change. Do not edit the module cache
  or introduce a permanent absolute-path `replace` directive.
- The current dependency graph declares Go 1.26. Preserve that baseline unless
  a separate compatibility decision is approved.
- Production builds must compile with CGO disabled. Python and system Kerberos
  tools are permitted only in the independent comparison harness.

## 5. Proposed Architecture

### Configuration and Public Surface

Retain `ClientKerberos`, `NewClientKerberos`, and `Transporter`. Add an additive
message-encryption option to Kerberos settings/client configuration. Empty means
`auto`; supported values are `auto`, `always`, and `never`.

- `auto`: require sealed messages on HTTP; rely on validated TLS on HTTPS.
- `always`: require sealed messages on both HTTP and HTTPS.
- `never`: explicit compatibility/diagnostic opt-out only; never an error fallback.

Preserve existing credential precedence: explicit ccache, then explicit keytab,
then password. Do not silently switch credentials after an authentication error.
Production code must not discover repository credential files implicitly.

Make the initialized Endpoint authoritative for URL, TLS, proxy, and dialing.
Validate conflicting legacy host/port/proto fields rather than obtaining a ticket
for one target and posting to another. Default the SPN to `HTTP/<target-host>`;
retain explicit SPN override support. Never derive the service SPN from a proxy.
Do not force lowercase user identities or uppercase arbitrary principal names.

### Session Ownership

Each Kerberos transport owns a long-lived credential client and HTTP client,
plus managed security contexts for authenticated connections. Retain tickets
across requests; distinguish reusable tickets from per-connection GSS contexts.
Suggested private responsibilities, implemented only when needed:

1. Credential initialization, ticket renewal, and destruction.
2. SPNEGO context initiation/continuation and mutual-authentication verification.
3. GSS sealing/unsealing through a small adapter over the fork.
4. WinRM multipart framing and bounded parsing.
5. HTTP connection/context lifecycle and request serialization.

Do not turn the existing NTLM `Encryption` type into a cross-authentication
framework until tests show a genuinely shared framing abstraction is useful.
Candidate files are `kerberos_session.go` and `kerberos_message.go`; keep new
types private and avoid duplicate public transports.

### Establishment State Machine

`uninitialized -> credentials-ready -> negotiating -> established -> invalid/closed`

1. Load configuration and selected credentials once; acquire or reuse a valid TGT.
2. Obtain the service ticket for the target HTTP SPN.
3. Start SPNEGO with integrity, confidentiality, and mutual authentication as
   required by the selected mode. Verify negotiated properties, not just flags
   requested by the initiator.
4. For encrypted HTTP, bootstrap with an empty POST to the same `/wsman` URL.
   Preserve exact HTTP content-length semantics using Go's request API.
5. Consume `WWW-Authenticate: Negotiate` tokens, including tokens on a successful
   HTTP response. Validate AP-REP, subkeys, sequence state, and context completion.
   Handle bounded negotiation continuations; cap at five exchanges and honor a
   deadline. Status 200 alone is insufficient evidence of context establishment.
6. Only after completion, send sealed SOAP. Verify and decrypt responses before
   handing plaintext to the existing SOAP parser.

Do not use the current one-shot `SetSPNEGOHeader` call as a substitute for
retaining and completing the security context. Never expose decrypted data until
integrity and sequence checks pass.

### Connection, Concurrency, and Cancellation

WinRM HTTP authentication/context state must not be assumed portable across
arbitrary pooled TCP connections. First implement a serialized HTTP/1.1 exchange
per session, with explicit connection/context association and reconnect detection.
`MaxConnsPerHost=1` is a constraint, not proof of connection identity. Decide how
the transport observes replacement connections in a tested prototype before
sending encrypted requests through the pool.

On connection loss, discard the old context and authenticate the new connection.
Do not automatically replay CreateShell, Execute, Send, or any request whose
delivery is uncertain. Account for net/http's own retry rules; do not mark SOAP
commands idempotent to enable retries. Reject cross-origin redirects and never
forward credentials or tokens to a new origin implicitly.

Serialize sequence allocation, sealing, send, receive, and unsealing until the
context implementation explicitly supports concurrency. Protect state without
holding a lock across calls that re-enter it. Cancellation must be able to wake
blocked operations and perform bounded cleanup; test polling and input together.

The existing `Transporter.Post` has no context argument. Add an optional
context-aware internal transport contract and thread the caller's context through
shell/command operations while retaining compatibility with existing transports.
Legacy calls use a bounded default. Document whether KDC calls in the fork are
cancelable; use supported deadlines or fix the dependency rather than leaking
goroutines to simulate cancellation. Add idempotent explicit shutdown/cleanup.

### WinRM Protected Message Framing

Use `application/HTTP-SPNEGO-session-encrypted` with the WinRM multipart format.
Carry the original SOAP content type and plaintext byte length in OriginalContent
metadata. Encode the security-header length as a four-byte little-endian value,
then the GSS header and encrypted payload according to the negotiated mechanism.

Derive the split between GSS header and ciphertext from the verified dependency
API and WinRM fixtures. Do not assume an RFC 4121 token can be split at a fixed
offset across enctypes, padding, EC/RRC values, or subkey choices.

Use `mime.ParseMediaType` and standard multipart support where compatible. The
WinRM two-part wire representation can differ from ordinary form-data MIME;
prove stdlib parsing/writing against real sanitized fixtures. If a narrow custom
framer is necessary, document the incompatible grammar and test it explicitly.
Never parse ciphertext with generic string splitting or newline normalization.

Before allocation or decryption, validate media type, boundary, protocol, lengths,
part count, and configured size limits. Bound encrypted and decrypted bodies,
including error bodies. Choose limits from envelope configuration plus verified
wrapping overhead and document them. Validate OriginalContent length after
unwrapping. Reject truncation, overflow, trailing unexpected parts, malformed
headers, signature failure, replay, and unexpected plaintext success responses
when encryption is required. Permit bounded plaintext error responses as errors,
not as a successful unprotected fallback.

### Errors and Diagnostics

Introduce structured errors with stage (`config`, `credentials`, `ticket`,
`negotiate`, `wrap`, `http`, `unwrap`, `soap`), HTTP status when present, and
wrapped cause. Preserve bounded SOAP fault details after decryption. Replace
integration-test regex classification with `errors.As` when these errors exist.

Log stage, endpoint, protection mode, content type, sizes, status, and sanitized
correlation IDs. Never log passwords, Authorization/WWW-Authenticate tokens,
keytabs, session keys, credential caches, or raw authenticated packet captures.
Captures and upstream test fixtures must contain synthetic credentials only.

## 6. Implementation Phases for an LLM Agent

Execute sequentially. Every phase starts from its named owning code and a
falsifiable hypothesis, makes the smallest testable change, then runs the focused
check before more edits. Keep production fixes and test-harness changes separate
when practical. Do not commit, tag, push, alter server policy, or change external
repositories unless explicitly authorized.

### Phase 0: Freeze the Oracle and Acceptance Tests

Inputs: existing integration tests and Python runner.

Tasks:

- Keep Python automatic encryption enabled. Record interpreter/package version,
  endpoint, protection mode, and sanitized outcome without recording credentials.
- Add a success-only parity gate. Equal failures must fail that gate; optionally
  retain equal-failure comparison under an explicitly diagnostic name.
- Require expected hostname, exit code, and stderr in both standalone live tests.
- Align `WINRM_KRB_CONFIG` with Python's `KRB5_CONFIG` so both use the same config.
- Read password files preserving spaces; remove only the agreed terminal line
  ending. Test LF/CRLF, empty files, missing files, and realm-qualified usernames.
- Explicitly select password mode for release gates; never depend on keytab presence.

Exit: Python live baseline passes; native success-only gate is demonstrably red;
default tests skip all network access and do not require credential files.

### Phase 1: Verify the GSS Adapter and Framing (complete)

Inputs: fork SPNEGO/context APIs and documented WinRM/GSS wire formats.

Tasks:

- Record actual exported API signatures and package versions in an implementation
  note. Build a small adapter prototype using synthetic initiator/acceptor tests.
- Verify mutual-authentication completion, acceptor subkeys, confidentiality,
  bidirectional Wrap/Unwrap, sequence advancement, tamper and replay rejection.
- Implement the bounded WinRM framer/parser with synthetic golden fixtures.
- Test zero/small/large payloads, Unicode byte lengths, malformed boundaries,
  oversized lengths, truncated headers, and ciphertext containing delimiter bytes.
- Cover AES128 and AES256 used by the configured realm. Inventory other dependency
  enctypes explicitly; do not enable weaker algorithms to satisfy an interop test.

Exit: focused adapter/framing tests pass with CGO disabled; mutation/replay tests
fail closed. Any missing dependency primitive is documented as a blocker.

### Phase 2: Persistent Credentials and Bootstrap

Inputs: `ClientKerberos.Transport/Post`, shared HTTP setup, adapter from Phase 1.

Tasks:

- Initialize credentials once; preserve precedence and cache successful tickets.
- Implement the bounded bootstrap/continuation state machine and context lifecycle.
- Add explicit encryption configuration and validated endpoint/SPN construction.
- Prove connection association, reconnect handling, no cross-origin redirect, and
  no uncertain command replay with a local mock server/dialer.
- Add lifecycle cleanup and deadline behavior; reject SOAP before establishment.

Exit: simulated bootstrap tests cover 200 with/without a final token, intermediate
401, invalid AP-REP, context failure, redirects, connection replacement, and limits.
No live-shell success claim is made for bootstrap alone.

### Phase 3: Encrypted SOAP Vertical Slice

Inputs: established session and framing code.

Tasks:

- Seal outgoing SOAP, send multipart, verify/unseal responses, and reuse the
  existing XML response parsing and shell/command machinery.
- Preserve HTTP/SOAP faults without plaintext fallback or credential retries.
- Exercise CreateShell, Execute `hostname`, Receive, command cleanup, DeleteShell.
- Add a fake encrypted transport/server test for the complete lifecycle.

Exit: mandatory native live hostname gate passes on HTTP 5985 using `user`/`pw`.
If Python passes but Go fails, stop feature expansion and repair this slice using
sanitized stage diagnostics. Do not change the expected result to accept failures.

### Phase 4: Command and Session Parity

Inputs: working encrypted vertical slice.

Tasks:

- Run multiple commands on one client and verify ticket reuse/context correctness.
- Compare cmd and PowerShell, stdout/stderr separation, nonzero exit status,
  Unicode output, stdin, and output larger than a single Receive envelope.
- Test cancellation during negotiation, input, and Receive; bounded cleanup;
  concurrent callers; ticket expiry; server close; and client shutdown.
- Propagate context through the actual request path and test race safety.
- Use read-only or ephemeral commands; do not modify host policy or persistent data.

Exit: normalized Go/Python command results match; success cases really succeed;
local race and timeout tests pass without leaked goroutines or shells.

### Phase 5: Hardening and Compatibility

Tasks:

- Exercise `auto/always/never`, HTTPS certificate verification, proxy/dial behavior,
  credential source errors, and existing Basic/NTLM/certificate tests.
- Add focused fuzz targets for multipart/token framing and structured error parsing.
- Validate encrypted sizes and response deadlines under malformed-input tests.
- Verify the production dependency graph has no CgoFiles or external process
  execution on the native authentication path. Keep Python/kinit only in tests.
- Document public defaults, cleanup requirements, bounded limits, migration from
  plaintext Kerberos, and unsupported features. Do not promise blanket parity.

Exit: offline suites, CGO-disabled build/test, race tests, bounded fuzz run, and
security-negative tests pass. Reproduce known flaky tests against the unchanged
baseline; report them separately rather than weakening assertions.

### Phase 6: Release Evidence

Tasks:

- Run all commands below with explicit password mode and no cached Go test results.
- Repeat native success in three fresh test processes, plus same-client repeated
  commands from Phase 4, to catch accidental cache/session dependence.
- Record revision, Go/fork/Python versions, timestamps, endpoint/SPN, test names,
  outcomes, and outstanding limitations. Exclude credentials and auth tokens.

Exit: every required gate is green. If the environment prevents a live check,
mark the release blocked and state what must be rerun. Never report completion
solely from mocks, matching errors, or a prior Python-only success.

## 7. Verification Commands

Run from the repository root. Configure the comparison virtual environment with
[requirements-integration.txt](../requirements-integration.txt) if needed.

```sh
CGO_ENABLED=0 go build ./...
CGO_ENABLED=0 go test -count=1 ./...
go test -race -count=1 ./...
```

The race detector normally requires CGO for instrumentation; its use does not
relax the CGO-disabled production requirement.

Python oracle:

```sh
WINRM_HOST="$(tr -d '\r\n' < target)"
WINRM_KRB_REALM="$(printf '%s\n' "${WINRM_HOST#*.}" | tr '[:lower:]' '[:upper:]')"
export WINRM_HOST WINRM_KRB_REALM

WINRM_KRB_CONFIG=/etc/krb5.conf KRB5_CONFIG=/etc/krb5.conf \
WINRM_PYWINRM_INTEGRATION=1 WINRM_KRB_AUTH=password \
WINRM_PYTHON=.venv/bin/python \
go test -count=1 -timeout=120s -run '^TestPywinrmIntegration$' -v .
```

Mandatory native exit gate (must not invoke Python or kinit):

```sh
WINRM_HOST="$(tr -d '\r\n' < target)"
WINRM_KRB_REALM="$(printf '%s\n' "${WINRM_HOST#*.}" | tr '[:lower:]' '[:upper:]')"
export WINRM_HOST WINRM_KRB_REALM

CGO_ENABLED=0 \
WINRM_KRB_CONFIG=/etc/krb5.conf \
WINRM_KERBEROS_INTEGRATION=1 WINRM_KRB_AUTH=password \
go test -count=1 -timeout=120s -run '^TestKerberosIntegration$' -v .
```

Success-only comparison, after Phase 0 changes its acceptance contract:

```sh
WINRM_HOST="$(tr -d '\r\n' < target)"
WINRM_KRB_REALM="$(printf '%s\n' "${WINRM_HOST#*.}" | tr '[:lower:]' '[:upper:]')"
export WINRM_HOST WINRM_KRB_REALM

WINRM_KRB_CONFIG=/etc/krb5.conf KRB5_CONFIG=/etc/krb5.conf \
WINRM_KERBEROS_COMPARISON=1 WINRM_KRB_AUTH=password \
WINRM_PYTHON=.venv/bin/python \
go test -count=1 -timeout=120s -run '^TestKerberosComparisonWithPywinrm$' -v .
```

## 8. Phase Handoff Template

Each agent leaves a short implementation note containing:

- Phase number and status: complete, in progress, or blocked.
- Verified hypothesis and actual code/dependency APIs used.
- Changed files and behavior; no unrelated cleanup.
- Exact focused validation commands and results, including expected red tests.
- Live evidence separately from mock evidence; never include secrets.
- Known failures, compatibility/security concerns, and the next smallest action.

Do not advance past a failed phase exit. Do not rewrite this specification to
remove a failing gate without explicit approval. A future agent should be able
to resume from the note without rediscovering the whole repository.
