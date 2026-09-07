# Phase 3: Encrypted SOAP

Status: complete.
Date: 2026-09-07.

## Scope

Phase 3 connects the established Kerberos security context to the complete
WinRM shell lifecycle. SOAP requests and responses are confidential and
integrity protected over HTTP, remain bound to the authenticated connection,
and are never replayed as plaintext or on a replacement connection.

## Implementation

- Every outbound SOAP envelope is wrapped by the established RFC 4121 context
  and encoded as `multipart/encrypted` with protocol
  `application/HTTP-SPNEGO-session-encrypted`.
- WinRM uses GSS IOV layout rather than a contiguous Wrap token. The adapter
  rotates the RFC 4121 body, moves the confounder and cryptographic trailer into
  the security-header buffer, sets RRC, and leaves encrypted application data in
  a separate buffer. AES-SHA1, AES-SHA256, and AES-SHA384 produce 60, 64, and 72
  byte security headers respectively.
- Incoming frames accept bounded variable-length security headers, reconstruct
  the RFC 4121 token, and rely on the GSS context to authenticate flags,
  sequence, RRC, ciphertext, and the encrypted header copy before returning XML.
- SPNEGO requests mutual authentication, sequence protection, integrity, and
  confidentiality. Sequence protection is mandatory for Windows to use its
  AP-REP sequence for protected responses.
- Protected SOAP is sent only on the connection that carried an authenticated
  bootstrap exchange. Connection replacement invalidates the context and fails
  without replay.
- Plaintext responses, malformed multipart data, oversized bodies, invalid
  security headers, tampering, replay, and unauthenticated replacement
  connections all invalidate the session.
- Authenticated encrypted SOAP faults are decrypted and returned to the existing
  SOAP fault parsers even when the HTTP status is non-successful.

## Dependency Interoperability

Windows may encrypt AP-REP with the service-ticket session key even when the
initiator supplied an authenticator subkey. gokrb5 v8.5.2 verifies with the
preferred authenticator subkey first, then securely falls back to the retained
ticket key. If the AP-REP contains an acceptor subkey, that remains the RFC 4121
context key; otherwise the key that authenticated AP-REP becomes the context
key.

The fix is published as `github.com/otuschhoff/gokrb5/v8 v8.5.2`. The WinRM
module uses that release directly and has no local `replace` directive.

## Verification

Synthetic tests cover:

- IOV header dimensions and RRC values for all four supported AES enctypes.
- Empty, Unicode, delimiter-bearing, and large protected messages.
- Bidirectional confidentiality, sequence advancement, tamper and replay
  rejection, subkey flags, malformed metadata, framing bounds, and fuzz seeds.
- Authenticated encrypted success and SOAP-fault responses.
- Plaintext fallback rejection, response tampering, oversized responses, and
  connection replacement without replay.
- A complete encrypted CreateShell, Command, Receive, Signal, and DeleteShell
  lifecycle against an in-process server.

The native acceptance gate uses `CGO_ENABLED=0`, HTTP port 5985, and credentials
from ignored local files. It runs `hostname`, requires exit code 0, compares
stdout with the short host derived from `target`, and requires empty stderr. The
gate passes with gokrb5 v8.5.2. The pywinrm parity gate remains available as an
independent oracle.

Validation commands:

```sh
CGO_ENABLED=0 go test -count=1 ./...
CGO_ENABLED=0 go vet ./...
go test -race -count=1 -run '^TestKerberos' .
WINRM_KERBEROS_INTEGRATION=1 CGO_ENABLED=0 \
  go test -count=1 -run '^TestKerberosIntegration$' -v .
git diff --check
```
