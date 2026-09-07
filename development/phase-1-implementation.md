# Phase 1: GSS Adapter and WinRM Framing

Status: complete.
Date: 2026-09-07.

## Scope

Phase 1 verifies the pinned fork's Kerberos context-protection primitives and
implements bounded WinRM protected-message framing. It does not connect this
code to `ClientKerberos`; credential lifetime and HTTP context establishment
belong to Phase 2.

Production prototypes:

- `kerberos_gss.go` adapts an established `gssapi.Context`, requires
  confidentiality, validates the RFC 4121 Wrap token header, and separates its
  fixed 16-byte security header from the encrypted payload.
- `kerberos_message.go` writes and parses the WinRM
  `multipart/encrypted` representation without searching opaque ciphertext for
  delimiters. It validates media parameters, metadata, boundaries, token and
  plaintext lengths, and configured limits before returning plaintext.

## Pinned API Evidence

The WinRM module is pinned to `github.com/otuschhoff/gokrb5/v8 v8.5.1`, module
checksum `h1:3XL8DBf4oNoTO+/K2WWThlgHmuOPMAj8dUdv8c8jXVU=`. Its module declares Go
1.26.0. This release contains fork commit `ea7cfe9` and the two context
accessors listed below.

Phase 1 verified these exported signatures:

```go
type gssapi.Context interface {
    Wrap(message []byte, confidential bool) ([]byte, error)
    Unwrap(token []byte) (message []byte, confidential bool, err error)
    GetMIC(message []byte) ([]byte, error)
    VerifyMIC(message, token []byte) error
    NegoExKey() (types.EncryptionKey, bool)
    NegoExVerifyKey() (types.EncryptionKey, bool)
}

func gssapi.NewSecurityContext(
    key types.EncryptionKey,
    initiator bool,
    sendSequence uint64,
    receiveSequence uint64,
    acceptorSubkey bool,
) (*gssapi.SecurityContext, error)

func spnego.SPNEGOClientWithOptions(
    client *client.Client,
    spn string,
    options spnego.KRB5TokenAPREQOptions,
) *spnego.SPNEGO

func (*spnego.SPNEGO).InitSecContext() (gssapi.ContextToken, error)
func (*spnego.SPNEGO).AcceptSecContext(gssapi.ContextToken) (bool, context.Context, gssapi.Status)
func (*spnego.SPNEGO).ContinueSecContext(gssapi.ContextToken) (bool, context.Context, gssapi.Status)
func (*spnego.SPNEGO).SecurityContext() gssapi.Context
func (*spnego.Client).Context() gssapi.Context
```

The synthetic SPNEGO test creates an AES256 service ticket, stores it in an
exported `credentials.CCache`, and completes AP-REQ/AP-REP between exported
initiator and acceptor APIs without a KDC. A missing AP-REP fails because mutual
authentication is required. The fork extracts the acceptor subkey and sequence
number while validating AP-REP; paired `SecurityContext` tests verify the
resulting acceptor-subkey flags and asymmetric send/receive sequence behavior.

## Wire Contract and Bounds

The Kerberos encrypted stream is:

```text
uint32 little-endian security-header length (16)
16-byte RFC 4121 Wrap token header
encrypted Wrap token body
```

This matches pywinrm 0.5.0's `wrap_winrm` contract. The surrounding content type
is `multipart/encrypted` with protocol
`application/HTTP-SPNEGO-session-encrypted`. `OriginalContent.Length` is the
UTF-8 plaintext byte count, not a character count.

The framer receives an explicit plaintext limit; Phase 2 must use the client's
envelope configuration. It permits at most 256 bytes of GSS wrapping overhead
and 4096 bytes of framing metadata. The current AES implementations use less
than that allowance, including the 16-byte outer header, confounder, encrypted
header copy, checksum, and possible padding. Boundaries are limited to 70
printable ASCII bytes and may not end in a space.

The parser supports one Kerberos encrypted message per HTTP body. Kerberos does
not use pywinrm's CredSSP-only `multipart/x-multi-encrypted` chunking path.

## Enctype Inventory

`gssapi.NewSecurityContext` supports only RFC 4121 AES enctypes:

| ID | Enctype | Phase 1 result |
| --- | --- | --- |
| 17 | AES128-CTS-HMAC-SHA1-96 | pass; configured realm permits it |
| 18 | AES256-CTS-HMAC-SHA1-96 | pass; configured realm permits it |
| 19 | AES128-CTS-HMAC-SHA256-128 | pass; dependency inventory |
| 20 | AES256-CTS-HMAC-SHA384-192 | pass; dependency inventory |
| 23 | RC4-HMAC | rejected |

The active `/etc/krb5.conf` declares only enctypes 17 and 18 for ticket and
service-ticket acquisition. No weaker enctype was enabled for this work.

## Verification

The focused tests cover:

- KDC-free mutual SPNEGO completion and required AP-REP rejection.
- AES128/AES256 and SHA1/SHA2 contexts, acceptor-subkey consistency,
  asymmetric sequences, bidirectional confidential Wrap/Unwrap, and advancement.
- Tamper, replay, wrong token ID, wrong filler, unsealed token, and truncated
  header rejection.
- Zero, small, large, Unicode, and delimiter-bearing payloads.
- A byte-exact synthetic WinRM fixture whose ciphertext contains the boundary.
- Malformed media types, protocols, boundaries, metadata, declared lengths,
  security-header lengths, terminal markers, truncation, and size limits.
- Parser fuzz seeds, CGO-disabled package tests, and a race-enabled focused run.

Commands used:

```sh
CGO_ENABLED=0 go test -count=1 -run '^TestKerberos(GSSAdapter|SPNEGO|MessageFramer)' -v .
CGO_ENABLED=0 go test -count=1 github.com/otuschhoff/gokrb5/v8/gssapi github.com/otuschhoff/gokrb5/v8/spnego
CGO_ENABLED=1 go test -race -count=1 -run '^TestKerberos(GSSAdapter|SPNEGO|MessageFramer)' .
```

## Phase 2 Dependency Resolution

Fork commit `ea7cfe9` exports locally established per-message contexts through
`SPNEGO.SecurityContext()` and publishes successfully verified mutual contexts
through the classic HTTP client's `Context()` method. It retains independent
send and receive sequence numbers plus acceptor-subkey state across mutual,
non-mutual, mechanism-switch mechListMIC, and DCE exchanges. A new HTTP
negotiation clears any previously published context before acquiring fresh
credentials, and failed or incomplete mutual authentication does not publish a
replacement.

The fork tests perform confidential bidirectional Wrap/Unwrap after each
establishment form, assert directional sequence pairing and subkey agreement,
verify context availability at each protocol leg, and cover HTTP publication
and stale-context clearing. The complete fork suite and vet pass with CGO
disabled; focused race tests pass with CGO enabled. The complete WinRM suite
also passes against the local fork.

The API blocker is resolved by the pinned `v8.5.1` release. No local
absolute-path replacement is present in `go.mod`.
