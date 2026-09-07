# Phase 2: Persistent Credentials and Bootstrap

Status: complete.
Date: 2026-09-07.

## Scope

Phase 2 replaces per-request Kerberos setup with one serialized session owned by
`ClientKerberos`. It initializes one gokrb5 client, retains its ticket cache,
performs bounded mutual SPNEGO bootstrap with an empty POST, and binds the
resulting GSS context to the observed HTTP connection. It does not send
protected SOAP; that remains the Phase 3 vertical slice.

## Implementation

- Credential precedence remains ccache, keytab, then password. Configuration
  and credentials are loaded once when the transport is initialized.
- `auto`, `always`, and `never` are explicit message-encryption modes. `auto`
  requires protection over HTTP and permits plaintext SOAP over HTTPS.
- The endpoint is authoritative. Conflicting legacy hostname, port, or protocol
  fields fail configuration, and the default SPN is `HTTP/<endpoint host>`.
- Bootstrap uses the released gokrb5 classic SPNEGO HTTP client with mutual,
  integrity, and confidentiality requested. HTTP 200 is accepted only when the
  client publishes a verified non-nil GSS context.
- Bootstrap is limited to five HTTP exchanges and 4096 response bytes.
  Redirects fail closed. `httptrace.GotConn` records every cloned request and
  restarts bootstrap from a fresh SPNEGO state if its connection changes.
- An established context is reused only on its bound connection. A SOAP request
  that observes connection replacement invalidates the context and returns
  without replay. A later caller may start a fresh bootstrap.
- Session operations are serialized. Context cancellation reaches bootstrap and
  SOAP HTTP requests. `Client.Close` exposes idempotent credential destruction
  and idle-connection cleanup through transports that support it.
- `KerberosError` provides stage, HTTP status, and wrapped-cause classification.

The exported `gssapi.Context` API has no negotiated-flag introspection. Mutual
authentication is established by the classic client validating the final
AP-REP before publishing `Context()`. Integrity and confidentiality are
capabilities of the returned RFC 4121 context and are exercised by the Phase 1
adapter tests. The requested flags are passed in `KRB5TokenAPREQOptions`.

## Compatibility

The public `Transporter` interface is unchanged. Context-aware delivery is an
optional internal interface, so existing transports continue through `Post`.
The existing context-taking shell and command APIs now propagate their context
through create, execute, receive, and input requests. Cleanup requests retain
their background context so cancellation does not prevent best-effort remote
shell cleanup.

## Verification

Synthetic tests cover credential precedence, endpoint and mode validation,
intermediate 401 responses, 200 with and without a context, invalid AP-REP,
non-200 completion, exchange and body limits, redirects, connection replacement,
in-flight cancellation, structured errors, repeated session use, no uncertain
SOAP replay, safe later re-establishment, idempotent close, and the Phase 3
protected-SOAP guard. An `httptest.Server` test proves that `GotConn` survives
cloned requests and observes one real keep-alive connection.

Validation commands:

```sh
CGO_ENABLED=0 go test -count=1 ./...
CGO_ENABLED=0 go vet ./...
go test -race -count=1 -run '^(TestValidateKerberosConfiguration|TestKerberosCredentialPrecedence|TestKerberosSession.*)$' .
git diff --check
```

All commands pass. No live-shell success is claimed for Phase 2. The next action
is Phase 3: wrap outgoing SOAP, parse and unwrap protected responses, then pass
the mandatory native HTTP hostname gate.