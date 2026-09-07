# Phase 5 Implementation: Hardening and Compatibility

Date: 2026-09-07.
Status: Complete.

## Implemented behavior

- Exercises `auto`, `always`, and `never` through public Kerberos transport initialization on HTTP and HTTPS. Empty mode remains equivalent to `auto`.
- Adds public Kerberos constructors for custom dialers and proxy selectors, matching the existing transport patterns.
- Verifies HTTPS with a supplied CA, rejects an unknown or malformed CA, and preserves explicit `Insecure` behavior.
- Preserves credential precedence as ccache, keytab, then password, and reports missing or malformed source files without fallback.
- Rejects disguised plaintext response media types with strict MIME parsing and invalidates the connection-bound session after response read or protocol failures.
- Returns malformed single-stream XML errors before XPath evaluation.
- Adds focused fuzz targets for RFC 4121 token handling and structured shell, command, stream, and exit-code responses. The existing multipart fuzz target remains the framing gate.
- Verifies response-body deadlines and session invalidation with a blocked local response body.

## Compatibility and security evidence

Deterministic tests cover:

- HTTP/HTTPS message-encryption mode selection.
- Kerberos custom dial and proxy propagation.
- Trusted CA, unknown CA, explicit insecure TLS, and malformed CA behavior.
- Missing and malformed configuration, ccache, and keytab sources.
- Encrypted plaintext, metadata, wrap-overhead, and response-size bounds.
- Strict plaintext and encrypted response content types, tampering, truncation, replay, replacement connections, and oversized bodies.
- Existing Basic, NTLM, certificate, shell, command, and SOAP behavior through the full repository suite.

The `CGO_ENABLED=0 go list` production graph reports no Cgo or SWIG files. Production Go files do not import `os/exec` or invoke external processes; Python execution exists only in the opt-in integration test harness.

The native encrypted hostname gate, Go/pywinrm hostname comparison, and six-scenario persistent-session parity gate all passed in fresh processes on 2026-09-07 after the hardening changes.

Bounded fuzz runs completed for:

```sh
CGO_ENABLED=0 go test . -run '^$' -fuzz '^FuzzKerberosMessageFramerOpen$' -fuzztime=5s
CGO_ENABLED=0 go test . -run '^$' -fuzz '^FuzzKerberosGSSAdapterUnwrap$' -fuzztime=5s
CGO_ENABLED=0 go test . -run '^$' -fuzz '^FuzzParseCommandResponses$' -fuzztime=5s
CGO_ENABLED=0 go test . -run '^$' -fuzz '^FuzzParseOutputResponses$' -fuzztime=5s
```

## Public boundaries

The README documents encryption defaults, endpoint and SPN authority, credential precedence, cleanup requirements, bounded framing/bootstrap behavior, custom routing, and migration from plaintext Kerberos. Native support is intentionally limited to password, keytab, or ccache credentials with mutual SPNEGO and AES RFC 4121 protection. Credential delegation, channel binding, RC4 GSS protection, and automatic authentication or plaintext fallback are unsupported.

Phase 6 remains responsible for repeated fresh-process live release evidence and the final versioned evidence record.
