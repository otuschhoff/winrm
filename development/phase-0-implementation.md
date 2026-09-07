# Phase 0 Implementation Note

Status: complete.
Date: 2026-09-07.
Specification: [Pure-Go WinRM design](design-pure-go-winrm.md).

## Verified Contract

- Release gates select password mode explicitly and never inspect keytab presence.
- The principal comes from repository-root `user`; the password comes from `pw`.
- Password parsing removes exactly one terminal LF or CRLF and preserves spaces.
- Go and Python use the same Kerberos config selected by `WINRM_KRB_CONFIG`.
- Both standalone gates require exit code 0, expected hostname stdout, and empty stderr.
- The success-parity gate requires both clients to succeed. Equal failures cannot pass.
- Equal-outcome comparison remains available only as
  `TestKerberosComparisonDiagnostic` under its own opt-in flag.
- Python explicitly uses pywinrm message encryption mode `auto` over HTTP 5985.
- Logs record endpoint, protection mode, runtime/client versions, status, and
  sanitized outcome. They do not record principal, password, tickets, or tokens.
- All network tests skip before credential access unless separately enabled.

## Changed Files

- [Go integration harness](../kerberos_integration_test.go)
- [Python oracle](compare_pywinrm.py)
- [Python oracle unit tests](test_compare_pywinrm.py)
- [Integration instructions](../README.md)

No production authentication behavior was changed in this phase.

## Offline Evidence

```sh
go test -count=1 -run '^(TestLoadPasswordCredentials|TestLoadPasswordCredentialsMissingFiles|TestMergeEnvironmentReplacesValues|TestComparisonResultMetadata|TestValidateHostnameResult)$' -v .
.venv/bin/python -m unittest -v development/test_compare_pywinrm.py
```

Result: all Go cases and all nine Python cases pass. Coverage includes LF, CRLF,
no newline, exactly-one-ending removal, preserved password spaces, empty and
missing files, qualified/mismatched/malformed principals, duplicate environment
replacement, metadata, hostname, stderr, and exit-code validation.

The four network tests were also run without opt-in flags and all skipped before
credential access.

## Live Evidence

Python oracle:

```sh
WINRM_HOST=server.example.com \
WINRM_KRB_CONFIG=/etc/krb5.conf KRB5_CONFIG=/etc/krb5.conf \
WINRM_PYWINRM_INTEGRATION=1 WINRM_KRB_AUTH=password \
WINRM_PYTHON=.venv/bin/python \
go test -count=1 -timeout=120s -run '^TestPywinrmIntegration$' -v .
```

Result: pass. Python 3.13.5 and pywinrm 0.5.0 connected to the configured HTTP
5985 endpoint with automatic Kerberos
message encryption and returned the expected hostname.

Native expected-red gate:

```sh
CGO_ENABLED=0 WINRM_HOST=server.example.com \
WINRM_KRB_CONFIG=/etc/krb5.conf \
WINRM_KERBEROS_INTEGRATION=1 WINRM_KRB_AUTH=password \
go test -count=1 -timeout=120s -run '^TestKerberosIntegration$' -v .
```

Result: expected failure, HTTP 500. Go 1.27.1 with gokrb5 v8.5.0-rc.5 still
sends plaintext SOAP after one-shot Kerberos SPNEGO authentication.

Success-only comparison:

```sh
WINRM_HOST=server.example.com \
WINRM_KRB_CONFIG=/etc/krb5.conf KRB5_CONFIG=/etc/krb5.conf \
WINRM_KERBEROS_COMPARISON=1 WINRM_KRB_AUTH=password \
WINRM_PYTHON=.venv/bin/python \
go test -count=1 -timeout=120s -run '^TestKerberosComparisonWithPywinrm$' -v .
```

Result: expected failure. Python succeeds; Go returns HTTP 500. The gate reports
the mismatch and cannot pass on equal failures.

## Known Issues and Next Action

The unrelated timing-sensitive `WinRMSuite.TestCloseCommandStopsFetch` failed in
one uncached full-suite run. It has passed in prior runs and was not modified.

Phase 1 starts by verifying the fork's actual GSS context and Wrap/Unwrap APIs
using synthetic initiator/acceptor tests. Do not begin HTTP integration before
the adapter proves confidentiality, mutual authentication, sequence handling,
tamper rejection, and replay rejection with CGO disabled.
