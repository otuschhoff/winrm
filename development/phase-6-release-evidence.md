# Phase 6 Release Evidence

Date: 2026-09-07.
Status: Complete.
Validation window: 2026-09-07 21:24:40 CEST through 2026-09-07 21:30:21 CEST.

## Tested revision and environment

| Property | Value |
| --- | --- |
| Source revision | `999827efe3aa96d981e80aeaa01c79a8581f6128` |
| Worktree before validation | Clean |
| OS/architecture | Linux/amd64 |
| Go | `go1.27.1` |
| Native build mode | `CGO_ENABLED=0` |
| gokrb5 | `github.com/otuschhoff/gokrb5/v8 v8.5.2` |
| Python | `3.13.5` |
| pywinrm | `0.5.0` |
| Endpoint | `http://win-host.example.com:5985/wsman` |
| SPN | `HTTP/win-host.example.com` |
| Authentication gate | Explicit password mode |
| Protection | Kerberos message encryption over HTTP |

No usernames, passwords, tickets, tokens, or encrypted payloads are included in this record.

## Offline gates

All commands ran uncached from the repository root:

| Command | Outcome |
| --- | --- |
| `CGO_ENABLED=0 go build ./...` | PASS |
| `CGO_ENABLED=0 go test -count=1 ./...` | PASS: `winrm` and `soap` |
| `go test -race -count=1 ./...` | PASS: `winrm` and `soap` |

Phase 5 also completed bounded five-second fuzz runs for `FuzzKerberosMessageFramerOpen`, `FuzzKerberosGSSAdapterUnwrap`, `FuzzParseCommandResponses`, and `FuzzParseOutputResponses` on this source revision with no failures.

## Live gates

Each invocation used `-count=1`, an explicit timeout, and explicit password mode. Each native repetition was a distinct `go test` process.

| Timestamp | Test | Outcome |
| --- | --- | --- |
| 2026-09-07 21:30:21 CEST | `TestPywinrmIntegration` | PASS: pywinrm encrypted hostname baseline, exit 0 |
| 2026-09-07 21:25:22 CEST | `TestKerberosIntegration` run 1 | PASS: native encrypted hostname, exit 0 |
| 2026-09-07 21:25:29 CEST | `TestKerberosIntegration` run 2 | PASS: native encrypted hostname, exit 0 |
| 2026-09-07 21:25:36 CEST | `TestKerberosIntegration` run 3 | PASS: native encrypted hostname, exit 0 |
| 2026-09-07 21:25:44 CEST | `TestKerberosComparisonWithPywinrm` | PASS: both clients succeeded with matching normalized hostname results |
| 2026-09-07 21:25:53 CEST | `TestKerberosPhase4ComparisonWithPywinrm` | PASS: one client/session per implementation across repeated cmd, PowerShell Unicode, stdout/stderr, exit 23, stdin EOF, and 200 KB output cases |

The native gates used no Python, `kinit`, libkrb5, or libgssapi. Python was invoked only by the explicitly named baseline and comparison tests.

## Outstanding limitations

- Live release evidence covers one HTTP 5985 domain target and password credentials. HTTPS behavior, custom CAs, proxy/dial routing, ccache, and keytab failures are covered locally; they are not claimed as live-environment interoperability evidence.
- Wall-clock ticket expiry was not forced on the domain. Deterministic tests verify that a failed/expired GSS context invalidates without SOAP replay and that a later operation can bootstrap afresh.
- Credential delegation, channel binding, RC4 GSS message protection, and automatic authentication or plaintext fallback are unsupported.
- `MessageEncryption=never` is an explicit compatibility/diagnostic mode and is not part of the secure release gate.
- Kerberos security contexts remain bound to one persistent HTTP connection and requests on that context are serialized.
- Native Kerberos and the default transport honor request contexts. A third-party legacy `Transporter` that implements only `Post` cannot be forcibly interrupted by `Client.Close`; context-aware custom transports should implement `PostContext` and release resources from `Close`.

All required Phase 6 gates succeeded. No blocked reruns remain.
