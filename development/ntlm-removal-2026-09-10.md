# NTLM Removal and AES-Only Kerberos

Date: 2026-09-10

Status: implemented. This is an intentional breaking change that removes all exported NTLM transports and message-encryption APIs.

## Removed

- Removed `ClientNTLM`, its custom dial/proxy constructors, and the Azure NTLM negotiator.
- Removed the legacy `Encryption` decorator, encrypted NTLM parser, tests, and fuzz targets.
- Removed the `WinRMUseNTLM` setting and all current README guidance for NTLM.
- Removed the Azure and bodgit NTLM modules and their now-unused transitive dependencies with `go mod tidy`.

Historical security and implementation records retain plain-text references to the removed feature so prior findings remain understandable.

## AES-Only Kerberos

- Override loaded krb5 configuration to request and permit only AES128/AES256 enctypes 17, 18, 19, and 20.
- Disable weak crypto regardless of the caller's krb5.conf setting.
- Reject ccache files containing non-AES session keys before creating a client.
- Filter non-AES keytab entries and reject keytabs with no AES keys.
- Retain the RFC 4121 GSS constructor check that rejects enctype 23 service-session keys.

This prevents the application from negotiating or using RC4. It does not remove dormant RC4 source from the Go standard library or the retained gokrb5 module; `crypto/tls` and gokrb5's aggregate crypto registry still reference `crypto/rc4`. Removing those packages from the compiled dependency graph would require maintaining forks of the Go toolchain and gokrb5 and is outside this repository-level change.
