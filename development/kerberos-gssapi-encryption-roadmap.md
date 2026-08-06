# Kerberos/GSSAPI WinRM Encryption Roadmap

## Goal
Implement Kerberos-based WinRM message protection (sign/seal, integrity verification, decrypt/unseal) for environments where WinRM requires GSSAPI encryption (for example over HTTP with message-level protection).

## Non-goals
- Rewriting existing NTLM encryption path.
- Implementing CredSSP.
- Replacing TLS transport security.

## Baseline Findings
- Kerberos transport currently performs authentication only (SPNEGO Authorization header), not message-level sign/seal.
- Encryption code currently supports NTLM only.
- Kerberos branches in encryption/wrap/unwrap are placeholders.
- No Kerberos encryption test coverage exists.

## Constraints and Compatibility
- Keep existing public APIs stable unless unavoidable.
- Preserve current NTLM behavior and tests.
- Prefer fail-closed behavior when Kerberos encryption is negotiated/required and protection cannot be verified.
- Target current dependency version: github.com/jcmturner/gokrb5/v8 v8.4.4.

## Phase 0: Design and Guardrails
### Objectives
- Finalize architecture and failure policy before code changes.

### Tasks
1. Add this roadmap file and keep it up to date during implementation.
2. Define explicit runtime modes:
   - kerberos-auth-only (existing behavior)
   - kerberos-message-encryption-required (new behavior)
3. Define fail policy for encryption-required mode:
   - Reject unencrypted responses.
   - Reject invalid/missing signatures.
   - Reject token parse/decrypt failures.
4. Define logging policy (debug-safe, no key material leakage).

### Deliverables
- Documented decisions in this roadmap.
- Issue checklist for each phase.

### Acceptance Criteria
- Team can answer: when do we fallback vs fail.
- Team can answer: what events are logged and at what level.

### Decisions (Implemented)
1. Runtime modes are explicit and named:
   - kerberos-auth-only
   - kerberos-message-encryption-required
2. Default runtime mode for Encryption("kerberos"):
   - kerberos-message-encryption-required
3. Fail policy in encryption-required mode:
   - Reject unencrypted responses: enabled
   - Reject invalid signatures: enabled by policy defaults (enforced during unwrap phases)
   - Reject token decrypt failures: enabled by policy defaults
4. Logging policy:
   - Do not log key material, token bytes, decrypted payloads, usernames/passwords, or full Authorization headers
   - Error messages should be actionable but scrubbed of sensitive data
   - Add verbose debug logging only behind explicit opt-in in later phases

---

## Phase 1: Kerberos Security Context Foundation
### Objectives
- Introduce a reusable Kerberos context object that persists per client session.

### Target Files
- kerberos.go
- (optional new file) kerberos_context.go

### Tasks
1. Add internal Kerberos context state:
   - gokrb5 client reference
   - SPN
   - service ticket
   - service session key
   - optional acceptor subkey
   - initiator/acceptor sequence counters
   - mutex
2. Initialize context once and reuse across requests.
3. Support both credential sources:
   - username/password + krb5 config
   - ccache + krb5 config
4. Add helper for SPN resolution (default HTTP/fqdn if SPN omitted).
5. Ensure context creation path is deterministic and testable.

### Deliverables
- New context struct + constructor/helpers.
- Refactored ClientKerberos setup that does not recreate expensive state per request.

### Acceptance Criteria
- Repeated requests reuse same Kerberos runtime context.
- Existing kerberos-auth-only flow still works.

---

## Phase 2: Wire Kerberos into Encryption Protocol Selector
### Objectives
- Enable Kerberos in Encryption transport and route to Kerberos-specific wrap/unwrap.

### Target Files
- encryption.go
- kerberos.go
- parameters.go (only if new knobs are needed)

### Tasks
1. Enable NewEncryption("kerberos").
2. Attach Kerberos context to Encryption object.
3. Implement protocol dispatch paths:
   - buildKerberosMessage
   - decryptKerberosMessage
4. Keep existing multipart framing and content-type handling.
5. Ensure kerberos mode does not silently fallback to plaintext when encryption is required.

### Deliverables
- Kerberos protocol recognized by encryption transport.
- End-to-end call flow routes through Kerberos wrap/unwrap functions.

### Acceptance Criteria
- Kerberos mode can construct encrypted request payload format.
- Kerberos mode attempts decrypt/verify on encrypted responses.

---

## Phase 3: Outbound Sign/Seal Implementation
### Objectives
- Implement client-to-server message sealing and signing according to GSSAPI/Kerberos key usage semantics.

### Target Files
- encryption.go
- kerberos.go
- (optional new file) kerberos_gssapi_wrap.go

### Tasks
1. Build outbound payload structure:
   - 4-byte little-endian signature length
   - signature token bytes
   - sealed/encrypted message bytes
2. Use Kerberos service session key for initiator direction.
3. Use correct key usage constants for outbound seal/sign.
4. Advance sender sequence safely.
5. Return explicit errors for all cryptographic and framing failures.
6. Remove/replace ignored error paths in encryption code touched by this phase.

### Deliverables
- Implemented buildKerberosMessage.
- Deterministic, tested serializer for payload layout.

### Acceptance Criteria
- Outbound Kerberos-protected payload is parseable by local test decoder.
- Tampering tests fail verification as expected.

---

## Phase 4: Inbound Verify/Unseal Implementation
### Objectives
- Implement server-to-client signature verification and decrypt/unseal logic.

### Target Files
- encryption.go
- kerberos.go
- (optional new file) kerberos_gssapi_unwrap.go

### Tasks
1. Parse payload safely with full bounds checks.
2. Verify signature token using acceptor direction key usage.
3. Decrypt/unseal message bytes.
4. Validate original content length metadata against decrypted payload length.
5. Advance receiver sequence safely.
6. Fail closed on any mismatch or parse error.

### Deliverables
- Implemented decryptKerberosMessage.
- Hardened parser logic for malformed/truncated data.

### Acceptance Criteria
- Valid encrypted server responses are decoded to SOAP XML.
- Invalid signature, wrong length, malformed framing all return errors.

---

## Phase 5: AP_REP and Subkey Handling
### Objectives
- Improve interoperability and correctness by processing AP_REP when provided and honoring acceptor subkey semantics.

### Target Files
- kerberos.go
- (optional new file) kerberos_aprep.go

### Tasks
1. Capture and parse WWW-Authenticate Negotiate response tokens.
2. Parse SPNEGO response token and extract KRB AP_REP when present.
3. Decrypt AP_REP encrypted part using AP_REP_ENCPART key usage.
4. If acceptor subkey exists, switch inbound/outbound keying as required by context rules.
5. Document current library limitation areas and local handling strategy.

### Deliverables
- AP_REP parsing/decrypt helper(s).
- Key selection logic updated to prefer negotiated subkey when applicable.

### Acceptance Criteria
- Test vectors with AP_REP subkey pass wrap/unwrap.
- Missing AP_REP path still works when server behavior allows it.

---

## Phase 6: Robustness and Security Hardening
### Objectives
- Eliminate parser panic risks and silent cryptographic failures in touched code.

### Target Files
- encryption.go
- kerberos.go

### Tasks
1. Replace unchecked indexing in multipart parsing with guarded parsing.
2. Eliminate ignored read/build errors in encryption flow.
3. Correct any chunking boundary errors if chunked paths are used.
4. Add defensive checks for nil context/session key and invalid protocol states.
5. Add clear, actionable error messages without exposing secrets.

### Deliverables
- Hardened parsing and error handling in Kerberos-enabled flow.

### Acceptance Criteria
- Fuzz-style malformed payload unit tests do not panic.
- Error paths are deterministic and asserted by tests.

---

## Phase 7: Test Suite Expansion
### Objectives
- Add focused automated coverage for Kerberos encryption behavior.

### Target Files
- new tests, for example:
  - kerberos_encryption_test.go
  - kerberos_context_test.go
  - kerberos_aprep_test.go

### Tasks
1. Unit tests for:
   - context initialization and reuse
   - SPN resolution
   - outbound payload framing
   - inbound payload parsing
   - tamper detection
   - length mismatch detection
   - sequence progression behavior
2. Integration-like tests with mocked HTTP responses and headers:
   - encrypted response path
   - plaintext-when-required rejection
3. Ensure all existing tests continue passing.

### Deliverables
- New Kerberos-focused tests with deterministic fixtures.

### Acceptance Criteria
- go test ./... passes.
- Kerberos encryption code paths have meaningful coverage.

---

## Phase 8: Documentation and Migration Notes
### Objectives
- Document behavior and how to enable/use Kerberos message encryption.

### Target Files
- README.md
- potentially development/ notes

### Tasks
1. Update Kerberos section to clarify:
   - auth-only mode vs encryption-required mode
   - required parameters/config
   - known limitations
2. Add troubleshooting section for common failures:
   - SPN mismatch
   - ccache parse/login issues
   - invalid/missing encrypted response framing
3. Add migration guidance for users relying on old fallback behavior.

### Deliverables
- Updated user docs and examples.

### Acceptance Criteria
- README instructions align with actual behavior.
- Contradictory statements about Kerberos support are resolved.

---

## Execution Checklist (Living)
- [x] Phase 0 complete
- [x] Phase 1 complete
- [x] Phase 2 complete
- [x] Phase 3 complete
- [x] Phase 4 complete
- [ ] Phase 5 complete
- [ ] Phase 6 complete
- [ ] Phase 7 complete
- [ ] Phase 8 complete

## Suggested Implementation Order (Granular)
1. Phase 1 context foundation.
2. Phase 2 protocol routing.
3. Phase 3 outbound seal.
4. Phase 4 inbound unseal.
5. Phase 6 hardening pass on touched code.
6. Phase 7 tests for all above.
7. Phase 5 AP_REP/subkey support.
8. Phase 8 docs finalization.

## Risks
- gokrb5 client-side SPNEGO/AP_REP verification limitations require careful local handling.
- Interop differences across Windows versions and WinRM policy settings.
- Sequence/key-direction mistakes can cause hard-to-debug failures.

## Mitigations
- Build deterministic unit fixtures for token framing and crypto checks.
- Add strict assertions around key usage and sequence direction.
- Keep feature flag or explicit mode until compatibility confidence is high.
