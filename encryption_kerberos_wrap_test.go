package winrm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	krbcrypto "github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/types"
)

func phase3TestSessionKey(t *testing.T) types.EncryptionKey {
	t.Helper()
	keyValue, err := hex.DecodeString("14f9bde6b50ec508201a97f74c4e5bd3")
	if err != nil {
		t.Fatalf("unable to decode key hex: %v", err)
	}
	return types.EncryptionKey{KeyType: 17, KeyValue: keyValue}
}

func TestBuildKerberosMessageSignsAndSealsPayload(t *testing.T) {
	sessionKey := phase3TestSessionKey(t)
	enc := &Encryption{
		protocol: "kerberos",
		kerberos: &ClientKerberos{
			context: &kerberosContext{
				serviceSessionKey: sessionKey,
			},
		},
	}

	payload := []byte("phase-3 payload")
	sealed, err := enc.buildKerberosMessage(payload, "host.example")
	if err != nil {
		t.Fatalf("buildKerberosMessage returned error: %v", err)
	}
	if len(sealed) < 5 {
		t.Fatalf("sealed payload too short: %d", len(sealed))
	}

	signatureLen := int(binary.LittleEndian.Uint32(sealed[:4]))
	if signatureLen <= 0 {
		t.Fatalf("signature length must be > 0, got %d", signatureLen)
	}
	if len(sealed) <= 4+signatureLen {
		t.Fatalf("sealed payload missing ciphertext: total=%d signature=%d", len(sealed), signatureLen)
	}

	signature := sealed[4 : 4+signatureLen]
	ciphertext := sealed[4+signatureLen:]

	var token gssapi.WrapToken
	if err := token.Unmarshal(signature, false); err != nil {
		t.Fatalf("unable to parse wrap token: %v", err)
	}
	if ok, err := token.Verify(sessionKey, keyusage.GSSAPI_INITIATOR_SEAL); err != nil || !ok {
		t.Fatalf("wrap token verify failed, ok=%t err=%v", ok, err)
	}
	if !bytes.Equal(token.Payload, payload) {
		t.Fatalf("token payload mismatch: got %q want %q", string(token.Payload), string(payload))
	}

	decrypted, err := krbcrypto.DecryptMessage(ciphertext, sessionKey, keyusage.GSSAPI_INITIATOR_SEAL)
	if err != nil {
		t.Fatalf("unable to decrypt sealed message: %v", err)
	}
	if !bytes.Equal(decrypted, payload) {
		t.Fatalf("decrypted payload mismatch: got %q want %q", string(decrypted), string(payload))
	}

	if got := enc.kerberos.context.initiatorSeq; got != 1 {
		t.Fatalf("initiator sequence expected to increment to 1, got %d", got)
	}
}

func TestBuildKerberosMessageRequiresKerberosTransport(t *testing.T) {
	enc := &Encryption{protocol: "kerberos"}
	_, err := enc.buildKerberosMessage([]byte("payload"), "host")
	if err == nil {
		t.Fatal("expected error for missing kerberos transport")
	}
	if !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildKerberosMessageRequiresSessionKey(t *testing.T) {
	enc := &Encryption{
		protocol: "kerberos",
		kerberos: &ClientKerberos{context: &kerberosContext{}},
	}

	_, err := enc.buildKerberosMessage([]byte("payload"), "host")
	if err == nil {
		t.Fatal("expected error for missing session key")
	}
	if !strings.Contains(err.Error(), "session key") {
		t.Fatalf("unexpected error: %v", err)
	}
}
