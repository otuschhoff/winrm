package winrm

import (
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"strings"
	"testing"

	krbcrypto "github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

func phase5SubKey(t *testing.T) types.EncryptionKey {
	t.Helper()
	base := phase3TestSessionKey(t)
	return types.EncryptionKey{KeyType: base.KeyType, KeyValue: append([]byte(nil), base.KeyValue...)}
}

func TestApplyKerberosAPRepUpdatesSubkeyAndSequence(t *testing.T) {
	ctx := &kerberosContext{}
	sub := phase5SubKey(t)
	encPart := messages.EncAPRepPart{
		Subkey:         sub,
		SequenceNumber: 7,
	}

	enc := &Encryption{}
	enc.applyKerberosAPRep(ctx, encPart)

	if ctx.acceptorSubKey == nil {
		t.Fatal("expected acceptor subkey to be set")
	}
	if ctx.acceptorSubKey.KeyType != sub.KeyType {
		t.Fatalf("subkey type mismatch: got %d want %d", ctx.acceptorSubKey.KeyType, sub.KeyType)
	}
	if ctx.acceptorSeq != 7 {
		t.Fatalf("acceptor sequence mismatch: got %d want 7", ctx.acceptorSeq)
	}
}

func TestBuildKerberosMessageUsesAcceptorSubkeyWhenPresent(t *testing.T) {
	serviceKey := phase3TestSessionKey(t)
	subKey := phase5SubKey(t)
	subKey.KeyValue[0] ^= 0xAA

	enc := &Encryption{
		protocol: "kerberos",
		kerberos: &ClientKerberos{context: &kerberosContext{
			serviceSessionKey: serviceKey,
			acceptorSubKey:    &subKey,
		}},
	}

	payload := []byte("phase-5 outbound payload")
	frame, err := enc.buildKerberosMessage(payload, "host.example")
	if err != nil {
		t.Fatalf("buildKerberosMessage error: %v", err)
	}

	sigLen := int(binary.LittleEndian.Uint32(frame[:4]))
	sig := frame[4 : 4+sigLen]
	sealed := frame[4+sigLen:]

	var token gssapi.WrapToken
	if err := token.Unmarshal(sig, false); err != nil {
		t.Fatalf("token unmarshal failed: %v", err)
	}
	if token.Flags&0x04 == 0 {
		t.Fatal("expected acceptor-subkey flag in outbound token")
	}
	if ok, err := token.Verify(subKey, keyusage.GSSAPI_INITIATOR_SEAL); err != nil || !ok {
		t.Fatalf("token verify with subkey failed: ok=%t err=%v", ok, err)
	}

	decrypted, err := krbcrypto.DecryptMessage(sealed, subKey, keyusage.GSSAPI_INITIATOR_SEAL)
	if err != nil {
		t.Fatalf("decrypt with subkey failed: %v", err)
	}
	if string(decrypted) != string(payload) {
		t.Fatalf("payload mismatch: got %q want %q", string(decrypted), string(payload))
	}
}

func TestDecryptKerberosMessageUsesAcceptorSubkeyWhenPresent(t *testing.T) {
	serviceKey := phase3TestSessionKey(t)
	subKey := phase5SubKey(t)
	subKey.KeyValue[0] ^= 0x55
	enc := &Encryption{
		protocol: "kerberos",
		kerberos: &ClientKerberos{context: &kerberosContext{
			serviceSessionKey: serviceKey,
			acceptorSubKey:    &subKey,
		}},
	}

	payload := []byte("phase-5 inbound payload")
	frame := phase4BuildAcceptorFrame(t, subKey, 0, payload)

	decrypted, err := enc.decryptKerberosMessage(frame, "host.example")
	if err != nil {
		t.Fatalf("decryptKerberosMessage error: %v", err)
	}
	if string(decrypted) != string(payload) {
		t.Fatalf("payload mismatch: got %q want %q", string(decrypted), string(payload))
	}
}

func TestProcessKerberosResponseAuthRejectsInvalidNegotiateToken(t *testing.T) {
	enc := &Encryption{protocol: "kerberos", kerberos: &ClientKerberos{}}
	resp := &http.Response{
		Header: http.Header{
			"Www-Authenticate": []string{"Negotiate *"},
		},
	}

	err := enc.processKerberosResponseAuth(resp)
	if err == nil {
		t.Fatal("expected invalid token parse error")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProcessKerberosResponseAuthIgnoresNonNegotiateHeader(t *testing.T) {
	enc := &Encryption{protocol: "kerberos", kerberos: &ClientKerberos{}}
	resp := &http.Response{Header: http.Header{"Www-Authenticate": []string{"Basic realm=foo"}}}
	if err := enc.processKerberosResponseAuth(resp); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resp = &http.Response{Header: http.Header{"Www-Authenticate": []string{"Negotiate " + base64.StdEncoding.EncodeToString([]byte(""))}}}
	if err := enc.processKerberosResponseAuth(resp); err != nil {
		t.Fatalf("unexpected error for empty negotiate token: %v", err)
	}
}
