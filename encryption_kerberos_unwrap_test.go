package winrm

import (
	"bytes"
	"encoding/binary"
	"testing"

	krbcrypto "github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/types"
)

func phase4BuildAcceptorFrame(t *testing.T, key types.EncryptionKey, seq uint64, payload []byte) []byte {
	t.Helper()

	etype, err := krbcrypto.GetEtype(key.KeyType)
	if err != nil {
		t.Fatalf("unable to get etype: %v", err)
	}

	_, sealedPayload, err := etype.EncryptMessage(key.KeyValue, payload, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		t.Fatalf("unable to seal payload: %v", err)
	}

	wrapToken := &gssapi.WrapToken{
		Flags:     0x03, // acceptor + sealed
		EC:        uint16(etype.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: seq,
		Payload:   payload,
	}
	if err := wrapToken.SetCheckSum(key, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil {
		t.Fatalf("unable to sign wrap token: %v", err)
	}
	signature, err := wrapToken.Marshal()
	if err != nil {
		t.Fatalf("unable to marshal wrap token: %v", err)
	}

	frame := make([]byte, 4)
	binary.LittleEndian.PutUint32(frame, uint32(len(signature)))
	frame = append(frame, signature...)
	frame = append(frame, sealedPayload...)
	return frame
}

func TestDecryptKerberosMessageUnsealsAndVerifies(t *testing.T) {
	key := phase3TestSessionKey(t)
	enc := &Encryption{
		protocol: "kerberos",
		kerberos: &ClientKerberos{
			context: &kerberosContext{serviceSessionKey: key},
		},
	}

	payload := []byte("phase-4 inbound payload")
	frame := phase4BuildAcceptorFrame(t, key, 0, payload)

	decrypted, err := enc.decryptKerberosMessage(frame, "host.example")
	if err != nil {
		t.Fatalf("decryptKerberosMessage returned error: %v", err)
	}
	if !bytes.Equal(decrypted, payload) {
		t.Fatalf("decrypted payload mismatch: got %q want %q", string(decrypted), string(payload))
	}
	if got := enc.kerberos.context.acceptorSeq; got != 1 {
		t.Fatalf("acceptor sequence expected to increment to 1, got %d", got)
	}
}

func TestDecryptKerberosMessageRejectsInvalidSignature(t *testing.T) {
	key := phase3TestSessionKey(t)
	enc := &Encryption{
		protocol: "kerberos",
		kerberos: &ClientKerberos{
			context: &kerberosContext{serviceSessionKey: key},
		},
	}

	payload := []byte("phase-4 inbound payload")
	frame := phase4BuildAcceptorFrame(t, key, 0, payload)
	signatureLen := int(binary.LittleEndian.Uint32(frame[:4]))
	if signatureLen < 2 {
		t.Fatalf("signature too short for tamper test: %d", signatureLen)
	}
	frame[4+signatureLen-1] ^= 0xFF

	if _, err := enc.decryptKerberosMessage(frame, "host.example"); err == nil {
		t.Fatal("expected signature verification failure")
	}
}

func TestDecryptKerberosMessageRejectsSequenceMismatch(t *testing.T) {
	key := phase3TestSessionKey(t)
	enc := &Encryption{
		protocol: "kerberos",
		kerberos: &ClientKerberos{
			context: &kerberosContext{
				serviceSessionKey: key,
				acceptorSeq:       2,
			},
		},
	}

	payload := []byte("phase-4 inbound payload")
	frame := phase4BuildAcceptorFrame(t, key, 0, payload)

	if _, err := enc.decryptKerberosMessage(frame, "host.example"); err == nil {
		t.Fatal("expected sequence mismatch error")
	}
}

func TestDecryptKerberosMessageRejectsTruncatedFrame(t *testing.T) {
	key := phase3TestSessionKey(t)
	enc := &Encryption{
		protocol: "kerberos",
		kerberos: &ClientKerberos{
			context: &kerberosContext{serviceSessionKey: key},
		},
	}

	if _, err := enc.decryptKerberosMessage([]byte{0x01, 0x00, 0x00}, "host.example"); err == nil {
		t.Fatal("expected truncated frame error")
	}
}
