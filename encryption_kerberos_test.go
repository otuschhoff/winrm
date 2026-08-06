package winrm

import (
	"strings"
	"testing"
)

func TestNewEncryptionSupportsKerberos(t *testing.T) {
	e, err := NewEncryption("kerberos")
	if err != nil {
		t.Fatalf("NewEncryption(kerberos) unexpected error: %v", err)
	}
	if e.protocol != "kerberos" {
		t.Fatalf("protocol = %q, want kerberos", e.protocol)
	}
	if got := string(e.protocolString); got != "application/HTTP-SPNEGO-session-encrypted" {
		t.Fatalf("protocolString = %q", got)
	}
	if e.kerberos == nil {
		t.Fatal("expected kerberos client holder to be initialized")
	}
}

func TestBuildMessageRoutesKerberos(t *testing.T) {
	e := &Encryption{protocol: "kerberos"}
	_, err := e.buildMessage([]byte("payload"), "host")
	if err == nil {
		t.Fatal("expected error when kerberos transport is not initialized")
	}
	if !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptMessageRoutesKerberos(t *testing.T) {
	e := &Encryption{protocol: "kerberos"}
	_, err := e.decryptMessage([]byte("payload"), "host")
	if err == nil {
		t.Fatal("expected error for unimplemented kerberos unwrap")
	}
	if !strings.Contains(err.Error(), "phase 4") {
		t.Fatalf("unexpected error: %v", err)
	}
}
