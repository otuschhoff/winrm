package winrm

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestNewEncryptionKerberosDefaultsToEncryptionRequiredMode(t *testing.T) {
	e, err := NewEncryption("kerberos")
	if err != nil {
		t.Fatalf("NewEncryption(kerberos) returned error: %v", err)
	}

	if e.kerberosMode != KerberosModeMessageEncryptionRequired {
		t.Fatalf("kerberos mode = %q, want %q", e.kerberosMode, KerberosModeMessageEncryptionRequired)
	}

	if !e.failurePolicy.RejectUnencryptedResponse {
		t.Fatal("expected RejectUnencryptedResponse to be true in encryption-required mode")
	}
}

func TestSetKerberosRuntimeModeRejectsInvalidValue(t *testing.T) {
	e, err := NewEncryption("kerberos")
	if err != nil {
		t.Fatalf("NewEncryption(kerberos) returned error: %v", err)
	}

	err = e.SetKerberosRuntimeMode(KerberosRuntimeMode("unknown-mode"))
	if err == nil {
		t.Fatal("expected unsupported mode error")
	}
}

func TestParseEncryptedResponseRejectsUnencryptedInRequiredMode(t *testing.T) {
	e, err := NewEncryption("kerberos")
	if err != nil {
		t.Fatalf("NewEncryption(kerberos) returned error: %v", err)
	}

	req, reqErr := http.NewRequest("POST", "http://example.local/wsman", nil)
	if reqErr != nil {
		t.Fatalf("unexpected request error: %v", reqErr)
	}

	resp := &http.Response{
		Header:  http.Header{"Content-Type": []string{"application/soap+xml"}},
		Body:    io.NopCloser(strings.NewReader("plain-response")),
		Request: req,
	}

	_, err = e.ParseEncryptedResponse(resp)
	if err == nil {
		t.Fatal("expected failure when unencrypted response is received in required mode")
	}

	if !strings.Contains(err.Error(), "required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseEncryptedResponseAllowsUnencryptedInAuthOnlyMode(t *testing.T) {
	e, err := NewEncryption("kerberos")
	if err != nil {
		t.Fatalf("NewEncryption(kerberos) returned error: %v", err)
	}

	if err := e.SetKerberosRuntimeMode(KerberosModeAuthOnly); err != nil {
		t.Fatalf("SetKerberosRuntimeMode returned error: %v", err)
	}

	req, reqErr := http.NewRequest("POST", "http://example.local/wsman", nil)
	if reqErr != nil {
		t.Fatalf("unexpected request error: %v", reqErr)
	}

	resp := &http.Response{
		Header:  http.Header{"Content-Type": []string{"application/soap+xml"}},
		Body:    io.NopCloser(strings.NewReader("plain-response")),
		Request: req,
	}

	body, err := e.ParseEncryptedResponse(resp)
	if err != nil {
		t.Fatalf("unexpected parse error in auth-only mode: %v", err)
	}

	if string(body) != "plain-response" {
		t.Fatalf("body = %q, want %q", string(body), "plain-response")
	}
}
