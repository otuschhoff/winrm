package winrm

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type errReadCloser struct{}

func (e errReadCloser) Read(_ []byte) (int, error) {
	return 0, errors.New("boom")
}

func (e errReadCloser) Close() error {
	return nil
}

func TestDecryptResponseRejectsNilBody(t *testing.T) {
	enc := &Encryption{protocol: "kerberos"}
	_, err := enc.decryptResponse(&http.Response{}, "host")
	if err == nil {
		t.Fatal("expected nil body error")
	}
}

func TestDecryptResponseRejectsMalformedMimeStructure(t *testing.T) {
	enc := &Encryption{protocol: "kerberos"}
	resp := &http.Response{
		Body: io.NopCloser(strings.NewReader(mimeBoundary + "\r\nheader-only")),
	}

	_, err := enc.decryptResponse(resp, "host")
	if err == nil {
		t.Fatal("expected malformed MIME structure error")
	}
	if !strings.Contains(err.Error(), "MIME") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptResponseRejectsMissingOriginalLength(t *testing.T) {
	enc := &Encryption{protocol: "kerberos"}
	body := strings.Join([]string{
		mimeBoundary,
		"\r\n",
		"\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n",
		mimeBoundary,
		"\r\n",
		"\tContent-Type: application/octet-stream\r\n",
		"payload",
	}, "")
	resp := &http.Response{Body: io.NopCloser(strings.NewReader(body))}

	_, err := enc.decryptResponse(resp, "host")
	if err == nil {
		t.Fatal("expected missing length error")
	}
	if !strings.Contains(err.Error(), "length") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptResponseReadFailure(t *testing.T) {
	enc := &Encryption{protocol: "kerberos"}
	resp := &http.Response{Body: errReadCloser{}}

	_, err := enc.decryptResponse(resp, "host")
	if err == nil {
		t.Fatal("expected read error")
	}
	if !strings.Contains(err.Error(), "read") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecryptNtlmMessageRejectsTruncatedFrame(t *testing.T) {
	enc := &Encryption{protocol: "ntlm"}
	if _, err := enc.decryptNtlmMessage([]byte{0x00, 0x00, 0x00}, "host"); err == nil {
		t.Fatal("expected truncated NTLM frame error")
	}
}

func TestDecryptNtlmMessageRejectsMissingCiphertext(t *testing.T) {
	enc := &Encryption{protocol: "ntlm"}
	frame := []byte{0x01, 0x00, 0x00, 0x00, 0xFF}
	if _, err := enc.decryptNtlmMessage(frame, "host"); err == nil {
		t.Fatal("expected NTLM missing ciphertext error")
	}
}
