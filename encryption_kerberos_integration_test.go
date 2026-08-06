package winrm

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func phase7MultipartEncryptedResponse(frame []byte, length int) []byte {
	payload := []byte{}
	payload = append(payload, []byte(mimeBoundary)...)
	payload = append(payload, []byte("\r\n")...)
	payload = append(payload, []byte("\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n")...)
	payload = append(payload, []byte(fmt.Sprintf("\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=%d\r\n", length))...)
	payload = append(payload, []byte(mimeBoundary)...)
	payload = append(payload, []byte("\r\n")...)
	payload = append(payload, []byte("\tContent-Type: application/octet-stream\r\n")...)
	payload = append(payload, frame...)
	payload = append(payload, []byte(mimeBoundary)...)
	payload = append(payload, []byte("--\r\n")...)
	return payload
}

func TestParseEncryptedResponseKerberosRoundTrip(t *testing.T) {
	enc, err := NewEncryption("kerberos")
	if err != nil {
		t.Fatalf("NewEncryption(kerberos) error: %v", err)
	}

	key := phase3TestSessionKey(t)
	enc.kerberos.context = &kerberosContext{serviceSessionKey: key}

	plain := []byte("<s:Envelope>ok</s:Envelope>")
	frame := phase4BuildAcceptorFrame(t, key, 0, plain)
	body := phase7MultipartEncryptedResponse(frame, len(plain))

	req, reqErr := http.NewRequest("POST", "http://host.example/wsman", nil)
	if reqErr != nil {
		t.Fatalf("request create error: %v", reqErr)
	}

	resp := &http.Response{
		Header: http.Header{
			"Content-Type": []string{`multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"`},
		},
		Body:    io.NopCloser(strings.NewReader(string(body))),
		Request: req,
	}

	got, err := enc.ParseEncryptedResponse(resp)
	if err != nil {
		t.Fatalf("ParseEncryptedResponse error: %v", err)
	}
	if string(got) != string(plain) {
		t.Fatalf("decrypted body mismatch: got %q want %q", string(got), string(plain))
	}
}

func TestParseEncryptedResponseKerberosLengthMismatch(t *testing.T) {
	enc, err := NewEncryption("kerberos")
	if err != nil {
		t.Fatalf("NewEncryption(kerberos) error: %v", err)
	}

	key := phase3TestSessionKey(t)
	enc.kerberos.context = &kerberosContext{serviceSessionKey: key}

	plain := []byte("<s:Envelope>ok</s:Envelope>")
	frame := phase4BuildAcceptorFrame(t, key, 0, plain)
	body := phase7MultipartEncryptedResponse(frame, len(plain)+10)

	req, reqErr := http.NewRequest("POST", "http://host.example/wsman", nil)
	if reqErr != nil {
		t.Fatalf("request create error: %v", reqErr)
	}

	resp := &http.Response{
		Header: http.Header{
			"Content-Type": []string{`multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"`},
		},
		Body:    io.NopCloser(strings.NewReader(string(body))),
		Request: req,
	}

	if _, err := enc.ParseEncryptedResponse(resp); err == nil {
		t.Fatal("expected length mismatch error")
	}
}
