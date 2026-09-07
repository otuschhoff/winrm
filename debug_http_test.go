package winrm

import (
	"strings"
	"testing"
)

func TestHTTPDebugState(t *testing.T) {
	previous := HTTPDebugEnabled()
	t.Cleanup(func() { SetHTTPDebug(previous) })

	SetHTTPDebug(true)
	if !HTTPDebugEnabled() {
		t.Fatal("HTTP debug should be enabled")
	}
	SetHTTPDebug(false)
	if HTTPDebugEnabled() {
		t.Fatal("HTTP debug should be disabled")
	}
}

func TestFormatDebugBodySummarizesEncryptedPayload(t *testing.T) {
	body := []byte("--Encrypted Boundary\r\n\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n--Encrypted Boundary\r\n\tContent-Type: application/octet-stream\r\n\x10\x00\x00\x00abcdefghijklmnopsealed--Encrypted Boundary--\r\n")
	formatted := formatDebugBody(body)
	if !strings.Contains(formatted, "<encrypted-winrm-payload") || !strings.Contains(formatted, "header-bytes=16") {
		t.Fatalf("unexpected encrypted payload summary: %q", formatted)
	}
}
