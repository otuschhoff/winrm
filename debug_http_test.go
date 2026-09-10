package winrm

import (
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

func captureDebugStderr(t *testing.T, write func()) string {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stderr
	os.Stderr = writer
	write()
	os.Stderr = previous
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	return string(output)
}

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

func TestHTTPDebugUnsafeState(t *testing.T) {
	previous := httpDebugUnsafe.Load()
	t.Cleanup(func() { SetHTTPDebugUnsafe(previous) })

	SetHTTPDebugUnsafe(true)
	if !HTTPDebugUnsafeEnabled() {
		t.Fatal("unsafe HTTP debug should be enabled")
	}
	SetHTTPDebugUnsafe(false)
	if HTTPDebugUnsafeEnabled() {
		t.Fatal("unsafe HTTP debug should be disabled")
	}
}

func TestRedactHTTPHeaders(t *testing.T) {
	headers := http.Header{
		"Authorization":      {"Basic synthetic-secret"},
		"Cookie":             {"session=synthetic-secret"},
		"Proxy-Authenticate": {"Negotiate synthetic-token"},
		"X-Password":         {"synthetic-secret"},
		"X-Apikey":           {"synthetic-secret"},
		"Location":           {"https://server.example.test/callback?token=synthetic-secret"},
		"Content-Type":       {"application/soap+xml"},
	}
	redacted := cloneHTTPHeaders(headers, false)
	if redacted.Get("Authorization") != debugRedactedValue || redacted.Get("Cookie") != debugRedactedValue || redacted.Get("Proxy-Authenticate") != debugRedactedValue || redacted.Get("X-Password") != debugRedactedValue || redacted.Get("X-ApiKey") != debugRedactedValue || redacted.Get("Location") != debugRedactedValue {
		t.Fatalf("sensitive headers were not redacted: %#v", redacted)
	}
	if redacted.Get("Content-Type") != "application/soap+xml" {
		t.Fatalf("content type was changed: %#v", redacted)
	}
	if headers.Get("Authorization") != "Basic synthetic-secret" {
		t.Fatal("source headers were mutated")
	}
	unsafe := cloneHTTPHeaders(headers, true)
	if unsafe.Get("Authorization") != "Basic synthetic-secret" {
		t.Fatalf("unsafe headers were redacted: %#v", unsafe)
	}
}

func TestFormatDebugBodyRedactsPlaintextByDefault(t *testing.T) {
	body := []byte("<secret>synthetic-secret</secret>")
	formatted := formatDebugBody(body)
	if strings.Contains(formatted, "synthetic-secret") || formatted != "<redacted bytes=33>" {
		t.Fatalf("safe debug body = %q", formatted)
	}
	unsafe := formatDebugBodyUnsafe(body)
	if unsafe != string(body) {
		t.Fatalf("unsafe debug body = %q", unsafe)
	}
}

func TestHTTPDebugOutputRedactsSensitiveDataByDefault(t *testing.T) {
	previousEnabled := HTTPDebugEnabled()
	previousUnsafe := httpDebugUnsafe.Load()
	t.Cleanup(func() {
		SetHTTPDebug(previousEnabled)
		SetHTTPDebugUnsafe(previousUnsafe)
	})
	t.Setenv("OPSCTL_DEBUG_WINRM_UNSAFE", "")
	SetHTTPDebug(true)
	SetHTTPDebugUnsafe(false)

	request, err := http.NewRequest(http.MethodPost, "http://user:password@server.example.test/wsman?token=synthetic-secret", strings.NewReader("<secret>synthetic-secret</secret>"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Basic synthetic-secret")
	response := &http.Response{
		Status: "200 OK",
		Header: http.Header{
			"Content-Type": {soapXML},
			"Set-Cookie":   {"session=synthetic-secret"},
		},
		Body: io.NopCloser(strings.NewReader("<secret>synthetic-secret</secret>")),
	}
	output := captureDebugStderr(t, func() { debugHTTPRoundTrip(request, response, nil) })
	if strings.Contains(output, "synthetic-secret") || strings.Contains(output, "password") {
		t.Fatalf("safe HTTP debug contains sensitive data: %s", output)
	}
	if !strings.Contains(output, debugRedactedValue) || !strings.Contains(output, "<redacted bytes=33>") {
		t.Fatalf("safe HTTP debug did not report redaction: %s", output)
	}
}

func TestHTTPDebugOutputUnsafeModeIncludesRawData(t *testing.T) {
	previousEnabled := HTTPDebugEnabled()
	previousUnsafe := httpDebugUnsafe.Load()
	t.Cleanup(func() {
		SetHTTPDebug(previousEnabled)
		SetHTTPDebugUnsafe(previousUnsafe)
	})
	t.Setenv("OPSCTL_DEBUG_WINRM_UNSAFE", "")
	SetHTTPDebug(true)
	SetHTTPDebugUnsafe(true)

	request, err := http.NewRequest(http.MethodPost, "http://server.example.test/wsman", strings.NewReader("synthetic-secret"))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Basic synthetic-secret")
	output := captureDebugStderr(t, func() { debugHTTPRoundTrip(request, nil, nil) })
	if !strings.Contains(output, "Basic synthetic-secret") || !strings.Contains(output, "body: synthetic-secret") {
		t.Fatalf("unsafe HTTP debug omitted raw data: %s", output)
	}
}

func TestHTTPDebugOutputRedactsErrorTextByDefault(t *testing.T) {
	previousEnabled := HTTPDebugEnabled()
	previousUnsafe := httpDebugUnsafe.Load()
	t.Cleanup(func() {
		SetHTTPDebug(previousEnabled)
		SetHTTPDebugUnsafe(previousUnsafe)
	})
	t.Setenv("OPSCTL_DEBUG_WINRM_UNSAFE", "")
	SetHTTPDebug(true)
	SetHTTPDebugUnsafe(false)

	output := captureDebugStderr(t, func() { debugHTTPRoundTrip(nil, nil, errors.New("synthetic-secret")) })
	if strings.Contains(output, "synthetic-secret") || !strings.Contains(output, "<redacted *errors.errorString>") {
		t.Fatalf("safe HTTP debug error output = %q", output)
	}
}

func TestFormatDebugBodyUnsafeIncludesEncryptedPayload(t *testing.T) {
	body := []byte("--Encrypted Boundary\r\n\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n--Encrypted Boundary\r\n\tContent-Type: application/octet-stream\r\n\x10\x00\x00\x00abcdefghijklmnopsealed--Encrypted Boundary--\r\n")
	formatted := formatDebugBodyUnsafe(body)
	if strings.Contains(formatted, "<encrypted-winrm-payload") || !strings.Contains(formatted, "application/HTTP-SPNEGO-session-encrypted") {
		t.Fatalf("unsafe encrypted debug body = %q", formatted)
	}
}

func TestSOAPDebugOutputRequiresUnsafeModeForPayload(t *testing.T) {
	t.Setenv("OPSCTL_DEBUG_WINRM_SOAP", "1")
	t.Setenv("OPSCTL_DEBUG_WINRM_UNSAFE", "")
	safeOutput := captureDebugStderr(t, func() { debugSOAPPayload("request", "plaintext", []byte("synthetic-secret")) })
	if strings.Contains(safeOutput, "synthetic-secret") || !strings.Contains(safeOutput, "<redacted bytes=16>") {
		t.Fatalf("safe SOAP debug output = %q", safeOutput)
	}
	t.Setenv("OPSCTL_DEBUG_WINRM_UNSAFE", "true")
	unsafeOutput := captureDebugStderr(t, func() { debugSOAPPayload("request", "plaintext", []byte("synthetic-secret")) })
	if !strings.Contains(unsafeOutput, "payload=synthetic-secret") {
		t.Fatalf("unsafe SOAP debug output = %q", unsafeOutput)
	}
}

func TestFormatDebugBodySummarizesEncryptedPayload(t *testing.T) {
	body := []byte("--Encrypted Boundary\r\n\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n--Encrypted Boundary\r\n\tContent-Type: application/octet-stream\r\n\x10\x00\x00\x00abcdefghijklmnopsealed--Encrypted Boundary--\r\n")
	formatted := formatDebugBody(body)
	if !strings.Contains(formatted, "<encrypted-winrm-payload") || !strings.Contains(formatted, "header-bytes=16") {
		t.Fatalf("unexpected encrypted payload summary: %q", formatted)
	}
}
