package winrm

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCaptureRecordWritesOpsctlSchema(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "capture.jsonl")
	t.Setenv("OPSCTL_DEBUG_WINRM_CAPTURE_FILE", filePath)
	request, err := http.NewRequest(http.MethodPost, "http://server.example.test:5985/wsman", nil)
	if err != nil {
		t.Fatal(err)
	}
	emitWinRMCaptureRecord(7, "request", "encrypted", "unencrypted_payload", []byte("<soap/>"), request, 0, kerberosSOAPContentType, request.Header)

	encoded, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	var record winrmCaptureRecord
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(encoded))), &record); err != nil {
		t.Fatal(err)
	}
	if record.Schema != "opsctl.winrm.capture.v1" || record.ExchangeID != 7 || record.BodyText != "<soap/>" {
		t.Fatalf("unexpected capture record: %#v", record)
	}
}

func TestParseCaptureGSSDetails(t *testing.T) {
	context := &fixtureKerberosGSSContext{header: fixtureKerberosGSSHeader(), payload: fixtureKerberosGSSBody([]byte("cipher"))}
	adapter, err := newKerberosGSSAdapter(context)
	if err != nil {
		t.Fatal(err)
	}
	framer, err := newKerberosMessageFramer(64)
	if err != nil {
		t.Fatal(err)
	}
	contentType, body, err := framer.seal([]byte("<soap/>"), adapter)
	if err != nil {
		t.Fatal(err)
	}
	details := parseCaptureGSSDetails(body, contentType)
	if details == nil || details.ParseError != "" || details.WrapTokenID != "0x0504" || details.OriginalContentLength != len("<soap/>") {
		t.Fatalf("unexpected GSS details: %#v", details)
	}
}
