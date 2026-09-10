package winrm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func flushCaptureForTest(t testing.TB) {
	t.Helper()
	if err := flushWinRMCapture(); err != nil {
		t.Fatal(err)
	}
}

func TestCaptureRecordRedactsSensitiveDataByDefault(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "capture.jsonl")
	t.Setenv("OPSCTL_DEBUG_WINRM_CAPTURE_FILE", filePath)
	t.Setenv("OPSCTL_DEBUG_WINRM_CAPTURE", "")
	t.Setenv("OPSCTL_DEBUG_WINRM_UNSAFE", "")
	request, err := http.NewRequest(http.MethodPost, "http://user:password@server.example.test:5985/wsman?token=secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Basic synthetic-secret")
	request.Header.Set("Cookie", "session=synthetic-secret")
	emitWinRMCaptureRecord(7, "request", "encrypted", "unencrypted_payload", []byte("<secret>synthetic-secret</secret>"), request, 0, kerberosSOAPContentType, request.Header)
	flushCaptureForTest(t)

	encoded, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("synthetic-secret")) || bytes.Contains(encoded, []byte("password")) {
		t.Fatalf("safe capture contains sensitive data: %s", encoded)
	}
	var record winrmCaptureRecord
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(encoded))), &record); err != nil {
		t.Fatal(err)
	}
	if record.Schema != "opsctl.winrm.capture.v1" || record.ExchangeID != 7 || !record.Redacted || record.BodyBase64 != "" || record.BodyText != "" {
		t.Fatalf("unexpected capture record: %#v", record)
	}
	if record.HTTPHeaders.Get("Authorization") != debugRedactedValue || record.HTTPHeaders.Get("Cookie") != debugRedactedValue {
		t.Fatalf("sensitive headers were not redacted: %#v", record.HTTPHeaders)
	}
	if record.URL != "http://server.example.test:5985/wsman" {
		t.Fatalf("safe URL = %q", record.URL)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filePath)
		if err != nil {
			t.Fatal(err)
		}
		if permissions := info.Mode().Perm(); permissions != 0o600 {
			t.Fatalf("capture permissions = %04o, want 0600", permissions)
		}
	}
}

func TestCaptureRecordUnsafeModeIncludesRawData(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "capture.jsonl")
	t.Setenv("OPSCTL_DEBUG_WINRM_CAPTURE_FILE", filePath)
	t.Setenv("OPSCTL_DEBUG_WINRM_UNSAFE", "1")
	request, err := http.NewRequest(http.MethodPost, "http://user:password@server.example.test:5985/wsman?token=secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Basic synthetic-secret")
	payload := []byte("<secret>synthetic-secret</secret>")
	emitWinRMCaptureRecord(8, "request", "plaintext", "final_packet", payload, request, 0, kerberosSOAPContentType, request.Header)
	flushCaptureForTest(t)

	encoded, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	var record winrmCaptureRecord
	if err := json.Unmarshal(bytes.TrimSpace(encoded), &record); err != nil {
		t.Fatal(err)
	}
	if record.Redacted || record.BodyText != string(payload) || record.HTTPHeaders.Get("Authorization") != "Basic synthetic-secret" {
		t.Fatalf("unexpected unsafe capture record: %#v", record)
	}
	if record.URL != request.URL.String() {
		t.Fatalf("unsafe URL = %q, want %q", record.URL, request.URL.String())
	}
}

func TestCaptureDisabledDoesNotCreateFile(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "capture.jsonl")
	t.Setenv("OPSCTL_DEBUG_WINRM_CAPTURE_FILE", "")
	t.Setenv("OPSCTL_DEBUG_WINRM_CAPTURE", "")
	t.Setenv("OPSCTL_DEBUG_WINRM_UNSAFE", "1")
	output := captureDebugStderr(t, func() {
		emitWinRMCaptureRecord(9, "request", "plaintext", "final_packet", []byte("synthetic-secret"), nil, 0, kerberosSOAPContentType, nil)
	})
	if output != "" {
		t.Fatalf("disabled capture output = %q", output)
	}
	if _, err := os.Stat(filePath); !os.IsNotExist(err) {
		t.Fatalf("disabled capture file stat error = %v", err)
	}
}

func TestCaptureEmptySafeRecordIsMarkedRedacted(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "capture.jsonl")
	t.Setenv("OPSCTL_DEBUG_WINRM_CAPTURE_FILE", filePath)
	t.Setenv("OPSCTL_DEBUG_WINRM_UNSAFE", "")
	emitWinRMCaptureRecord(11, "request", "bootstrap", "final_packet", nil, nil, 0, kerberosSOAPContentType, nil)
	flushCaptureForTest(t)
	encoded, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	var record winrmCaptureRecord
	if err := json.Unmarshal(bytes.TrimSpace(encoded), &record); err != nil {
		t.Fatal(err)
	}
	if !record.Redacted {
		t.Fatalf("safe record is not marked redacted: %#v", record)
	}
}

func TestCaptureTightensExistingFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are not meaningful on Windows")
	}
	filePath := filepath.Join(t.TempDir(), "capture.jsonl")
	if err := os.WriteFile(filePath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPSCTL_DEBUG_WINRM_CAPTURE_FILE", filePath)
	t.Setenv("OPSCTL_DEBUG_WINRM_CAPTURE", "")
	t.Setenv("OPSCTL_DEBUG_WINRM_UNSAFE", "")
	emitWinRMCaptureRecord(10, "request", "plaintext", "final_packet", nil, nil, 0, kerberosSOAPContentType, nil)
	flushCaptureForTest(t)
	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o600 {
		t.Fatalf("capture permissions = %04o, want 0600", permissions)
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

func TestCaptureUnsafePayloadIsBoundedWithoutDuplication(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "capture.jsonl")
	t.Setenv("OPSCTL_DEBUG_WINRM_CAPTURE_FILE", filePath)
	t.Setenv("OPSCTL_DEBUG_WINRM_UNSAFE", "1")
	payload := bytes.Repeat([]byte("x"), winrmCapturePayloadLimit+1024)
	emitWinRMCaptureRecord(12, "response", "plaintext", "final_packet", payload, nil, 200, kerberosSOAPContentType, nil)
	flushCaptureForTest(t)

	encoded, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	var record winrmCaptureRecord
	if err := json.Unmarshal(bytes.TrimSpace(encoded), &record); err != nil {
		t.Fatal(err)
	}
	if record.Bytes != len(payload) || record.CapturedBytes != winrmCapturePayloadLimit || !record.BodyTruncated {
		t.Fatalf("capture bounds = bytes %d, captured %d, truncated %t", record.Bytes, record.CapturedBytes, record.BodyTruncated)
	}
	if len(record.BodyText) != winrmCapturePayloadLimit || record.BodyBase64 != "" {
		t.Fatalf("capture representations = text %d, base64 %d", len(record.BodyText), len(record.BodyBase64))
	}
}

func TestCaptureSinkDropsWhenQueueIsSaturated(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	sink := newCaptureSink()
	sink.process = func(captureSinkJob) {
		once.Do(func() { close(started) })
		<-release
	}
	sink.enqueue(captureSinkJob{encoded: []byte("first")})
	<-started
	for index := 0; index < winrmCaptureQueueSize+1; index++ {
		sink.enqueue(captureSinkJob{encoded: []byte("queued")})
	}
	if dropped := sink.dropped.Load(); dropped != 1 {
		t.Fatalf("dropped records = %d, want 1", dropped)
	}
	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sink.flush(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestCaptureFlushHonorsContext(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	sink := newCaptureSink()
	sink.process = func(captureSinkJob) {
		close(started)
		<-release
	}
	sink.enqueue(captureSinkJob{encoded: []byte("blocked")})
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sink.flush(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("flush error = %v, want context canceled", err)
	}
	close(release)
}

func TestCaptureFileRotatesAtLimit(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "capture.jsonl")
	if err := os.WriteFile(filePath, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(filePath, winrmCaptureFileLimit); err != nil {
		t.Fatal(err)
	}
	writeCaptureFile(filePath, []byte(`{"new":true}`))
	if _, err := os.Stat(filePath + ".1"); err != nil {
		t.Fatalf("rotated capture: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filePath + ".1")
		if err != nil {
			t.Fatal(err)
		}
		if permissions := info.Mode().Perm(); permissions != 0o600 {
			t.Fatalf("rotated capture permissions = %04o, want 0600", permissions)
		}
	}
	encoded, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != "{\"new\":true}\n" {
		t.Fatalf("new capture = %q", encoded)
	}
}

func BenchmarkCaptureFile64KiB(b *testing.B) {
	for _, unsafe := range []bool{false, true} {
		b.Run(fmt.Sprintf("unsafe-%t", unsafe), func(b *testing.B) {
			filePath := filepath.Join(b.TempDir(), "capture.jsonl")
			b.Setenv("OPSCTL_DEBUG_WINRM_CAPTURE_FILE", filePath)
			b.Setenv("OPSCTL_DEBUG_WINRM_CAPTURE", "")
			if unsafe {
				b.Setenv("OPSCTL_DEBUG_WINRM_UNSAFE", "1")
			} else {
				b.Setenv("OPSCTL_DEBUG_WINRM_UNSAFE", "")
			}
			payload := bytes.Repeat([]byte("x"), 64<<10)
			request, err := http.NewRequest(http.MethodPost, "http://server.example.test/wsman", nil)
			if err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				emitWinRMCaptureRecord(1, "request", "plaintext", "final_packet", payload, request, 0, kerberosSOAPContentType, nil)
			}
			b.StopTimer()
			flushCaptureForTest(b)
		})
	}
}

func BenchmarkCaptureSaturatedQueue(b *testing.B) {
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	sink := newCaptureSink()
	sink.process = func(captureSinkJob) {
		once.Do(func() { close(started) })
		<-release
	}
	sink.enqueue(captureSinkJob{encoded: []byte("blocked")})
	<-started
	for range cap(sink.queue) {
		sink.enqueue(captureSinkJob{encoded: []byte("queued")})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		sink.enqueue(captureSinkJob{encoded: []byte("dropped")})
	}
	b.StopTimer()
	close(release)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sink.flush(ctx); err != nil {
		b.Fatal(err)
	}
}
