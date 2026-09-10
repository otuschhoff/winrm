package winrm

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

var winrmCaptureCounter atomic.Uint64
var winrmCaptureSink = newCaptureSink()

const (
	debugRedactedValue        = "[REDACTED]"
	winrmCaptureQueueSize     = 64
	winrmCapturePayloadLimit  = 64 << 10
	winrmCaptureRecordLimit   = 256 << 10
	winrmCaptureFileLimit     = 16 << 20
	winrmCaptureHeaderLimit   = 8 << 10
	winrmCaptureHeaderCount   = 64
	winrmCaptureMetadataLimit = 8 << 10
	winrmCaptureFlushTimeout  = 5 * time.Second
)

type winrmCaptureRecord struct {
	Schema            string                  `json:"schema"`
	Implementation    string                  `json:"implementation"`
	ExchangeID        uint64                  `json:"exchange_id"`
	Direction         string                  `json:"direction"`
	Phase             string                  `json:"phase"`
	Representation    string                  `json:"representation"`
	Method            string                  `json:"method,omitempty"`
	URL               string                  `json:"url,omitempty"`
	Status            int                     `json:"status,omitempty"`
	ContentType       string                  `json:"content_type,omitempty"`
	HTTPHeaders       http.Header             `json:"http_headers,omitempty"`
	Bytes             int                     `json:"bytes"`
	CapturedBytes     int                     `json:"captured_bytes,omitempty"`
	BodyBase64        string                  `json:"body_base64,omitempty"`
	BodyText          string                  `json:"body_text,omitempty"`
	BodyTruncated     bool                    `json:"body_truncated,omitempty"`
	HeadersTruncated  bool                    `json:"headers_truncated,omitempty"`
	MetadataTruncated bool                    `json:"metadata_truncated,omitempty"`
	Redacted          bool                    `json:"redacted,omitempty"`
	GSS               *winrmCaptureGSSDetails `json:"gss,omitempty"`
	Kerberos          *winrmCaptureGSSDetails `json:"kerberos,omitempty"`
}

type captureSinkJob struct {
	encoded  []byte
	stderr   bool
	filePath string
	barrier  chan struct{}
}

type captureSink struct {
	queue   chan captureSinkJob
	once    sync.Once
	dropped atomic.Uint64
	process func(captureSinkJob)
}

func newCaptureSink() *captureSink {
	return &captureSink{queue: make(chan captureSinkJob, winrmCaptureQueueSize), process: processCaptureSinkJob}
}

func (sink *captureSink) start() {
	sink.once.Do(func() { go sink.run() })
}

func (sink *captureSink) enqueue(job captureSinkJob) {
	sink.start()
	select {
	case sink.queue <- job:
	default:
		sink.dropped.Add(1)
	}
}

func (sink *captureSink) run() {
	for job := range sink.queue {
		if job.barrier != nil {
			close(job.barrier)
			continue
		}
		sink.process(job)
	}
}

func processCaptureSinkJob(job captureSinkJob) {
	if job.stderr {
		_, _ = fmt.Fprintf(os.Stderr, "[DEBUG][WINRM-CAPTURE] %s\n", job.encoded)
	}
	if job.filePath != "" {
		writeCaptureFile(job.filePath, job.encoded)
	}
}

func (sink *captureSink) flush(ctx context.Context) error {
	sink.start()
	barrier := make(chan struct{})
	select {
	case sink.queue <- captureSinkJob{barrier: barrier}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-barrier:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// FlushWinRMCapture waits for all capture records accepted before the call to
// reach their configured sinks. Records dropped before the call are not retried.
func FlushWinRMCapture(ctx context.Context) error {
	return winrmCaptureSink.flush(ctx)
}

// WinRMCaptureDroppedRecords reports records discarded because the bounded
// capture queue was full.
func WinRMCaptureDroppedRecords() uint64 {
	return winrmCaptureSink.dropped.Load()
}

func flushWinRMCapture() error {
	ctx, cancel := context.WithTimeout(context.Background(), winrmCaptureFlushTimeout)
	defer cancel()
	return FlushWinRMCapture(ctx)
}

type winrmCaptureGSSDetails struct {
	Protocol              string `json:"protocol,omitempty"`
	OriginalContentLength int    `json:"original_content_length,omitempty"`
	SignatureLength       int    `json:"signature_length,omitempty"`
	SealedPayloadBytes    int    `json:"sealed_payload_bytes,omitempty"`
	WrapTokenID           string `json:"wrap_token_id,omitempty"`
	Flags                 uint8  `json:"flags,omitempty"`
	EC                    int    `json:"ec,omitempty"`
	RRC                   int    `json:"rrc,omitempty"`
	SndSeqNum             uint64 `json:"snd_seq_num,omitempty"`
	ParseError            string `json:"parse_error,omitempty"`
}

func winrmCaptureEnabled() bool {
	return strings.TrimSpace(os.Getenv("OPSCTL_DEBUG_WINRM_CAPTURE")) != "" || strings.TrimSpace(os.Getenv("OPSCTL_DEBUG_WINRM_CAPTURE_FILE")) != ""
}

func winrmUnsafeDebugEnabled() bool {
	value := strings.TrimSpace(os.Getenv("OPSCTL_DEBUG_WINRM_UNSAFE"))
	return value == "1" || strings.EqualFold(value, "true")
}

func debugSOAPPayload(direction, phase string, payload []byte) {
	if strings.TrimSpace(os.Getenv("OPSCTL_DEBUG_WINRM_SOAP")) == "" {
		return
	}
	if len(payload) == 0 {
		fmt.Fprintf(os.Stderr, "[DEBUG][WINRM-SOAP] %s.%s.payload=<none>\n", direction, phase)
		return
	}
	fmt.Fprintf(os.Stderr, "[DEBUG][WINRM-SOAP] %s.%s.bytes=%d\n", direction, phase, len(payload))
	formatter := formatDebugBody
	if winrmUnsafeDebugEnabled() {
		formatter = formatDebugBodyUnsafe
	}
	fmt.Fprintf(os.Stderr, "[DEBUG][WINRM-SOAP] %s.%s.payload=%s\n", direction, phase, formatter(payload))
}

func nextWinRMCaptureExchangeID() uint64 {
	return winrmCaptureCounter.Add(1)
}

func cloneHTTPHeaders(headers http.Header, unsafe bool) http.Header {
	if len(headers) == 0 {
		return nil
	}
	cloned := make(http.Header, len(headers))
	for key, values := range headers {
		if !unsafe && sensitiveHTTPHeader(key) {
			cloned[key] = []string{debugRedactedValue}
			continue
		}
		cloned[key] = append([]string(nil), values...)
	}
	return cloned
}

func cloneHTTPHeadersBounded(headers http.Header, unsafe bool) (http.Header, bool) {
	if len(headers) == 0 {
		return nil, false
	}
	cloned := make(http.Header, len(headers))
	remaining := winrmCaptureHeaderLimit
	count := 0
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		values := headers[key]
		if count >= winrmCaptureHeaderCount || len(key) > remaining {
			return cloned, true
		}
		count++
		remaining -= len(key)
		if !unsafe && sensitiveHTTPHeader(key) {
			cloned[key] = []string{debugRedactedValue}
			continue
		}
		for _, value := range values {
			if len(value) > remaining {
				cloned[key] = append(cloned[key], value[:remaining])
				return cloned, true
			}
			cloned[key] = append(cloned[key], value)
			remaining -= len(value)
		}
	}
	return cloned, false
}

func boundCaptureMetadata(value string) (string, bool) {
	if len(value) <= winrmCaptureMetadataLimit {
		return value, false
	}
	return strings.ToValidUTF8(value[:winrmCaptureMetadataLimit], ""), true
}

func sensitiveHTTPHeader(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "authorization", "proxy-authorization", "www-authenticate", "proxy-authenticate", "authentication-info", "proxy-authentication-info", "cookie", "set-cookie", "location", "referer":
		return true
	}
	compactName := strings.Map(func(char rune) rune {
		switch char {
		case '-', '_', ' ':
			return -1
		default:
			return char
		}
	}, name)
	return strings.Contains(name, "token") || strings.Contains(name, "secret") || strings.Contains(name, "credential") || strings.Contains(name, "password") || strings.Contains(name, "passwd") || strings.Contains(compactName, "apikey") || strings.Contains(compactName, "privatekey") || strings.Contains(compactName, "accesskey")
}

func debugURL(value *url.URL, unsafe bool) string {
	if value == nil {
		return ""
	}
	if unsafe {
		return value.String()
	}
	clean := *value
	clean.User = nil
	clean.RawQuery = ""
	clean.ForceQuery = false
	clean.Fragment = ""
	clean.RawFragment = ""
	return clean.String()
}

func parseCaptureGSSDetails(payload []byte, contentType string) *winrmCaptureGSSDetails {
	if !strings.Contains(strings.ToLower(contentType), "session-encrypted") {
		return nil
	}
	details := &winrmCaptureGSSDetails{Protocol: contentType}
	streamMarker := []byte("\tContent-Type: application/octet-stream\r\n")
	streamStart := bytes.Index(payload, streamMarker)
	if streamStart < 0 {
		details.ParseError = "encrypted stream marker is missing"
		return details
	}
	stream := payload[streamStart+len(streamMarker):]
	terminalBoundary := []byte("--" + kerberosMultipartBoundary + "--\r\n")
	if boundaryStart := bytes.LastIndex(stream, terminalBoundary); boundaryStart >= 0 {
		stream = stream[:boundaryStart]
	}
	if len(stream) < 4 {
		details.ParseError = "encrypted stream is missing security header length"
		return details
	}
	headerLength := int(binary.LittleEndian.Uint32(stream[:4]))
	details.SignatureLength = headerLength
	if headerLength < kerberosGSSHeaderLength || 4+headerLength > len(stream) {
		details.ParseError = fmt.Sprintf("invalid Kerberos security header length %d", headerLength)
		return details
	}
	header := stream[4 : 4+headerLength]
	details.SealedPayloadBytes = len(stream) - 4 - headerLength
	details.WrapTokenID = fmt.Sprintf("0x%02x%02x", header[0], header[1])
	details.Flags = header[2]
	details.EC = int(binary.BigEndian.Uint16(header[4:6]))
	details.RRC = int(binary.BigEndian.Uint16(header[6:8]))
	details.SndSeqNum = binary.BigEndian.Uint64(header[8:16])

	metadata := payload[:streamStart]
	if marker := []byte(";Length="); bytes.Contains(metadata, marker) {
		lengthText := metadata[bytes.LastIndex(metadata, marker)+len(marker):]
		if end := bytes.Index(lengthText, []byte("\r\n")); end >= 0 {
			lengthText = lengthText[:end]
		}
		fmt.Sscanf(string(lengthText), "%d", &details.OriginalContentLength)
	}
	return details
}

func emitWinRMCaptureRecord(exchangeID uint64, direction, phase, representation string, payload []byte, request *http.Request, status int, contentType string, headers http.Header) {
	if !winrmCaptureEnabled() {
		return
	}
	unsafe := winrmUnsafeDebugEnabled()
	method, rawURL := "", ""
	if request != nil {
		method = request.Method
		rawURL = debugURL(request.URL, unsafe)
	}
	method, methodTruncated := boundCaptureMetadata(method)
	rawURL, urlTruncated := boundCaptureMetadata(rawURL)
	contentType, contentTypeTruncated := boundCaptureMetadata(contentType)
	capturedPayload := payload
	if len(capturedPayload) > winrmCapturePayloadLimit {
		capturedPayload = capturedPayload[:winrmCapturePayloadLimit]
	}
	gssDetails := parseCaptureGSSDetails(capturedPayload, contentType)
	capturedHeaders, headersTruncated := cloneHTTPHeadersBounded(headers, unsafe)
	record := winrmCaptureRecord{
		Schema: "opsctl.winrm.capture.v1", Implementation: "go-winrm", ExchangeID: exchangeID,
		Direction: direction, Phase: phase, Representation: representation,
		Method: method, URL: rawURL, Status: status, ContentType: contentType,
		HTTPHeaders: capturedHeaders, Bytes: len(payload), CapturedBytes: len(capturedPayload),
		BodyTruncated: len(capturedPayload) != len(payload), HeadersTruncated: headersTruncated, Redacted: !unsafe,
		MetadataTruncated: methodTruncated || urlTruncated || contentTypeTruncated,
		GSS:               gssDetails, Kerberos: gssDetails,
	}
	if unsafe {
		if utf8.Valid(capturedPayload) {
			record.BodyText = string(capturedPayload)
		} else {
			record.BodyBase64 = base64.StdEncoding.EncodeToString(capturedPayload)
		}
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return
	}
	if len(encoded) > winrmCaptureRecordLimit {
		record.BodyBase64 = ""
		record.BodyText = ""
		record.CapturedBytes = 0
		record.BodyTruncated = len(payload) > 0
		encoded, err = json.Marshal(record)
		if err != nil || len(encoded) > winrmCaptureRecordLimit {
			return
		}
	}
	winrmCaptureSink.enqueue(captureSinkJob{
		encoded:  append([]byte(nil), encoded...),
		stderr:   strings.TrimSpace(os.Getenv("OPSCTL_DEBUG_WINRM_CAPTURE")) != "",
		filePath: strings.TrimSpace(os.Getenv("OPSCTL_DEBUG_WINRM_CAPTURE_FILE")),
	})
}

func writeCaptureFile(filePath string, encoded []byte) {
	lineSize := int64(len(encoded) + 1)
	if info, err := os.Stat(filePath); err == nil && info.Size()+lineSize > winrmCaptureFileLimit {
		rotatedPath := filePath + ".1"
		_ = os.Remove(rotatedPath)
		if err := os.Rename(filePath, rotatedPath); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[DEBUG][WINRM-CAPTURE] capture-file-error=%q\n", err)
			return
		}
		if err := os.Chmod(rotatedPath, 0o600); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[DEBUG][WINRM-CAPTURE] capture-file-error=%q\n", err)
			return
		}
	}
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[DEBUG][WINRM-CAPTURE] capture-file-error=%q\n", err)
		return
	}
	if chmodErr := file.Chmod(0o600); chmodErr != nil {
		_ = file.Close()
		_, _ = fmt.Fprintf(os.Stderr, "[DEBUG][WINRM-CAPTURE] capture-file-error=%q\n", chmodErr)
		return
	}
	written, writeErr := file.Write(append(encoded, '\n'))
	if writeErr == nil && written != len(encoded)+1 {
		writeErr = fmt.Errorf("short capture write: wrote %d of %d bytes", written, len(encoded)+1)
	}
	closeErr := file.Close()
	if writeErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[DEBUG][WINRM-CAPTURE] capture-file-error=%q\n", writeErr)
	} else if closeErr != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[DEBUG][WINRM-CAPTURE] capture-file-error=%q\n", closeErr)
	}
}
