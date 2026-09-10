package winrm

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"
)

var winrmCaptureCounter atomic.Uint64
var winrmCaptureFileMu sync.Mutex

const debugRedactedValue = "[REDACTED]"

type winrmCaptureRecord struct {
	Schema         string                  `json:"schema"`
	Implementation string                  `json:"implementation"`
	ExchangeID     uint64                  `json:"exchange_id"`
	Direction      string                  `json:"direction"`
	Phase          string                  `json:"phase"`
	Representation string                  `json:"representation"`
	Method         string                  `json:"method,omitempty"`
	URL            string                  `json:"url,omitempty"`
	Status         int                     `json:"status,omitempty"`
	ContentType    string                  `json:"content_type,omitempty"`
	HTTPHeaders    http.Header             `json:"http_headers,omitempty"`
	Bytes          int                     `json:"bytes"`
	BodyBase64     string                  `json:"body_base64,omitempty"`
	BodyText       string                  `json:"body_text,omitempty"`
	Redacted       bool                    `json:"redacted,omitempty"`
	GSS            *winrmCaptureGSSDetails `json:"gss,omitempty"`
	Kerberos       *winrmCaptureGSSDetails `json:"kerberos,omitempty"`
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

func sensitiveHTTPHeader(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "authorization", "proxy-authorization", "www-authenticate", "proxy-authenticate", "authentication-info", "proxy-authentication-info", "cookie", "set-cookie", "location", "referer":
		return true
	}
	compactName := strings.NewReplacer("-", "", "_", "", " ", "").Replace(name)
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
	gssDetails := parseCaptureGSSDetails(payload, contentType)
	record := winrmCaptureRecord{
		Schema: "opsctl.winrm.capture.v1", Implementation: "go-winrm", ExchangeID: exchangeID,
		Direction: direction, Phase: phase, Representation: representation,
		Method: method, URL: rawURL, Status: status, ContentType: contentType,
		HTTPHeaders: cloneHTTPHeaders(headers, unsafe), Bytes: len(payload), Redacted: !unsafe,
		GSS: gssDetails, Kerberos: gssDetails,
	}
	if unsafe {
		record.BodyBase64 = base64.StdEncoding.EncodeToString(payload)
		if utf8.Valid(payload) {
			record.BodyText = string(payload)
		}
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return
	}
	if strings.TrimSpace(os.Getenv("OPSCTL_DEBUG_WINRM_CAPTURE")) != "" {
		fmt.Fprintf(os.Stderr, "[DEBUG][WINRM-CAPTURE] %s\n", encoded)
	}
	if filePath := strings.TrimSpace(os.Getenv("OPSCTL_DEBUG_WINRM_CAPTURE_FILE")); filePath != "" {
		winrmCaptureFileMu.Lock()
		defer winrmCaptureFileMu.Unlock()
		file, openErr := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if openErr != nil {
			fmt.Fprintf(os.Stderr, "[DEBUG][WINRM-CAPTURE] capture-file-error=%q\n", openErr)
			return
		}
		if chmodErr := file.Chmod(0o600); chmodErr != nil {
			_ = file.Close()
			fmt.Fprintf(os.Stderr, "[DEBUG][WINRM-CAPTURE] capture-file-error=%q\n", chmodErr)
			return
		}
		line := append(encoded, '\n')
		written, writeErr := file.Write(line)
		if writeErr == nil && written != len(line) {
			writeErr = fmt.Errorf("short capture write: wrote %d of %d bytes", written, len(line))
		}
		closeErr := file.Close()
		if writeErr != nil {
			fmt.Fprintf(os.Stderr, "[DEBUG][WINRM-CAPTURE] capture-file-error=%q\n", writeErr)
		} else if closeErr != nil {
			fmt.Fprintf(os.Stderr, "[DEBUG][WINRM-CAPTURE] capture-file-error=%q\n", closeErr)
		}
	}
}
