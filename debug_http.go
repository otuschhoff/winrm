package winrm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync/atomic"
)

var httpDebugEnabled atomic.Bool
var httpDebugUnsafe atomic.Bool
var httpDebugCounter atomic.Uint64

// SetHTTPDebug enables or disables verbose HTTP request/response logging.
func SetHTTPDebug(enabled bool) {
	httpDebugEnabled.Store(enabled)
}

// HTTPDebugEnabled reports whether verbose HTTP logging is enabled.
func HTTPDebugEnabled() bool {
	return httpDebugEnabled.Load()
}

// SetHTTPDebugUnsafe controls whether HTTP debugging includes raw headers and bodies.
// Unsafe output can contain credentials, commands, and command output.
func SetHTTPDebugUnsafe(enabled bool) {
	httpDebugUnsafe.Store(enabled)
}

// HTTPDebugUnsafeEnabled reports whether raw HTTP debugging is enabled.
func HTTPDebugUnsafeEnabled() bool {
	return httpDebugUnsafe.Load() || winrmUnsafeDebugEnabled()
}

func debugHTTPRoundTrip(req *http.Request, resp *http.Response, err error) {
	if !HTTPDebugEnabled() {
		return
	}
	id := httpDebugCounter.Add(1)
	unsafe := HTTPDebugUnsafeEnabled()

	fmt.Fprintf(os.Stderr, "[DEBUG][HTTP][%d] ---- request ----\n", id)
	if req == nil {
		fmt.Fprintf(os.Stderr, "[DEBUG][HTTP][%d] <nil request>\n", id)
	} else {
		fmt.Fprintf(os.Stderr, "[DEBUG][HTTP][%d] %s %s\n", id, req.Method, debugURL(req.URL, unsafe))
		dumpHeaders(id, req.Header, unsafe)
		if body, bodyErr := readRequestBodyForDebug(req); bodyErr != nil {
			fmt.Fprintf(os.Stderr, "[DEBUG][HTTP][%d] request-body-error: %s\n", id, formatDebugError(bodyErr, unsafe))
		} else {
			fmt.Fprintf(os.Stderr, "[DEBUG][HTTP][%d] request-body-bytes=%d\n", id, len(body))
			dumpDebugBody(id, body, unsafe)
		}
	}

	fmt.Fprintf(os.Stderr, "[DEBUG][HTTP][%d] ---- response ----\n", id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[DEBUG][HTTP][%d] roundtrip-error: %s\n", id, formatDebugError(err, unsafe))
	}
	if resp == nil {
		fmt.Fprintf(os.Stderr, "[DEBUG][HTTP][%d] <nil response>\n", id)
		fmt.Fprintf(os.Stderr, "[DEBUG][HTTP][%d] -----------------\n", id)
		return
	}

	fmt.Fprintf(os.Stderr, "[DEBUG][HTTP][%d] status=%s\n", id, resp.Status)
	dumpHeaders(id, resp.Header, unsafe)
	fmt.Fprintf(os.Stderr, "[DEBUG][HTTP][%d] -----------------\n", id)
}

func debugHTTPResponseBody(body []byte, err error) {
	if !HTTPDebugEnabled() {
		return
	}
	id := httpDebugCounter.Add(1)
	unsafe := HTTPDebugUnsafeEnabled()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[DEBUG][HTTP][%d] response-body-error: %s\n", id, formatDebugError(err, unsafe))
	}
	fmt.Fprintf(os.Stderr, "[DEBUG][HTTP][%d] response-body-bytes=%d\n", id, len(body))
	dumpDebugBody(id, body, unsafe)
}

func dumpDebugBody(id uint64, body []byte, unsafe bool) {
	formatter := formatDebugBody
	if unsafe {
		formatter = formatDebugBodyUnsafe
	}
	for _, line := range strings.Split(formatter(body), "\n") {
		fmt.Fprintf(os.Stderr, "[DEBUG][HTTP][%d] body: %s\n", id, line)
	}
}

func formatDebugBody(body []byte) string {
	if len(body) == 0 {
		return "<empty>"
	}
	if looksLikeEncryptedWinRMPayload(body) {
		return summarizeEncryptedWinRMPayload(body)
	}
	return fmt.Sprintf("<redacted bytes=%d>", len(body))
}

func formatDebugBodyUnsafe(body []byte) string {
	if len(body) == 0 {
		return "<empty>"
	}

	var formatted strings.Builder
	formatted.Grow(len(body) * 4)
	const hexDigits = "0123456789ABCDEF"
	for _, char := range body {
		switch char {
		case '\n':
			formatted.WriteByte('\n')
		case '\r':
			formatted.WriteString(`\r`)
		case '\t':
			formatted.WriteString(`\t`)
		default:
			if char >= 0x20 && char <= 0x7e {
				formatted.WriteByte(char)
			} else {
				formatted.WriteString(`\x`)
				formatted.WriteByte(hexDigits[char>>4])
				formatted.WriteByte(hexDigits[char&0x0f])
			}
		}
	}
	return formatted.String()
}

func formatDebugError(err error, unsafe bool) string {
	if unsafe {
		return err.Error()
	}
	return fmt.Sprintf("<redacted %T>", err)
}

func looksLikeEncryptedWinRMPayload(body []byte) bool {
	return bytes.Contains(body, []byte(kerberosEncryptedProtocol)) && bytes.Contains(body, []byte("application/octet-stream"))
}

func summarizeEncryptedWinRMPayload(body []byte) string {
	marker := []byte("Content-Type: application/octet-stream\r\n")
	index := bytes.Index(body, marker)
	if index == -1 {
		return fmt.Sprintf("<encrypted-winrm-payload bytes=%d>", len(body))
	}
	payload := body[index+len(marker):]
	terminalBoundary := []byte("--" + kerberosMultipartBoundary + "--\r\n")
	hasClosingBoundary := false
	if end := bytes.LastIndex(payload, terminalBoundary); end >= 0 {
		hasClosingBoundary = true
		payload = payload[:end]
	}
	if len(payload) < 4 {
		return "<encrypted-winrm-payload truncated>"
	}
	headerLength := int(binary.LittleEndian.Uint32(payload[:4]))
	sealedLength := len(payload) - 4 - headerLength
	if sealedLength < 0 {
		sealedLength = 0
	}
	return fmt.Sprintf("<encrypted-winrm-payload header-bytes=%d sealed-bytes=%d total-bytes=%d closing-boundary=%t>", headerLength, sealedLength, len(payload), hasClosingBoundary)
}

func readRequestBodyForDebug(req *http.Request) ([]byte, error) {
	if req == nil || req.GetBody == nil {
		return nil, nil
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	defer body.Close()
	return io.ReadAll(body)
}

func dumpHeaders(id uint64, headers http.Header, unsafe bool) {
	if len(headers) == 0 {
		fmt.Fprintf(os.Stderr, "[DEBUG][HTTP][%d] headers: <empty>\n", id)
		return
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	redacted := cloneHTTPHeaders(headers, unsafe)
	for _, key := range keys {
		fmt.Fprintf(os.Stderr, "[DEBUG][HTTP][%d] %s: %s\n", id, key, strings.Join(redacted[key], ", "))
	}
}
