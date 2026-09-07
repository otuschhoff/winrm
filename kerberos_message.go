package winrm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"mime"
	"strconv"
	"strings"
)

const (
	kerberosEncryptedProtocol = "application/HTTP-SPNEGO-session-encrypted"
	kerberosMultipartBoundary = "Encrypted Boundary"
	kerberosSOAPContentType   = "application/soap+xml;charset=UTF-8"
	kerberosMaxWrapOverhead   = 256
	kerberosMaxMetadataSize   = 4096
)

type kerberosMessageFramer struct {
	maxPlaintextSize int
}

func newKerberosMessageFramer(maxPlaintextSize int) (*kerberosMessageFramer, error) {
	if maxPlaintextSize <= 0 {
		return nil, errors.New("Kerberos plaintext size limit must be positive")
	}
	maxInt := int(^uint(0) >> 1)
	if maxPlaintextSize > maxInt-kerberosMaxWrapOverhead-kerberosMaxMetadataSize {
		return nil, errors.New("Kerberos plaintext size limit is too large")
	}
	return &kerberosMessageFramer{maxPlaintextSize: maxPlaintextSize}, nil
}

func (framer *kerberosMessageFramer) seal(message []byte, adapter *kerberosGSSAdapter) (string, []byte, error) {
	if adapter == nil {
		return "", nil, errors.New("Kerberos GSS adapter is required")
	}
	if len(message) > framer.maxPlaintextSize {
		return "", nil, fmt.Errorf("Kerberos plaintext length %d exceeds limit %d", len(message), framer.maxPlaintextSize)
	}
	header, payload, err := adapter.wrap(message)
	if err != nil {
		return "", nil, err
	}
	if len(header)+len(payload) > len(message)+kerberosMaxWrapOverhead {
		return "", nil, errors.New("wrapped Kerberos token exceeds overhead limit")
	}

	marker := "--" + kerberosMultipartBoundary
	var body bytes.Buffer
	fmt.Fprintf(&body, "%s\r\n", marker)
	fmt.Fprintf(&body, "\tContent-Type: %s\r\n", kerberosEncryptedProtocol)
	fmt.Fprintf(&body, "\tOriginalContent: type=%s;Length=%d\r\n", kerberosSOAPContentType, len(message))
	fmt.Fprintf(&body, "%s\r\n", marker)
	body.WriteString("\tContent-Type: application/octet-stream\r\n")
	if err := binary.Write(&body, binary.LittleEndian, uint32(len(header))); err != nil {
		return "", nil, err
	}
	body.Write(header)
	body.Write(payload)
	fmt.Fprintf(&body, "%s--\r\n", marker)

	contentType := fmt.Sprintf(`multipart/encrypted;protocol="%s";boundary="%s"`, kerberosEncryptedProtocol, kerberosMultipartBoundary)
	return contentType, body.Bytes(), nil
}

func (framer *kerberosMessageFramer) open(contentType string, body []byte, adapter *kerberosGSSAdapter) ([]byte, error) {
	if adapter == nil {
		return nil, errors.New("Kerberos GSS adapter is required")
	}
	mediaType, parameters, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, fmt.Errorf("parse Kerberos response content type: %w", err)
	}
	if !strings.EqualFold(mediaType, "multipart/encrypted") {
		return nil, fmt.Errorf("unexpected Kerberos response media type %q", mediaType)
	}
	if !strings.EqualFold(parameters["protocol"], kerberosEncryptedProtocol) {
		return nil, fmt.Errorf("unexpected Kerberos response protocol %q", parameters["protocol"])
	}
	boundary := parameters["boundary"]
	if boundary == "" {
		return nil, errors.New("Kerberos response boundary is missing")
	}
	if !validKerberosBoundary(boundary) {
		return nil, errors.New("Kerberos response boundary is invalid")
	}
	if len(body) > framer.maxPlaintextSize+kerberosMaxWrapOverhead+kerberosMaxMetadataSize {
		return nil, fmt.Errorf("Kerberos response length %d exceeds configured limit", len(body))
	}

	marker := []byte("--" + boundary)
	metadataEnd := bytes.Index(body, append(append([]byte(nil), marker...), []byte("\r\n\tContent-Type: application/octet-stream\r\n")...))
	if metadataEnd < 0 || metadataEnd > kerberosMaxMetadataSize {
		return nil, errors.New("invalid Kerberos multipart metadata")
	}
	metadata := body[:metadataEnd]
	payloadStart := metadataEnd + len(marker) + len("\r\n\tContent-Type: application/octet-stream\r\n")
	terminalBoundary := append(append([]byte(nil), marker...), []byte("--\r\n")...)
	if !bytes.HasSuffix(body[payloadStart:], terminalBoundary) {
		return nil, errors.New("Kerberos multipart terminal boundary is missing")
	}
	encryptedStream := body[payloadStart : len(body)-len(terminalBoundary)]
	if len(encryptedStream) < 4+kerberosGSSHeaderLength+1 {
		return nil, errors.New("Kerberos encrypted stream is truncated")
	}

	expectedLength, err := parseKerberosMetadata(metadata, marker, framer.maxPlaintextSize)
	if err != nil {
		return nil, err
	}
	headerLength := uint64(binary.LittleEndian.Uint32(encryptedStream[:4]))
	if headerLength != kerberosGSSHeaderLength {
		return nil, fmt.Errorf("Kerberos security header length %d, want %d", headerLength, kerberosGSSHeaderLength)
	}
	headerEnd := uint64(4) + headerLength
	if headerEnd >= uint64(len(encryptedStream)) {
		return nil, errors.New("Kerberos encrypted stream is truncated")
	}
	message, err := adapter.unwrap(encryptedStream[4:headerEnd], encryptedStream[headerEnd:])
	if err != nil {
		return nil, err
	}
	if len(message) != expectedLength {
		return nil, fmt.Errorf("Kerberos plaintext length %d does not match declared length %d", len(message), expectedLength)
	}
	return message, nil
}

func validKerberosBoundary(boundary string) bool {
	if boundary == "" || len(boundary) > 70 || boundary[len(boundary)-1] == ' ' {
		return false
	}
	for index := range len(boundary) {
		if boundary[index] < 0x20 || boundary[index] > 0x7e {
			return false
		}
	}
	return true
}

func parseKerberosMetadata(metadata, marker []byte, maxPlaintextSize int) (int, error) {
	metadata = bytes.TrimSuffix(metadata, []byte("\r\n"))
	lines := bytes.Split(metadata, []byte("\r\n"))
	if len(lines) != 3 || !bytes.Equal(lines[0], marker) {
		return 0, errors.New("invalid Kerberos multipart metadata")
	}
	contentType, ok := cutKerberosHeader(lines[1], "Content-Type")
	if !ok || !strings.EqualFold(contentType, kerberosEncryptedProtocol) {
		return 0, errors.New("invalid Kerberos multipart protocol header")
	}
	originalContent, ok := cutKerberosHeader(lines[2], "OriginalContent")
	if !ok {
		return 0, errors.New("Kerberos OriginalContent header is missing")
	}
	const typePrefix = "type="
	lengthSeparator := strings.Index(originalContent, ";Length=")
	if !strings.HasPrefix(originalContent, typePrefix) || lengthSeparator < len(typePrefix) || strings.Contains(originalContent[lengthSeparator+1:], ";Length=") {
		return 0, errors.New("invalid Kerberos OriginalContent header")
	}
	originalMediaType, parameters, err := mime.ParseMediaType(originalContent[len(typePrefix):lengthSeparator])
	if err != nil || !strings.EqualFold(originalMediaType, "application/soap+xml") || !strings.EqualFold(parameters["charset"], "UTF-8") || len(parameters) != 1 {
		return 0, errors.New("invalid Kerberos OriginalContent media type")
	}
	length, err := strconv.ParseUint(originalContent[lengthSeparator+len(";Length="):], 10, 63)
	if err != nil || length > uint64(maxPlaintextSize) {
		return 0, errors.New("invalid Kerberos OriginalContent length")
	}
	return int(length), nil
}

func cutKerberosHeader(line []byte, name string) (string, bool) {
	prefix := "\t" + name + ": "
	if !bytes.HasPrefix(line, []byte(prefix)) {
		return "", false
	}
	return string(line[len(prefix):]), true
}
