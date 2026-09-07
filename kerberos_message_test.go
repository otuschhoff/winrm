package winrm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

func TestKerberosMessageFramerRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		keyType int32
		key     []byte
		message []byte
	}{
		{name: "zero", keyType: 17, key: []byte("0123456789abcdef")},
		{name: "small", keyType: 18, key: []byte("0123456789abcdef0123456789abcdef"), message: []byte("<s:Envelope/>")},
		{name: "Unicode byte length", keyType: 17, key: []byte("0123456789abcdef"), message: []byte("日本語 €")},
		{name: "boundary text", keyType: 18, key: []byte("0123456789abcdef0123456789abcdef"), message: []byte("--Encrypted Boundary\r\n")},
		{name: "large", keyType: 18, key: []byte("0123456789abcdef0123456789abcdef"), message: bytes.Repeat([]byte("payload"), 20000)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			initiator, acceptor := newTestKerberosGSSPair(t, test.keyType, test.key, true)
			framer, err := newKerberosMessageFramer(max(1, len(test.message)))
			if err != nil {
				t.Fatal(err)
			}
			contentType, body, err := framer.seal(test.message, initiator)
			if err != nil {
				t.Fatal(err)
			}
			message, err := framer.open(contentType, body, acceptor)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(message, test.message) {
				t.Fatalf("message length %d, want %d", len(message), len(test.message))
			}
		})
	}
}

func TestKerberosMessageFramerGoldenFixture(t *testing.T) {
	header := []byte{5, 4, 6, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7}
	payload := []byte("cipher--Encrypted Boundary\r\ntext")
	context := &fixtureKerberosGSSContext{header: header, payload: payload, message: []byte("hello")}
	adapter, err := newKerberosGSSAdapter(context)
	if err != nil {
		t.Fatal(err)
	}
	framer, err := newKerberosMessageFramer(5)
	if err != nil {
		t.Fatal(err)
	}
	contentType, body, err := framer.seal(context.message, adapter)
	if err != nil {
		t.Fatal(err)
	}

	var stream bytes.Buffer
	binary.Write(&stream, binary.LittleEndian, uint32(kerberosGSSHeaderLength))
	stream.Write(header)
	stream.Write(payload)
	want := fmt.Sprintf("--Encrypted Boundary\r\n\tContent-Type: %s\r\n\tOriginalContent: type=%s;Length=5\r\n--Encrypted Boundary\r\n\tContent-Type: application/octet-stream\r\n", kerberosEncryptedProtocol, kerberosSOAPContentType)
	wantBody := append([]byte(want), stream.Bytes()...)
	wantBody = append(wantBody, []byte("--Encrypted Boundary--\r\n")...)
	if contentType != `multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"` {
		t.Fatalf("content type = %q", contentType)
	}
	if !bytes.Equal(body, wantBody) {
		t.Fatalf("body differs from golden fixture")
	}
	message, err := framer.open(contentType, body, adapter)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(message, context.message) {
		t.Fatalf("message = %q", message)
	}
}

func TestKerberosMessageFramerRejectsMalformedInput(t *testing.T) {
	framer, err := newKerberosMessageFramer(32)
	if err != nil {
		t.Fatal(err)
	}
	context := &fixtureKerberosGSSContext{
		header: fixtureKerberosGSSHeader(), payload: []byte("ciphertext"), message: []byte("hello"),
	}
	adapter, _ := newKerberosGSSAdapter(context)
	contentType, validBody, err := framer.seal(context.message, adapter)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name        string
		contentType string
		mutate      func([]byte) []byte
	}{
		{name: "malformed content type", contentType: "not a media type"},
		{name: "wrong media type", contentType: strings.Replace(contentType, "multipart/encrypted", "text/plain", 1)},
		{name: "wrong protocol", contentType: strings.Replace(contentType, kerberosEncryptedProtocol, "application/wrong", 1)},
		{name: "missing boundary parameter", contentType: `multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted"`},
		{name: "oversized boundary", contentType: `multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="` + strings.Repeat("x", 71) + `"`},
		{name: "control boundary", contentType: "multipart/encrypted;protocol=\"application/HTTP-SPNEGO-session-encrypted\";boundary=\"bad\tboundary\""},
		{name: "trailing-space boundary", contentType: `multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="bad "`},
		{name: "malformed first boundary", contentType: contentType, mutate: replaceBytes([]byte("--Encrypted Boundary\r\n"), []byte("--Wrong\r\n"), 1)},
		{name: "malformed second boundary", contentType: contentType, mutate: replaceBytes([]byte("--Encrypted Boundary\r\n\tContent-Type: application/octet-stream"), []byte("--Wrong\r\n\tContent-Type: application/octet-stream"), 1)},
		{name: "missing terminal boundary", contentType: contentType, mutate: func(body []byte) []byte { return body[:len(body)-len("--Encrypted Boundary--\r\n")] }},
		{name: "wrong original media type", contentType: contentType, mutate: replaceBytes([]byte(kerberosSOAPContentType), []byte("text/plain;charset=UTF-8"), 1)},
		{name: "extra original media parameter", contentType: contentType, mutate: replaceBytes([]byte(kerberosSOAPContentType), []byte(kerberosSOAPContentType+";boundary=attack"), 1)},
		{name: "wrong declared length", contentType: contentType, mutate: replaceBytes([]byte("Length=5"), []byte("Length=6"), 1)},
		{name: "oversized declared length", contentType: contentType, mutate: replaceBytes([]byte("Length=5"), []byte("Length=999"), 1)},
		{name: "negative declared length", contentType: contentType, mutate: replaceBytes([]byte("Length=5"), []byte("Length=-1"), 1)},
		{name: "non-numeric declared length", contentType: contentType, mutate: replaceBytes([]byte("Length=5"), []byte("Length=nope"), 1)},
		{name: "empty declared length", contentType: contentType, mutate: replaceBytes([]byte("Length=5"), []byte("Length="), 1)},
		{name: "duplicate declared length", contentType: contentType, mutate: replaceBytes([]byte("Length=5"), []byte("Length=5;Length=5"), 1)},
		{name: "truncated stream", contentType: contentType, mutate: truncateEncryptedStream},
		{name: "oversized security header", contentType: contentType, mutate: setSecurityHeaderLength(17)},
		{name: "zero security header", contentType: contentType, mutate: setSecurityHeaderLength(0)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := append([]byte(nil), validBody...)
			if test.mutate != nil {
				body = test.mutate(body)
			}
			if _, err := framer.open(test.contentType, body, adapter); err == nil {
				t.Fatal("malformed message was accepted")
			}
		})
	}
}

func TestKerberosMessageFramerEnforcesSizeLimits(t *testing.T) {
	framer, err := newKerberosMessageFramer(4)
	if err != nil {
		t.Fatal(err)
	}
	context := &fixtureKerberosGSSContext{header: fixtureKerberosGSSHeader(), payload: []byte("ciphertext")}
	adapter, _ := newKerberosGSSAdapter(context)
	if _, _, err := framer.seal([]byte("12345"), adapter); err == nil {
		t.Fatal("oversized plaintext was accepted")
	}
	context.payload = bytes.Repeat([]byte("x"), 4+kerberosMaxWrapOverhead)
	if _, _, err := framer.seal([]byte("1234"), adapter); err == nil {
		t.Fatal("oversized wrapped token was accepted")
	}
	body := bytes.Repeat([]byte("x"), 4+kerberosMaxWrapOverhead+kerberosMaxMetadataSize+1)
	if _, err := framer.open(`multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"`, body, adapter); err == nil {
		t.Fatal("oversized response was accepted")
	}
	if _, err := newKerberosMessageFramer(0); err == nil {
		t.Fatal("zero size limit was accepted")
	}
}

type fixtureKerberosGSSContext struct {
	header, payload, message []byte
}

func fixtureKerberosGSSHeader() []byte {
	return []byte{0x05, 0x04, 0x02, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
}

func (context *fixtureKerberosGSSContext) Wrap(message []byte, confidential bool) ([]byte, error) {
	if !confidential {
		return nil, fmt.Errorf("confidentiality was not requested")
	}
	context.message = append([]byte(nil), message...)
	return append(append([]byte(nil), context.header...), context.payload...), nil
}

func (context *fixtureKerberosGSSContext) Unwrap(token []byte) ([]byte, bool, error) {
	want := append(append([]byte(nil), context.header...), context.payload...)
	if !bytes.Equal(token, want) {
		return nil, false, fmt.Errorf("wrapped token mismatch")
	}
	return append([]byte(nil), context.message...), true, nil
}

func replaceBytes(old, replacement []byte, count int) func([]byte) []byte {
	return func(body []byte) []byte { return bytes.Replace(body, old, replacement, count) }
}

func truncateEncryptedStream(body []byte) []byte {
	prefix := []byte("\tContent-Type: application/octet-stream\r\n")
	start := bytes.Index(body, prefix) + len(prefix)
	terminal := []byte("--Encrypted Boundary--\r\n")
	return append(append([]byte(nil), body[:start+4+kerberosGSSHeaderLength]...), terminal...)
}

func setSecurityHeaderLength(length uint32) func([]byte) []byte {
	return func(body []byte) []byte {
		prefix := []byte("\tContent-Type: application/octet-stream\r\n")
		start := bytes.Index(body, prefix) + len(prefix)
		binary.LittleEndian.PutUint32(body[start:start+4], length)
		return body
	}
}

func FuzzKerberosMessageFramerOpen(f *testing.F) {
	context := &fixtureKerberosGSSContext{header: fixtureKerberosGSSHeader(), payload: []byte("ciphertext"), message: []byte("hello")}
	adapter, _ := newKerberosGSSAdapter(context)
	framer, _ := newKerberosMessageFramer(64)
	contentType, body, err := framer.seal(context.message, adapter)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(contentType, body)
	f.Add("not a media type", []byte("invalid"))
	f.Fuzz(func(t *testing.T, fuzzContentType string, fuzzBody []byte) {
		fuzzContext := &fixtureKerberosGSSContext{header: fixtureKerberosGSSHeader(), payload: []byte("ciphertext"), message: []byte("hello")}
		fuzzAdapter, _ := newKerberosGSSAdapter(fuzzContext)
		_, _ = framer.open(fuzzContentType, fuzzBody, fuzzAdapter)
	})
}
