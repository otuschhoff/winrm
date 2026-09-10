package winrm

import (
	"io"
	"net/http"
	"sync"
	"testing"
)

type trackingEncryptionResponseBody struct {
	read   bool
	closed bool
}

func (body *trackingEncryptionResponseBody) Read(buffer []byte) (int, error) {
	body.read = true
	return copy(buffer, "<soap/>"), io.EOF
}

func (body *trackingEncryptionResponseBody) Close() error {
	body.closed = true
	return nil
}

func TestEncryptionBootstrapFailureDoesNotRetryPlaintext(t *testing.T) {
	var mutex sync.Mutex
	var requestBodies []string
	server, host, port, err := StartTestServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Errorf("read request body: %v", readErr)
		}
		mutex.Lock()
		requestBodies = append(requestBodies, string(body))
		mutex.Unlock()
		response.Header().Set("Content-Type", soapXML)
		response.WriteHeader(http.StatusInternalServerError)
		_, _ = response.Write([]byte("<fault/>"))
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	encryption, err := NewEncryption("ntlm")
	if err != nil {
		t.Fatal(err)
	}
	parameters := *DefaultParameters
	parameters.TransportDecorator = func() Transporter { return encryption }
	client, err := NewClientWithParameters(NewEndpoint(host, port, false, false, nil, nil, nil, 0), "test", "test", &parameters)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if _, err := client.CreateShell(); err == nil {
		t.Fatal("encrypted NTLM bootstrap failure unexpectedly succeeded")
	}
	mutex.Lock()
	defer mutex.Unlock()
	if len(requestBodies) != 1 {
		t.Fatalf("request count = %d, want one bootstrap request", len(requestBodies))
	}
	if requestBodies[0] != "" {
		t.Fatalf("bootstrap failure sent plaintext SOAP: %q", requestBodies[0])
	}
}

func TestEncryptionRejectsUnexpectedPlaintextResponse(t *testing.T) {
	encryption, err := NewEncryption("ntlm")
	if err != nil {
		t.Fatal(err)
	}
	body := &trackingEncryptionResponseBody{}
	response := &http.Response{
		Header: http.Header{"Content-Type": {soapXML}},
		Body:   body,
	}
	if _, err := encryption.ParseEncryptedResponse(response); err == nil {
		t.Fatal("encrypted NTLM transport accepted a plaintext response")
	}
	if body.read || !body.closed {
		t.Fatalf("plaintext response body read=%t closed=%t, want false/true", body.read, body.closed)
	}
}
