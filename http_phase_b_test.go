package winrm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/winrm/soap"
)

type phaseBTrackingBody struct {
	reader     io.Reader
	closeCount int
	closeErr   error
}

func (body *phaseBTrackingBody) Read(buffer []byte) (int, error) {
	return body.reader.Read(buffer)
}

func (body *phaseBTrackingBody) Close() error {
	body.closeCount++
	return body.closeErr
}

type phaseBPartialErrorReader struct {
	data []byte
	err  error
}

type phaseBCloseIdleTransport struct {
	closeCount int
}

func (transport *phaseBCloseIdleTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("unexpected round trip")
}

func (transport *phaseBCloseIdleTransport) CloseIdleConnections() {
	transport.closeCount++
}

func (reader *phaseBPartialErrorReader) Read(buffer []byte) (int, error) {
	if len(reader.data) == 0 {
		return 0, reader.err
	}
	count := copy(buffer, reader.data)
	reader.data = reader.data[count:]
	return count, nil
}

func TestClientRequestRejectsSOAPHTTPError(t *testing.T) {
	responseBody := &phaseBTrackingBody{reader: strings.NewReader("<fault/>")}
	transport := clientRequest{transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Status:     "500 Internal Server Error",
			Header:     http.Header{"Content-Type": {soapXML}},
			Body:       responseBody,
			Request:    request,
		}, nil
	})}
	client := &Client{url: "http://server.example.test/wsman", Parameters: *DefaultParameters}
	request := NewOpenShellRequest(client.url, &client.Parameters)
	defer request.Free()

	if _, err := transport.PostContext(context.Background(), client, request); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("PostContext error = %v, want HTTP 500 error", err)
	} else if strings.Contains(err.Error(), "<fault/>") {
		t.Fatalf("PostContext error exposed SOAP body: %v", err)
	}
	if responseBody.closeCount != 1 {
		t.Fatalf("response body close count = %d, want 1", responseBody.closeCount)
	}
}

func TestReadSOAPResponseSemantics(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		contentType string
		body        string
		want        string
		wantError   string
	}{
		{name: "OK SOAP", status: http.StatusOK, contentType: soapXML + "; charset=UTF-8", body: "<ok/>", want: "<ok/>"},
		{name: "unauthorized SOAP", status: http.StatusUnauthorized, contentType: soapXML, body: "<fault/>", wantError: "status 401"},
		{name: "server error SOAP", status: http.StatusInternalServerError, contentType: soapXML, body: "<fault/>", wantError: "status 500"},
		{name: "OK non SOAP", status: http.StatusOK, contentType: "text/plain", body: "nope", wantError: "invalid SOAP content type"},
		{name: "unauthorized non SOAP", status: http.StatusUnauthorized, contentType: "text/plain", body: "nope", wantError: "status 401"},
		{name: "disguised MIME", status: http.StatusOK, contentType: "text/plain; note=application/soap+xml", body: "nope", wantError: "invalid SOAP content type"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := &phaseBTrackingBody{reader: strings.NewReader(test.body)}
			response := &http.Response{
				StatusCode: test.status,
				Header:     http.Header{"Content-Type": {test.contentType}},
				Body:       body,
			}
			result, err := readSOAPResponse(response, 64)
			if result != test.want {
				t.Fatalf("response = %q, want %q", result, test.want)
			}
			if test.wantError == "" && err != nil || test.wantError != "" && (err == nil || !strings.Contains(err.Error(), test.wantError)) {
				t.Fatalf("error = %v, want substring %q", err, test.wantError)
			}
			if body.closeCount != 1 {
				t.Fatalf("close count = %d, want 1", body.closeCount)
			}
		})
	}
}

func TestReadSOAPResponseBoundsConsumption(t *testing.T) {
	reader := &strings.Reader{}
	*reader = *strings.NewReader("123456789")
	body := &phaseBTrackingBody{reader: reader}
	response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {soapXML}}, Body: body}

	_, err := readSOAPResponse(response, 4)
	if err == nil || !strings.Contains(err.Error(), "exceeds limit 4") {
		t.Fatalf("error = %v, want size limit error", err)
	}
	if consumed := 9 - reader.Len(); consumed != 5 {
		t.Fatalf("consumed bytes = %d, want limit+1 (5)", consumed)
	}
	if body.closeCount != 1 {
		t.Fatalf("close count = %d, want 1", body.closeCount)
	}
}

func TestReadSOAPResponseRejectsInvalidMIMEWithoutReading(t *testing.T) {
	reader := strings.NewReader("synthetic response payload")
	body := &phaseBTrackingBody{reader: reader}
	response := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"text/plain; note=application/soap+xml"}},
		Body:       body,
	}

	_, err := readSOAPResponse(response, 64)
	if err == nil || !strings.Contains(err.Error(), "invalid SOAP content type") {
		t.Fatalf("error = %v, want invalid MIME error", err)
	}
	if reader.Len() != len("synthetic response payload") {
		t.Fatalf("invalid MIME body was read; %d bytes remain", reader.Len())
	}
	if body.closeCount != 1 {
		t.Fatalf("close count = %d, want 1", body.closeCount)
	}
}

func TestReadSOAPResponsePreservesReadAndCloseErrors(t *testing.T) {
	readErr := errors.New("synthetic read failure")
	closeErr := errors.New("synthetic close failure")
	body := &phaseBTrackingBody{
		reader:   &phaseBPartialErrorReader{data: []byte("partial"), err: readErr},
		closeErr: closeErr,
	}
	response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {soapXML}}, Body: body}

	_, err := readSOAPResponse(response, 64)
	if !errors.Is(err, readErr) || !errors.Is(err, closeErr) {
		t.Fatalf("error = %v, want joined read and close errors", err)
	}
	if body.closeCount != 1 {
		t.Fatalf("close count = %d, want 1", body.closeCount)
	}
}

func TestReadSOAPResponseReturnsCloseErrorAfterSuccess(t *testing.T) {
	closeErr := errors.New("synthetic close failure")
	body := &phaseBTrackingBody{reader: strings.NewReader("<ok/>"), closeErr: closeErr}
	response := &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {soapXML}}, Body: body}

	result, err := readSOAPResponse(response, 64)
	if result != "<ok/>" || !errors.Is(err, closeErr) {
		t.Fatalf("response = %q, error = %v, want body and close error", result, err)
	}
}

func TestHTTPDebugDoesNotChangeBoundedResponseSemantics(t *testing.T) {
	previousEnabled := HTTPDebugEnabled()
	previousUnsafe := httpDebugUnsafe.Load()
	t.Cleanup(func() {
		SetHTTPDebug(previousEnabled)
		SetHTTPDebugUnsafe(previousUnsafe)
	})
	t.Setenv("OPSCTL_DEBUG_WINRM_UNSAFE", "")
	SetHTTPDebugUnsafe(false)

	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			SetHTTPDebug(enabled)
			reader := strings.NewReader("123456789")
			body := &phaseBTrackingBody{reader: reader}
			response := &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     http.Header{"Content-Type": {soapXML}},
				Body:       body,
			}
			output := captureDebugStderr(t, func() {
				debugHTTPRoundTrip(nil, response, nil)
				_, err := readSOAPResponse(response, 4)
				if err == nil || !strings.Contains(err.Error(), "exceeds limit 4") {
					t.Fatalf("error = %v, want size limit error", err)
				}
			})
			if consumed := 9 - reader.Len(); consumed != 5 {
				t.Fatalf("consumed bytes = %d, want limit+1 (5)", consumed)
			}
			if body.closeCount != 1 {
				t.Fatalf("close count = %d, want 1", body.closeCount)
			}
			if enabled && !strings.Contains(output, "response-body-bytes=5") {
				t.Fatalf("debug output omitted authoritative byte count: %s", output)
			}
			if !enabled && output != "" {
				t.Fatalf("disabled debug output = %q, want empty", output)
			}
		})
	}
}

func TestHTTPDebugPreservesPartialReadError(t *testing.T) {
	previousEnabled := HTTPDebugEnabled()
	previousUnsafe := httpDebugUnsafe.Load()
	t.Cleanup(func() {
		SetHTTPDebug(previousEnabled)
		SetHTTPDebugUnsafe(previousUnsafe)
	})
	t.Setenv("OPSCTL_DEBUG_WINRM_UNSAFE", "")
	SetHTTPDebugUnsafe(false)
	readErr := errors.New("synthetic read failure")

	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			SetHTTPDebug(enabled)
			body := &phaseBTrackingBody{reader: &phaseBPartialErrorReader{data: []byte("partial"), err: readErr}}
			response := &http.Response{
				StatusCode: http.StatusOK,
				Status:     "200 OK",
				Header:     http.Header{"Content-Type": {soapXML}},
				Body:       body,
			}
			output := captureDebugStderr(t, func() {
				debugHTTPRoundTrip(nil, response, nil)
				_, err := readSOAPResponse(response, 64)
				if !errors.Is(err, readErr) {
					t.Fatalf("error = %v, want read failure", err)
				}
			})
			if body.closeCount != 1 {
				t.Fatalf("close count = %d, want 1", body.closeCount)
			}
			if enabled && (!strings.Contains(output, "response-body-bytes=7") || strings.Contains(output, readErr.Error())) {
				t.Fatalf("safe debug output did not preserve/redact partial read result: %s", output)
			}
		})
	}
}

func TestClientAuthRequestHonorsCanceledContext(t *testing.T) {
	var requestContext context.Context
	transport := ClientAuthRequest{transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requestContext = request.Context()
		return nil, request.Context().Err()
	})}
	client := &Client{url: "http://server.example.test/wsman", Parameters: *DefaultParameters}
	request := NewOpenShellRequest(client.url, &client.Parameters)
	defer request.Free()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := transport.PostContext(ctx, client, request)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context canceled", err)
	}
	if requestContext != ctx {
		t.Fatal("certificate transport did not propagate the caller context")
	}
}

func TestBuiltInTransportsApplyWholeResponseTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", soapXML)
		response.WriteHeader(http.StatusOK)
		response.(http.Flusher).Flush()
		<-request.Context().Done()
	}))
	defer server.Close()

	tests := []struct {
		name string
		post func(context.Context, *Client, *soap.SoapMessage) (string, error)
	}{
		{
			name: "default",
			post: clientRequest{transport: http.DefaultTransport, timeout: 25 * time.Millisecond}.PostContext,
		},
		{
			name: "certificate",
			post: ClientAuthRequest{transport: http.DefaultTransport, timeout: 25 * time.Millisecond}.PostContext,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parameters := *DefaultParameters
			client := &Client{url: server.URL, Parameters: parameters}
			request := NewOpenShellRequest(client.url, &client.Parameters)
			defer request.Free()
			started := time.Now()
			_, err := test.post(context.Background(), client, request)
			if err == nil || !strings.Contains(err.Error(), "Client.Timeout") {
				t.Fatalf("error = %v, want whole-response timeout", err)
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("timeout returned after %s, want under 1s", elapsed)
			}
		})
	}
}

func TestBuiltInTransportsCloseIdleConnections(t *testing.T) {
	defaultRoundTripper := &phaseBCloseIdleTransport{}
	defaultTransport := &clientRequest{transport: defaultRoundTripper}
	if err := defaultTransport.Close(); err != nil {
		t.Fatal(err)
	}
	if defaultRoundTripper.closeCount != 1 {
		t.Fatalf("default close count = %d, want 1", defaultRoundTripper.closeCount)
	}

	certificateRoundTripper := &phaseBCloseIdleTransport{}
	certificateTransport := &ClientAuthRequest{transport: certificateRoundTripper}
	client := &Client{http: certificateTransport}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if certificateRoundTripper.closeCount != 1 {
		t.Fatalf("certificate close count = %d, want 1", certificateRoundTripper.closeCount)
	}
}
