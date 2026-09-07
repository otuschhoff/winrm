package winrm

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/gssapi"
)

func TestKerberosEncryptedShellLifecycle(t *testing.T) {
	initiator, acceptor := newTestKerberosGSSPair(t, 18, []byte("0123456789abcdef0123456789abcdef"), true)
	framer, err := newKerberosMessageFramer(DefaultParameters.EnvelopeSize)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var actions []string
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		requestCount++
		if requestCount == 1 {
			if request.Body != nil {
				body, readErr := io.ReadAll(request.Body)
				if readErr != nil || len(body) != 0 {
					t.Errorf("bootstrap body = %q, %v", body, readErr)
				}
			}
			writer.WriteHeader(http.StatusOK)
			return
		}
		body, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Error(readErr)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		plaintext, openErr := framer.open(request.Header.Get("Content-Type"), body, acceptor)
		if openErr != nil {
			t.Error(openErr)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		action, response := encryptedLifecycleResponse(string(plaintext))
		actions = append(actions, action)
		contentType, responseBody, sealErr := framer.seal([]byte(response), acceptor)
		if sealErr != nil {
			t.Error(sealErr)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", contentType)
		_, _ = writer.Write(responseBody)
	}))
	defer server.Close()

	session := &kerberosSession{
		state: kerberosSessionCredentialsReady, endpoint: server.URL, spn: "HTTP/host.example.test",
		requireEncryption: true, httpClient: server.Client(),
	}
	session.newNegotiator = func(client *http.Client) kerberosNegotiator {
		return &fixtureKerberosNegotiator{client: client, rounds: 1, context: initiator.context.(gssapi.Context)}
	}
	transport := &ClientKerberos{session: session}
	client := &Client{Parameters: *DefaultParameters, url: server.URL, http: transport}
	stdout, stderr, exitCode, err := client.RunCmdWithContext(context.Background(), "hostname")
	if err != nil {
		t.Fatal(err)
	}
	if exitCode != 0 || stdout != "host.example.test\n" || stderr != "" {
		t.Fatalf("command result = stdout %q, stderr %q, exit %d", stdout, stderr, exitCode)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	wantActions := []string{"create", "command", "receive", "signal", "delete"}
	if strings.Join(actions, ",") != strings.Join(wantActions, ",") {
		t.Fatalf("actions = %q, want %q", actions, wantActions)
	}
}

func encryptedLifecycleResponse(request string) (string, string) {
	switch {
	case strings.Contains(request, "transfer/Create"):
		return "create", createShellResponse
	case strings.Contains(request, "shell/Command"):
		return "command", executeCommandResponse
	case strings.Contains(request, "shell/Receive"):
		return "receive", `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Body><rsp:ReceiveResponse><rsp:Stream Name="stdout">aG9zdC5leGFtcGxlLnRlc3QK</rsp:Stream><rsp:CommandState State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done"><rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState></rsp:ReceiveResponse></s:Body></s:Envelope>`
	case strings.Contains(request, "shell/Signal"):
		return "signal", `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"/>`
	case strings.Contains(request, "transfer/Delete"):
		return "delete", `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"/>`
	default:
		return "unknown", `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"/>`
	}
}
