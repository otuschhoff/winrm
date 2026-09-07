package winrm

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/gssapi"
)

func TestKerberosEncryptedConcurrentCommandsReuseContext(t *testing.T) {
	initiator, acceptor := newTestKerberosGSSPair(t, 18, []byte("0123456789abcdef0123456789abcdef"), true)
	framer, err := newKerberosMessageFramer(DefaultParameters.EnvelopeSize)
	if err != nil {
		t.Fatal(err)
	}
	const commandCount = 8
	var mu sync.Mutex
	bootstrapCount := 0
	receiveCount := 0
	actions := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if bootstrapCount == 0 {
			bootstrapCount++
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
		action := kerberosPhase4Action(string(plaintext))
		actions[action]++
		response := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"/>`
		switch action {
		case "create":
			response = createShellResponse
		case "command":
			response = executeCommandResponse
		case "receive":
			receiveCount++
			response = kerberosPhase4Receive([]byte(fmt.Sprintf("result-%d", receiveCount)), nil, true, 0)
		}
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
	client := &Client{Parameters: *DefaultParameters, url: server.URL, http: &ClientKerberos{session: session}}

	results := make(chan string, commandCount)
	errors := make(chan error, commandCount)
	var wait sync.WaitGroup
	for index := 0; index < commandCount; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			stdout, stderr, exitCode, runErr := client.RunCmdWithContext(context.Background(), "hostname")
			if runErr != nil || stderr != "" || exitCode != 0 {
				errors <- fmt.Errorf("result = stdout %q, stderr %q, exit %d: %w", stdout, stderr, exitCode, runErr)
				return
			}
			results <- stdout
		}()
	}
	wait.Wait()
	close(results)
	close(errors)
	for runErr := range errors {
		t.Error(runErr)
	}
	unique := map[string]bool{}
	for result := range results {
		unique[result] = true
	}
	if len(unique) != commandCount {
		t.Fatalf("unique command results = %d, want %d", len(unique), commandCount)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if bootstrapCount != 1 || actions["create"] != commandCount || actions["command"] != commandCount || actions["receive"] != commandCount {
		t.Fatalf("bootstrap/actions = %d/%#v", bootstrapCount, actions)
	}
}

func TestKerberosEncryptedSequentialCommandParity(t *testing.T) {
	initiator, acceptor := newTestKerberosGSSPair(t, 18, []byte("0123456789abcdef0123456789abcdef"), true)
	framer, err := newKerberosMessageFramer(DefaultParameters.EnvelopeSize)
	if err != nil {
		t.Fatal(err)
	}
	largeOutput := "日本語 €\r\n" + strings.Repeat("x", 180000)
	const commandError = "command error Ω\r\n"
	const powershellOutput = "PowerShell 日本語 €\r\n"
	const stdinValue = "stdin 日本語 €"

	var mu sync.Mutex
	bootstrapCount := 0
	commandIndex := -1
	receiveCounts := map[int]int{}
	stdinData := ""
	stdinEOF := false
	powershellObserved := false
	actions := map[string]int{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if bootstrapCount == 0 {
			bootstrapCount++
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
		message := string(plaintext)
		action := kerberosPhase4Action(message)
		actions[action]++
		response := `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"/>`
		switch action {
		case "create":
			response = createShellResponse
		case "command":
			commandIndex++
			powershellObserved = powershellObserved || strings.Contains(message, "powershell.exe -EncodedCommand")
			response = executeCommandResponse
		case "send":
			if strings.Contains(message, base64.StdEncoding.EncodeToString([]byte(stdinValue))) {
				stdinData += stdinValue
			}
			stdinEOF = stdinEOF || strings.Contains(message, `End="true"`)
		case "receive":
			receiveCounts[commandIndex]++
			switch commandIndex {
			case 0:
				if receiveCounts[0] == 1 {
					response = kerberosPhase4Receive([]byte(largeOutput[:90000]), []byte(commandError), false, 0)
				} else {
					response = kerberosPhase4Receive([]byte(largeOutput[90000:]), nil, true, 23)
				}
			case 1:
				response = kerberosPhase4Receive([]byte(powershellOutput), nil, true, 0)
			case 2:
				if stdinEOF {
					response = kerberosPhase4Receive([]byte(stdinData), nil, true, 0)
				} else {
					response = kerberosPhase4Receive(nil, nil, false, 0)
				}
			default:
				t.Errorf("unexpected command index %d", commandIndex)
			}
		}
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

	stdout, stderr, exitCode, err := client.RunCmdWithContext(context.Background(), "phase4-cmd")
	if err != nil || stdout != largeOutput || stderr != commandError || exitCode != 23 {
		t.Fatalf("cmd result = stdout length %d, stderr %q, exit %d, error %v", len(stdout), stderr, exitCode, err)
	}
	stdout, stderr, exitCode, err = client.RunPSWithContext(context.Background(), "Write-Output 'PowerShell 日本語 €'")
	if err != nil || stdout != powershellOutput || stderr != "" || exitCode != 0 {
		t.Fatalf("PowerShell result = stdout %q, stderr %q, exit %d, error %v", stdout, stderr, exitCode, err)
	}
	stdout, stderr, exitCode, err = client.RunWithContextWithString(context.Background(), "phase4-stdin", stdinValue)
	if err != nil || stdout != stdinValue || stderr != "" || exitCode != 0 {
		t.Fatalf("stdin result = stdout %q, stderr %q, exit %d, error %v", stdout, stderr, exitCode, err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if bootstrapCount != 1 {
		t.Fatalf("bootstrap requests = %d, want 1", bootstrapCount)
	}
	if !powershellObserved {
		t.Fatal("PowerShell command was not encoded through the encrypted command path")
	}
	if stdinData != stdinValue || !stdinEOF {
		t.Fatalf("stdin = %q, EOF %t", stdinData, stdinEOF)
	}
	if receiveCounts[0] != 2 {
		t.Fatalf("large-output Receive requests = %d, want 2", receiveCounts[0])
	}
	if actions["create"] != 3 || actions["command"] != 3 || actions["signal"] != 3 || actions["delete"] != 3 {
		t.Fatalf("lifecycle actions = %#v", actions)
	}
}

func kerberosPhase4Action(message string) string {
	switch {
	case strings.Contains(message, "transfer/Create"):
		return "create"
	case strings.Contains(message, "shell/Command"):
		return "command"
	case strings.Contains(message, "shell/Receive"):
		return "receive"
	case strings.Contains(message, "shell/Send"):
		return "send"
	case strings.Contains(message, "shell/Signal"):
		return "signal"
	case strings.Contains(message, "transfer/Delete"):
		return "delete"
	default:
		return "unknown"
	}
}

func kerberosPhase4Receive(stdout, stderr []byte, done bool, exitCode int) string {
	state := "Running"
	exit := ""
	if done {
		state = "Done"
		exit = fmt.Sprintf("<rsp:ExitCode>%d</rsp:ExitCode>", exitCode)
	}
	stream := ""
	if len(stdout) > 0 {
		stream += `<rsp:Stream Name="stdout">` + base64.StdEncoding.EncodeToString(stdout) + `</rsp:Stream>`
	}
	if len(stderr) > 0 {
		stream += `<rsp:Stream Name="stderr">` + base64.StdEncoding.EncodeToString(stderr) + `</rsp:Stream>`
	}
	return `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell"><s:Body><rsp:ReceiveResponse>` + stream + `<rsp:CommandState State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/` + state + `">` + exit + `</rsp:CommandState></rsp:ReceiveResponse></s:Body></s:Envelope>`
}
