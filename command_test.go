package winrm

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ChrisTrenkamp/goxpath/tree/xmltree"
	"github.com/otuschhoff/winrm/soap"
	. "gopkg.in/check.v1"
)

func (s *WinRMSuite) TestExecuteCommand(c *C) {
	endpoint := NewEndpoint("localhost", 5985, false, false, nil, nil, nil, 0)
	client, err := NewClient(endpoint, "Administrator", "v3r1S3cre7")
	c.Assert(err, IsNil)

	shell := &Shell{client: client, id: "67A74734-DD32-4F10-89DE-49A060483810"}
	count := 0
	r := Requester{}
	r.http = func(client *Client, message *soap.SoapMessage) (string, error) {
		switch count {
		case 0:
			{
				c.Assert(message.String(), Contains, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command")
				count = 1
				return executeCommandResponse, nil
			}
		case 1:
			{
				c.Assert(message.String(), Contains, "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive")
				count = 2
				return outputResponse, nil
			}
		default:
			{
				return doneCommandResponse, nil
			}
		}
	}
	client.http = &r
	command, _ := shell.Execute("ipconfig /all")
	var stdout, stderr bytes.Buffer
	var wg sync.WaitGroup
	f := func(b *bytes.Buffer, r *commandReader) {
		wg.Add(1)
		defer wg.Done()
		_, _ = io.Copy(b, r)
	}
	go f(&stdout, command.Stdout)
	go f(&stderr, command.Stderr)
	command.Wait()
	wg.Wait()
	c.Assert(stdout.String(), Equals, "That's all folks!!!")
	c.Assert(stderr.String(), Equals, "This is stderr, I'm pretty sure!")
}

func (s *WinRMSuite) TestStdinCommand(c *C) {
	endpoint := NewEndpoint("localhost", 5985, false, false, nil, nil, nil, 0)
	client, err := NewClient(endpoint, "Administrator", "v3r1S3cre7")
	c.Assert(err, IsNil)

	shell := &Shell{
		client: client,
		id:     "67A74734-DD32-4F10-89DE-49A060483810",
	}

	count := 0
	r := Requester{}
	r.http = func(client *Client, message *soap.SoapMessage) (string, error) {
		if strings.Contains(message.String(), "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send") {
			c.Assert(message.String(), Contains, "c3RhbmRhcmQgaW5wdXQ=")
			return "", nil
		}
		if strings.Contains(message.String(), "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command") {
			return executeCommandResponse, nil
		} else if count != 1 && strings.Contains(message.String(), "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive") {
			count = 1
			return outputResponse, nil
		} else {
			return doneCommandResponse, nil
		}
	}
	client.http = &r
	command, _ := shell.Execute("ipconfig /all")
	_, _ = command.Stdin.Write([]byte("standard input"))
	// slurp output from command
	var outWriter, errWriter bytes.Buffer
	go func() { _, _ = io.Copy(&outWriter, command.Stdout) }()
	go func() { _, _ = io.Copy(&errWriter, command.Stderr) }()
	command.Wait()
}

func (s *WinRMSuite) TestStdinWriteClose(c *C) {
	endpoint := NewEndpoint("localhost", 5985, false, false, nil, nil, nil, 0)
	client, err := NewClient(endpoint, "Administrator", "v3r1S3cre7")
	c.Assert(err, IsNil)
	client.Parameters.EnvelopeSize = 1400
	shell := &Shell{client: client, id: "SHELLID"}
	command := &Command{client: client, shell: shell, id: "COMMANDID"}
	command.Stdin = &commandWriter{Command: command}

	var requests []string
	r := Requester{}
	r.http = func(client *Client, message *soap.SoapMessage) (string, error) {
		requests = append(requests, message.String())
		return "", nil
	}
	client.http = &r

	payload := []byte(strings.Repeat("123456", 100))
	written, err := command.Stdin.WriteClose(payload)
	c.Assert(err, IsNil)
	c.Assert(written, Equals, len(payload))
	c.Assert(len(requests) > 1, Equals, true)
	for _, request := range requests {
		c.Assert(len(request) <= client.Parameters.EnvelopeSize, Equals, true)
	}
	c.Assert(requests[len(requests)-2], Not(Contains), `End="true"`)
	c.Assert(requests[len(requests)-1], Contains, `End="true"`)
	_, err = command.Stdin.Write([]byte("later"))
	c.Assert(err, Equals, io.ErrClosedPipe)
}

func TestCommandInputEnvelopeSizing(t *testing.T) {
	payload := bytes.Repeat([]byte("input-0123456789"), 400)
	tests := []struct {
		name          string
		assertMaximal bool
		send          func(*commandWriter) (int64, error)
	}{
		{name: "direct WriteClose", assertMaximal: true, send: func(writer *commandWriter) (int64, error) {
			written, err := writer.WriteClose(payload)
			return int64(written), err
		}},
		{name: "strings Reader WriteTo", assertMaximal: true, send: func(writer *commandWriter) (int64, error) {
			written, err := io.Copy(writer, strings.NewReader(string(payload)))
			return written, errors.Join(err, writer.Close())
		}},
		{name: "small buffer io.Copy", send: func(writer *commandWriter) (int64, error) {
			reader := io.LimitReader(bytes.NewReader(payload), int64(len(payload)))
			written, err := io.CopyBuffer(writer, reader, make([]byte, 7))
			return written, errors.Join(err, writer.Close())
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			parameters := *DefaultParameters
			parameters.EnvelopeSize = 2400
			parameters.Locale = strings.Repeat("long-locale-", 8)
			var requests []string
			requester := &Requester{http: func(_ *Client, message *soap.SoapMessage) (string, error) {
				requests = append(requests, message.String())
				return "", nil
			}}
			client := &Client{
				Parameters: parameters,
				url:        "http://host.example.test/wsman?" + strings.Repeat("route", 24),
				http:       requester,
			}
			command := &Command{
				ctx:    context.Background(),
				client: client,
				shell:  &Shell{client: client, id: strings.Repeat("shell-id-", 12)},
				id:     strings.Repeat("command-id-", 12),
			}
			writer := &commandWriter{Command: command}

			written, err := test.send(writer)
			if err != nil || written != int64(len(payload)) {
				t.Fatalf("send = %d, %v; want %d bytes", written, err, len(payload))
			}
			decoded, eofCount := decodeInputRequests(t, requests, parameters.EnvelopeSize)
			if !bytes.Equal(decoded, payload) {
				t.Fatalf("decoded input length = %d, want %d", len(decoded), len(payload))
			}
			if eofCount != 1 {
				t.Fatalf("EOF markers = %d, want 1", eofCount)
			}
			if test.assertMaximal {
				firstChunkLength := firstInputChunkLength(t, requests[0])
				if firstChunkLength >= len(payload) {
					t.Fatal("test payload did not exercise chunking")
				}
				larger := NewSendInputRequest(client.url, command.shell.id, command.id, payload[:firstChunkLength+1], false, &parameters)
				largerSize := len(larger.String())
				larger.Free()
				if largerSize <= parameters.EnvelopeSize {
					t.Fatalf("first chunk was not maximal: one more byte produces size %d within envelope %d", largerSize, parameters.EnvelopeSize)
				}
			}
		})
	}
}

func TestCommandInputEnvelopeEdgeCases(t *testing.T) {
	parameters := *DefaultParameters
	parameters.EnvelopeSize = 1
	requests := 0
	requester := &Requester{http: func(_ *Client, _ *soap.SoapMessage) (string, error) {
		requests++
		return "", nil
	}}
	client := &Client{Parameters: parameters, url: "http://host.example.test/wsman", http: requester}
	command := &Command{ctx: context.Background(), client: client, shell: &Shell{client: client, id: "SHELLID"}, id: "COMMANDID"}
	writer := &commandWriter{Command: command}
	written, err := writer.WriteClose([]byte("input"))
	if err == nil || written != 0 || requests != 0 {
		t.Fatalf("impossible envelope = %d bytes, %v, %d requests; want no partial send", written, err, requests)
	}

	parameters.EnvelopeSize = DefaultParameters.EnvelopeSize
	client.Parameters = parameters
	var captured []string
	requester.http = func(_ *Client, message *soap.SoapMessage) (string, error) {
		captured = append(captured, message.String())
		return "", nil
	}
	writer = &commandWriter{Command: command}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	decoded, eofCount := decodeInputRequests(t, captured, parameters.EnvelopeSize)
	if len(decoded) != 0 || eofCount != 1 || len(captured) != 1 {
		t.Fatalf("empty input = %d decoded bytes, %d EOFs, %d requests", len(decoded), eofCount, len(captured))
	}
}

func firstInputChunkLength(t *testing.T, request string) int {
	t.Helper()
	doc, err := xmltree.ParseXML(strings.NewReader(request))
	if err != nil {
		t.Fatal(err)
	}
	streams, err := xPath(doc, "//rsp:Stream[@Name='stdin']")
	if err != nil || len(streams) != 1 {
		t.Fatalf("stdin streams = %d, %v", len(streams), err)
	}
	chunk, err := base64.StdEncoding.DecodeString(streams[0].ResValue())
	if err != nil {
		t.Fatal(err)
	}
	return len(chunk)
}

func decodeInputRequests(t *testing.T, requests []string, envelopeSize int) ([]byte, int) {
	t.Helper()
	var decoded bytes.Buffer
	eofCount := 0
	for index, request := range requests {
		if len(request) > envelopeSize {
			t.Fatalf("request %d size = %d, exceeds envelope %d", index, len(request), envelopeSize)
		}
		doc, err := xmltree.ParseXML(strings.NewReader(request))
		if err != nil {
			t.Fatal(err)
		}
		streams, err := xPath(doc, "//rsp:Stream[@Name='stdin']")
		if err != nil || len(streams) != 1 {
			t.Fatalf("request %d stdin streams = %d, %v", index, len(streams), err)
		}
		chunk, err := base64.StdEncoding.DecodeString(streams[0].ResValue())
		if err != nil {
			t.Fatal(err)
		}
		decoded.Write(chunk)
		ends, err := xPath(doc, "//rsp:Stream[@Name='stdin']/@End")
		if err != nil {
			t.Fatal(err)
		}
		if len(ends) > 0 {
			eofCount++
			if index != len(requests)-1 {
				t.Fatalf("request %d has EOF before final request", index)
			}
		}
	}
	return decoded.Bytes(), eofCount
}

func (s *WinRMSuite) TestCommandExitCode(c *C) {
	endpoint := NewEndpoint("localhost", 5985, false, false, nil, nil, nil, 0)
	client, err := NewClient(endpoint, "Administrator", "v3r1S3cre7")
	c.Assert(err, IsNil)

	shell := &Shell{
		client: client,
		id:     "67A74734-DD32-4F10-89DE-49A060483810",
	}

	count := 0
	r := Requester{}
	r.http = func(client *Client, message *soap.SoapMessage) (string, error) {
		defer func() { count++ }()
		switch count {
		case 0:
			return executeCommandResponse, nil
		case 1:
			return doneCommandResponse, nil
		default:
			c.Log("Mimicking some observed Windows behavior where only the first 'done' response has the actual exit code and 0 afterwards")
			return doneCommandExitCode0Response, nil
		}
	}
	client.http = &r
	command, _ := shell.Execute("ipconfig /all")

	command.Wait()
	<-time.After(time.Second) // to make the test fail if fetchOutput races to re-set the exit code

	c.Assert(command.ExitCode(), Equals, 123)
}

func (s *WinRMSuite) TestCloseCommandStopsFetch(c *C) {
	endpoint := NewEndpoint("localhost", 5985, false, false, nil, nil, nil, 0)
	client, err := NewClient(endpoint, "Administrator", "v3r1S3cre7")
	c.Assert(err, IsNil)

	shell := &Shell{client: client, id: "67A74734-DD32-4F10-89DE-49A060483810"}

	httpChan := make(chan string)
	r := Requester{}
	r.http = func(client *Client, message *soap.SoapMessage) (string, error) {
		switch {
		case strings.Contains(message.String(), "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive"):
			c.Log("Request for command output received by server")
			r := <-httpChan
			c.Log("Returning command output")
			return r, nil
		case strings.Contains(message.String(), "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command"):
			return executeCommandResponse, nil
		case strings.Contains(message.String(), "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal"):
			c.Log("Signal message received by server")
			return "", nil // response is not used
		default:
			c.Logf("Unexpected message: %s", message)
			return "", nil
		}
	}
	client.http = &r
	command, _ := shell.Execute("ipconfig /all")
	// need to be reading Stdout/Stderr, otherwise, the writes to these are blocking...
	go func() { _, _ = io.ReadAll(command.Stdout) }()
	go func() { _, _ = io.ReadAll(command.Stderr) }()

	httpChan <- outputResponse // wait for command to enter fetch/slurp

	command.Close()

	select {
	case httpChan <- outputResponse: // return to fetch from slurp
		c.Log("Fetch loop 'drained' one last response before realizing that the command is now closed")
	case <-time.After(1 * time.Second):
		c.Log("no poll within one second, fetch may have stopped")
	}

	select {
	case httpChan <- outputResponse:
		c.Log("Fetch loop is still polling after command.Close()")
		c.FailNow()
	case <-time.After(1 * time.Second):
		c.Log("no poll within one second, assuming fetch has stopped")
	}
}

func (s *WinRMSuite) TestConnectionTimeout(c *C) {
	count := 0
	ts, host, port, err := StartTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.Header().Set("Content-Type", "application/soap+xml")
		switch count {
		case 0:
			{
				count = 1
				fmt.Fprintln(w, executeCommandResponse)
			}
		case 1:
			{
				count = 2
				fmt.Fprintln(w, outputResponse)
			}
		default:
			{
				fmt.Fprintln(w, doneCommandResponse)
			}
		}
	}))
	if err != nil {
		c.Error(err)
	}
	defer ts.Close()

	endpoint := NewEndpoint(host, port, false, false, nil, nil, nil, 1*time.Second)
	client, err := NewClient(endpoint, "Administrator", "v3r1S3cre7")
	c.Assert(err, IsNil)

	shell := &Shell{client: client, id: "67A74734-DD32-4F10-89DE-49A060483810"}
	_, err = shell.Execute("ipconfig /all")
	c.Assert(err, ErrorMatches, ".*timeout.*")
}

func (s *WinRMSuite) TestOperationTimeoutSupport(c *C) {
	count := 0
	ts, host, port, err := StartTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/soap+xml")
		switch count {
		case 0:
			{
				count = 1
				fmt.Fprintln(w, executeCommandResponse)
			}
		case 1:
			{
				count = 2
				w.WriteHeader(500)
				fmt.Fprintln(w, operationTimeoutResponse)
			}
		case 2:
			{
				count = 3
				fmt.Fprintln(w, outputResponse)
			}
		default:
			{
				fmt.Fprintln(w, doneCommandResponse)
			}
		}
	}))
	if err != nil {
		c.Error(err)
	}
	defer ts.Close()

	endpoint := NewEndpoint(host, port, false, false, nil, nil, nil, 0)
	client, err := NewClient(endpoint, "Administrator", "v3r1S3cre7")
	c.Assert(err, IsNil)

	shell := &Shell{client: client, id: "67A74734-DD32-4F10-89DE-49A060483810"}
	command, _ := shell.Execute("ipconfig /all")
	var stdout, stderr bytes.Buffer
	var wg sync.WaitGroup
	f := func(b *bytes.Buffer, r *commandReader) {
		wg.Add(1)
		defer wg.Done()
		_, _ = io.Copy(b, r)
	}
	go f(&stdout, command.Stdout)
	go f(&stderr, command.Stderr)
	command.Wait()
	wg.Wait()
	c.Assert(stdout.String(), Equals, "That's all folks!!!")
	c.Assert(stderr.String(), Equals, "This is stderr, I'm pretty sure!")
}

func (s *WinRMSuite) TestPermanentSOAPFaultStopsReceive(c *C) {
	endpoint := NewEndpoint("localhost", 5985, false, false, nil, nil, nil, 0)
	client, err := NewClient(endpoint, "Administrator", "v3r1S3cre7")
	c.Assert(err, IsNil)

	receiveCount := 0
	r := Requester{}
	r.http = func(_ *Client, message *soap.SoapMessage) (string, error) {
		switch {
		case strings.Contains(message.String(), "shell/Command"):
			return executeCommandResponse, nil
		case strings.Contains(message.String(), "shell/Receive"):
			receiveCount++
			return "", &httpResponseError{statusCode: http.StatusInternalServerError, body: executeCommandResponseWithError}
		default:
			return "", nil
		}
	}
	client.http = &r
	command, err := client.NewShell("SHELLID").Execute("hostname")
	c.Assert(err, IsNil)
	command.Wait()

	var fault *SOAPFaultError
	c.Assert(errors.As(command.Error(), &fault), Equals, true)
	c.Assert(errors.Is(command.Error(), ErrOperationTimeout), Equals, false)
	c.Assert(receiveCount, Equals, 1)
}

func (s *WinRMSuite) TestMultipleOperationTimeoutsRetryUntilCompletion(c *C) {
	endpoint := NewEndpoint("localhost", 5985, false, false, nil, nil, nil, 0)
	client, err := NewClient(endpoint, "Administrator", "v3r1S3cre7")
	c.Assert(err, IsNil)

	receiveCount := 0
	r := Requester{}
	r.http = func(_ *Client, message *soap.SoapMessage) (string, error) {
		switch {
		case strings.Contains(message.String(), "shell/Command"):
			return executeCommandResponse, nil
		case strings.Contains(message.String(), "shell/Receive"):
			receiveCount++
			if receiveCount <= 3 {
				return "", &httpResponseError{statusCode: http.StatusInternalServerError, body: operationTimeoutResponse}
			}
			return doneCommandResponse, nil
		default:
			return "", nil
		}
	}
	client.http = &r
	command, err := client.NewShell("SHELLID").Execute("hostname")
	c.Assert(err, IsNil)
	command.Wait()

	c.Assert(command.Error(), IsNil)
	c.Assert(command.ExitCode(), Equals, 123)
	c.Assert(receiveCount, Equals, 4)
}

func (s *WinRMSuite) TestEOFError(c *C) {
	count := 0
	endpoint := NewEndpoint("localhost", 5985, false, false, nil, nil, nil, 0)
	client, err := NewClient(endpoint, "Administrator", "v3r1S3cre7")
	c.Assert(err, IsNil)
	r := Requester{}
	// simulating a dropped client connection
	r.http = func(client *Client, message *soap.SoapMessage) (string, error) {
		defer func() { count++ }()
		switch count {
		case 0:
			return executeCommandResponse, nil
		case 1:
			return "", fmt.Errorf("http response error: 200 - /wsman: %w", io.EOF)
		default:
			return doneCommandExitCode0Response, nil
		}
	}
	client.http = &r
	shell := &Shell{client: client, id: "67A74734-DD32-4F10-89DE-49A060483810"}
	command, _ := shell.Execute("ipconfig /all")

	command.Wait()
	c.Assert(command.exitCode, Equals, 16001)
	c.Assert(command.err.Error(), Contains, "EOF")
}
