package winrm

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otuschhoff/winrm/soap"
)

type blockingCommandTransport struct {
	mu              sync.Mutex
	receiveStarted  chan struct{}
	receiveOnce     sync.Once
	signals         int
	deletes         int
	closed          int
	receiveErr      error
	receiveResponse string
	sendErr         error
}

type signalingReadCloser struct {
	io.ReadCloser
	started chan struct{}
	once    sync.Once
}

type failingWriter struct {
	err error
}

func (writer failingWriter) Write([]byte) (int, error) {
	return 0, writer.err
}

func (reader *signalingReadCloser) Read(data []byte) (int, error) {
	reader.once.Do(func() { close(reader.started) })
	return reader.ReadCloser.Read(data)
}

func newBlockingCommandTransport() *blockingCommandTransport {
	return &blockingCommandTransport{receiveStarted: make(chan struct{})}
}

func (transport *blockingCommandTransport) Transport(*Endpoint) error { return nil }

func (transport *blockingCommandTransport) Post(client *Client, request *soap.SoapMessage) (string, error) {
	return transport.PostContext(context.Background(), client, request)
}

func (transport *blockingCommandTransport) PostContext(ctx context.Context, _ *Client, request *soap.SoapMessage) (string, error) {
	message := request.String()
	switch {
	case strings.Contains(message, "transfer/Create"):
		return createShellResponse, nil
	case strings.Contains(message, "shell/Command"):
		return executeCommandResponse, nil
	case strings.Contains(message, "shell/Receive"):
		transport.receiveOnce.Do(func() { close(transport.receiveStarted) })
		if transport.receiveErr != nil {
			return "", transport.receiveErr
		}
		if transport.receiveResponse != "" {
			return transport.receiveResponse, nil
		}
		<-ctx.Done()
		return "", ctx.Err()
	case strings.Contains(message, "shell/Send"):
		return "", transport.sendErr
	case strings.Contains(message, "shell/Signal"):
		transport.mu.Lock()
		transport.signals++
		transport.mu.Unlock()
		return "", nil
	case strings.Contains(message, "transfer/Delete"):
		transport.mu.Lock()
		transport.deletes++
		transport.mu.Unlock()
		return "", nil
	default:
		return "", nil
	}
}

func (transport *blockingCommandTransport) Close() error {
	transport.mu.Lock()
	transport.closed++
	transport.mu.Unlock()
	return nil
}

func (transport *blockingCommandTransport) counts() (signals, deletes, closed int) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.signals, transport.deletes, transport.closed
}

func newBlockingCommandClient(transport *blockingCommandTransport) *Client {
	return &Client{Parameters: *DefaultParameters, url: "http://host.example.test/wsman", http: transport}
}

func TestCommandCancellationInterruptsReceiveAndCleansUp(t *testing.T) {
	transport := newBlockingCommandTransport()
	client := newBlockingCommandClient(transport)
	shell := client.NewShell("SHELLID")
	ctx, cancel := context.WithCancel(context.Background())
	command, err := shell.ExecuteWithContext(ctx, "hostname")
	if err != nil {
		t.Fatal(err)
	}
	<-transport.receiveStarted
	cancel()

	select {
	case <-command.done:
	case <-time.After(time.Second):
		t.Fatal("command did not stop after Receive cancellation")
	}
	if !errors.Is(command.Error(), context.Canceled) {
		t.Fatalf("command error = %v, want context cancellation", command.Error())
	}
	if signals, _, _ := transport.counts(); signals != 1 {
		t.Fatalf("Signal requests = %d, want 1", signals)
	}
}

func TestRunCancellationClosesBlockingInput(t *testing.T) {
	transport := newBlockingCommandTransport()
	client := newBlockingCommandClient(transport)
	ctx, cancel := context.WithCancel(context.Background())
	pipeReader, inputWriter := io.Pipe()
	inputReader := &signalingReadCloser{ReadCloser: pipeReader, started: make(chan struct{})}
	defer inputWriter.Close()
	result := make(chan error, 1)
	go func() {
		_, err := client.RunWithContextWithInput(ctx, "hostname", io.Discard, io.Discard, inputReader)
		result <- err
	}()
	<-inputReader.started
	cancel()

	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("run error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("run did not stop after input cancellation")
	}
	if _, err := inputWriter.Write([]byte("blocked")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("input writer error = %v, want closed pipe", err)
	}
	if signals, deletes, _ := transport.counts(); signals != 1 || deletes != 1 {
		t.Fatalf("cleanup requests = Signal %d, Delete %d; want 1 each", signals, deletes)
	}
}

func TestClientCloseJoinsActiveCommand(t *testing.T) {
	transport := newBlockingCommandTransport()
	client := newBlockingCommandClient(transport)
	shell := client.NewShell("SHELLID")
	command, err := shell.ExecuteWithContext(context.Background(), "hostname")
	if err != nil {
		t.Fatal(err)
	}
	<-transport.receiveStarted

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-command.done:
	default:
		t.Fatal("client closed before active command stopped")
	}
	if signals, _, closed := transport.counts(); signals != 1 || closed != 1 {
		t.Fatalf("shutdown requests = Signal %d, transport close %d; want 1 each", signals, closed)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, closed := transport.counts(); closed != 1 {
		t.Fatalf("transport close calls = %d, want 1", closed)
	}
}

func TestServerCloseDuringReceiveFinishesCommand(t *testing.T) {
	transport := newBlockingCommandTransport()
	transport.receiveErr = io.ErrUnexpectedEOF
	client := newBlockingCommandClient(transport)

	_, _, exitCode, err := client.RunCmdWithContext(context.Background(), "hostname")
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("run error = %v, want unexpected EOF", err)
	}
	if exitCode != 16001 {
		t.Fatalf("exit code = %d, want 16001", exitCode)
	}
	client.lifecycleMu.Lock()
	activeCommands := len(client.activeCommands)
	client.lifecycleMu.Unlock()
	if activeCommands != 0 {
		t.Fatalf("active commands = %d, want 0", activeCommands)
	}
	if signals, deletes, _ := transport.counts(); signals != 1 || deletes != 1 {
		t.Fatalf("cleanup requests = Signal %d, Delete %d; want 1 each", signals, deletes)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestStdinSendFailureStopsBeforeReceive(t *testing.T) {
	transport := newBlockingCommandTransport()
	transport.sendErr = io.ErrClosedPipe
	client := newBlockingCommandClient(transport)

	_, _, _, err := client.RunWithContextWithString(context.Background(), "more", "input")
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("run error = %v, want closed pipe", err)
	}
	select {
	case <-transport.receiveStarted:
		t.Fatal("Receive started after stdin delivery failed")
	default:
	}
	if signals, deletes, _ := transport.counts(); signals != 1 || deletes != 1 {
		t.Fatalf("cleanup requests = Signal %d, Delete %d; want 1 each", signals, deletes)
	}
}

func TestOutputWriteFailureIsReturned(t *testing.T) {
	transport := newBlockingCommandTransport()
	transport.receiveResponse = kerberosPhase4Receive([]byte("output"), nil, true, 0)
	client := newBlockingCommandClient(transport)
	wantErr := errors.New("output destination failed")

	_, err := client.RunWithContext(context.Background(), "hostname", failingWriter{err: wantErr}, io.Discard)
	if !errors.Is(err, wantErr) {
		t.Fatalf("run error = %v, want output destination failure", err)
	}
}
