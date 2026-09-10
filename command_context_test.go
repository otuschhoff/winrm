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
	mu               sync.Mutex
	receiveStarted   chan struct{}
	receiveOnce      sync.Once
	commandStarted   chan struct{}
	commandOnce      sync.Once
	commandCanceled  chan struct{}
	createStarted    chan struct{}
	createOnce       sync.Once
	createCanceled   chan struct{}
	receiveResponses []string
	receiveIndex     int
	signals          int
	deletes          int
	closed           int
	receiveErr       error
	receiveResponse  string
	sendErr          error
	signalErr        error
	deleteErr        error
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
		if transport.createStarted != nil {
			transport.createOnce.Do(func() { close(transport.createStarted) })
			if transport.createCanceled != nil {
				<-ctx.Done()
				close(transport.createCanceled)
			}
		}
		return createShellResponse, nil
	case strings.Contains(message, "shell/Command"):
		if transport.commandStarted != nil {
			transport.commandOnce.Do(func() { close(transport.commandStarted) })
			if transport.commandCanceled != nil {
				<-ctx.Done()
				close(transport.commandCanceled)
			}
		}
		return executeCommandResponse, nil
	case strings.Contains(message, "shell/Receive"):
		transport.receiveOnce.Do(func() { close(transport.receiveStarted) })
		transport.mu.Lock()
		if transport.receiveIndex < len(transport.receiveResponses) {
			response := transport.receiveResponses[transport.receiveIndex]
			transport.receiveIndex++
			transport.mu.Unlock()
			return response, nil
		}
		transport.mu.Unlock()
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
		return "", transport.signalErr
	case strings.Contains(message, "transfer/Delete"):
		transport.mu.Lock()
		transport.deletes++
		transport.mu.Unlock()
		return "", transport.deleteErr
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

func TestOutputWriteFailureStopsMultipleResponses(t *testing.T) {
	transport := newBlockingCommandTransport()
	transport.receiveResponses = []string{
		kerberosPhase4Receive([]byte("first"), nil, false, 0),
		kerberosPhase4Receive([]byte("second"), nil, false, 0),
	}
	client := newBlockingCommandClient(transport)
	wantErr := errors.New("output destination failed")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := client.RunWithContext(ctx, "hostname", failingWriter{err: wantErr}, io.Discard)
		result <- err
	}()

	select {
	case err := <-result:
		if !errors.Is(err, wantErr) {
			t.Fatalf("run error = %v, want output destination failure", err)
		}
	case <-time.After(250 * time.Millisecond):
		cancel()
		t.Fatal("output failure left the fetch loop blocked on a later response")
	}
	client.lifecycleMu.Lock()
	activeCommands := len(client.activeCommands)
	client.lifecycleMu.Unlock()
	if activeCommands != 0 {
		t.Fatalf("active commands = %d, want 0", activeCommands)
	}
}

func TestStderrWriteFailureStopsMultipleResponses(t *testing.T) {
	transport := newBlockingCommandTransport()
	transport.receiveResponses = []string{
		kerberosPhase4Receive(nil, []byte("first"), false, 0),
		kerberosPhase4Receive(nil, []byte("second"), false, 0),
	}
	client := newBlockingCommandClient(transport)
	wantErr := errors.New("stderr destination failed")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := client.RunWithContext(ctx, "hostname", io.Discard, failingWriter{err: wantErr})
		result <- err
	}()

	select {
	case err := <-result:
		if !errors.Is(err, wantErr) {
			t.Fatalf("run error = %v, want stderr destination failure", err)
		}
	case <-time.After(250 * time.Millisecond):
		cancel()
		t.Fatal("stderr failure left the fetch loop blocked on a later response")
	}
}

func TestCommandSignalAdmissionHonorsContext(t *testing.T) {
	command := &Command{}
	command.initSignalGate()
	<-command.signalGate
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	err := command.signal(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("signal error = %v, want deadline exceeded", err)
	}
}

func TestCanceledCommandSignalDoesNotConsumeCleanup(t *testing.T) {
	transport := newBlockingCommandTransport()
	client := newBlockingCommandClient(transport)
	command, err := newCommandWithOutput(context.Background(), client.NewShell("SHELLID"), "COMMANDID", false)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := command.signal(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled signal error = %v, want context canceled", err)
	}
	if signals, _, _ := transport.counts(); signals != 0 {
		t.Fatalf("canceled Signal requests = %d, want 0", signals)
	}
	if err := command.signal(context.Background()); err != nil {
		t.Fatal(err)
	}
	if signals, _, _ := transport.counts(); signals != 1 {
		t.Fatalf("valid Signal requests = %d, want 1", signals)
	}
	command.finish(nil)
}

func TestCommandCancellationInterruptsUnreadOutput(t *testing.T) {
	for _, test := range []struct {
		name   string
		stdout []byte
		stderr []byte
	}{
		{name: "stdout", stdout: []byte("output")},
		{name: "stderr", stderr: []byte("error")},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := newBlockingCommandTransport()
			transport.receiveResponses = []string{
				kerberosPhase4Receive(test.stdout, test.stderr, false, 0),
				kerberosPhase4Receive(test.stdout, test.stderr, false, 0),
			}
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
				t.Fatal("canceled command remained blocked on unread output")
			}
			if !errors.Is(command.Error(), context.Canceled) {
				t.Fatalf("command error = %v, want context canceled", command.Error())
			}
		})
	}
}

func TestClientRejectsCreationAfterClose(t *testing.T) {
	transport := newBlockingCommandTransport()
	client := newBlockingCommandClient(transport)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateShellWithContext(context.Background()); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("CreateShell after Close error = %v, want closed error", err)
	}
	shell := client.NewShell("SHELLID")
	if _, err := shell.ExecuteWithContext(context.Background(), "hostname"); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("Execute after Close error = %v, want closed error", err)
	}
}

func TestClientCloseOwnsCommandCreatedDuringShutdown(t *testing.T) {
	transport := newBlockingCommandTransport()
	transport.commandStarted = make(chan struct{})
	transport.commandCanceled = make(chan struct{})
	client := newBlockingCommandClient(transport)
	shell := client.NewShell("SHELLID")
	executeResult := make(chan error, 1)
	go func() {
		command, err := shell.ExecuteWithContext(context.Background(), "hostname")
		if err == nil {
			command.Wait()
		}
		executeResult <- err
	}()
	<-transport.commandStarted
	closeResult := make(chan error, 1)
	go func() { closeResult <- client.Close() }()
	<-transport.commandCanceled

	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Client.Close did not own command created during shutdown")
	}
	if err := <-executeResult; err != nil {
		t.Fatal(err)
	}
	if signals, deletes, _ := transport.counts(); signals != 1 || deletes != 1 {
		t.Fatalf("shutdown cleanup = Signal %d, Delete %d; want 1 each", signals, deletes)
	}
}

func TestClientCloseOwnsShellCreatedDuringShutdown(t *testing.T) {
	transport := newBlockingCommandTransport()
	transport.createStarted = make(chan struct{})
	transport.createCanceled = make(chan struct{})
	client := newBlockingCommandClient(transport)
	createResult := make(chan error, 1)
	go func() {
		_, err := client.CreateShellWithContext(context.Background())
		createResult <- err
	}()
	<-transport.createStarted
	closeResult := make(chan error, 1)
	go func() { closeResult <- client.Close() }()
	<-transport.createCanceled

	if err := <-createResult; err != nil {
		t.Fatal(err)
	}
	if err := <-closeResult; err != nil {
		t.Fatal(err)
	}
	if _, deletes, _ := transport.counts(); deletes != 1 {
		t.Fatalf("Delete requests = %d, want 1", deletes)
	}
}

func TestClientConcurrentCloseIsIdempotent(t *testing.T) {
	transport := newBlockingCommandTransport()
	client := newBlockingCommandClient(transport)
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 8)
	for index := 0; index < 8; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsSeen <- client.Close()
		}()
	}
	wait.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, _, closed := transport.counts(); closed != 1 {
		t.Fatalf("transport close calls = %d, want 1", closed)
	}
}

func TestShellCloseIsIdempotent(t *testing.T) {
	transport := newBlockingCommandTransport()
	client := newBlockingCommandClient(transport)
	shell := client.NewShell("SHELLID")
	if err := shell.Close(); err != nil {
		t.Fatal(err)
	}
	if err := shell.Close(); err != nil {
		t.Fatal(err)
	}
	if _, deletes, _ := transport.counts(); deletes != 1 {
		t.Fatalf("Delete requests = %d, want 1", deletes)
	}
}

func TestCanceledShellCloseDoesNotConsumeCleanup(t *testing.T) {
	transport := newBlockingCommandTransport()
	client := newBlockingCommandClient(transport)
	shell := client.NewShell("SHELLID")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := shell.CloseWithContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled shell close error = %v, want context canceled", err)
	}
	if _, deletes, _ := transport.counts(); deletes != 0 {
		t.Fatalf("canceled Delete requests = %d, want 0", deletes)
	}
	if err := shell.Close(); err != nil {
		t.Fatal(err)
	}
	if _, deletes, _ := transport.counts(); deletes != 1 {
		t.Fatalf("valid Delete requests = %d, want 1", deletes)
	}
}

func TestCommandCompletionCancelsChildContext(t *testing.T) {
	transport := newBlockingCommandTransport()
	transport.receiveResponse = kerberosPhase4Receive(nil, nil, true, 0)
	client := newBlockingCommandClient(transport)
	command, err := client.NewShell("SHELLID").ExecuteWithContext(context.Background(), "hostname")
	if err != nil {
		t.Fatal(err)
	}
	command.Wait()
	if !errors.Is(command.ctx.Err(), context.Canceled) {
		t.Fatalf("command context error = %v, want canceled after completion", command.ctx.Err())
	}
}

func TestRunSurfacesSignalAndDeleteErrors(t *testing.T) {
	transport := newBlockingCommandTransport()
	transport.receiveResponse = kerberosPhase4Receive(nil, nil, true, 0)
	transport.signalErr = errors.New("synthetic signal failure")
	transport.deleteErr = errors.New("synthetic delete failure")
	client := newBlockingCommandClient(transport)

	_, err := client.RunWithContext(context.Background(), "hostname", io.Discard, io.Discard)
	if !errors.Is(err, transport.signalErr) || !errors.Is(err, transport.deleteErr) {
		t.Fatalf("run error = %v, want Signal and Delete failures", err)
	}
}

func TestClientCloseSurfacesSignalAndDeleteErrors(t *testing.T) {
	transport := newBlockingCommandTransport()
	transport.signalErr = errors.New("synthetic signal failure")
	transport.deleteErr = errors.New("synthetic delete failure")
	client := newBlockingCommandClient(transport)
	command, err := client.NewShell("SHELLID").ExecuteWithContext(context.Background(), "hostname")
	if err != nil {
		t.Fatal(err)
	}
	<-transport.receiveStarted

	err = client.Close()
	if !errors.Is(err, transport.signalErr) || !errors.Is(err, transport.deleteErr) {
		t.Fatalf("client close error = %v, want Signal and Delete failures", err)
	}
	<-command.done
}

func TestShellCloseAdmissionHonorsContext(t *testing.T) {
	transport := newBlockingCommandTransport()
	transport.commandStarted = make(chan struct{})
	transport.commandCanceled = make(chan struct{})
	client := newBlockingCommandClient(transport)
	shell := client.NewShell("SHELLID")
	executeContext, cancelExecute := context.WithCancel(context.Background())
	defer cancelExecute()
	executeResult := make(chan error, 1)
	go func() {
		_, err := shell.ExecuteWithContext(executeContext, "hostname")
		executeResult <- err
	}()
	<-transport.commandStarted
	closeContext, cancelClose := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancelClose()

	err := shell.CloseWithContext(closeContext)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shell close error = %v, want deadline exceeded", err)
	}
	cancelExecute()
	<-transport.commandCanceled
	if err := <-executeResult; err != nil {
		t.Fatal(err)
	}
}
