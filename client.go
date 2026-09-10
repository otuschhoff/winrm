package winrm

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/otuschhoff/winrm/soap"
)

// Client struct
type Client struct {
	Parameters
	username         string
	password         string
	useHTTPS         bool
	url              string
	http             Transporter
	lifecycleMu      sync.Mutex
	lifecycleOnce    sync.Once
	closeOnce        sync.Once
	closeDone        chan struct{}
	closeErr         error
	lifecycleState   clientLifecycleState
	nextOperation    uint64
	operationsDone   chan struct{}
	operationCancels map[uint64]context.CancelFunc
	activeCommands   map[*Command]struct{}
	activeShells     map[*Shell]struct{}
}

type clientLifecycleState uint8

const (
	clientOpen clientLifecycleState = iota
	clientClosing
	clientClosed
)

// Transporter does different transporters
// and init a Post request based on them
type Transporter interface {
	// init request baset on the transport configurations
	Post(*Client, *soap.SoapMessage) (string, error)
	Transport(*Endpoint) error
}

// NewClient will create a new remote client on url, connecting with user and password
// This function doesn't connect (connection happens only when CreateShell is called)
func NewClient(endpoint *Endpoint, user, password string) (*Client, error) {
	return NewClientWithParameters(endpoint, user, password, DefaultParameters)
}

// NewClientWithParameters will create a new remote client on url, connecting with user and password
// This function doesn't connect (connection happens only when CreateShell is called)
func NewClientWithParameters(endpoint *Endpoint, user, password string, params *Parameters) (*Client, error) {
	// alloc a new client
	client := &Client{
		Parameters: *params,
		username:   user,
		password:   password,
		url:        endpoint.url(),
		useHTTPS:   endpoint.HTTPS,
		// default transport
		http: &clientRequest{dial: params.Dial},
	}
	client.initLifecycle()

	// switch to other transport if provided
	if params.TransportDecorator != nil {
		client.http = params.TransportDecorator()
	}

	// set the transport to some endpoint configuration
	if err := client.http.Transport(endpoint); err != nil {
		return nil, fmt.Errorf("can't parse this key and certs: %w", err)
	}

	return client, nil
}

func readCACerts(certs []byte) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()

	if !certPool.AppendCertsFromPEM(certs) {
		return nil, errors.New("unable to read certificates")
	}

	return certPool, nil
}

// CreateShell will create a WinRM Shell,
// which is the prealable for running commands.
func (c *Client) CreateShell() (*Shell, error) {
	return c.CreateShellWithContext(context.Background())
}

// CreateShellWithContext creates a WinRM shell using the supplied request context.
func (c *Client) CreateShellWithContext(ctx context.Context) (*Shell, error) {
	operationContext, finishOperation, err := c.beginOperation(ctx)
	if err != nil {
		return nil, err
	}
	defer finishOperation()
	request := NewOpenShellRequest(c.url, &c.Parameters)
	defer request.Free()

	response, err := c.sendRequestContext(operationContext, request)
	if err != nil {
		return nil, err
	}

	shellID, err := ParseOpenShellResponse(response)
	if err != nil {
		return nil, err
	}

	return c.newOwnedShell(shellID)
}

// NewShell will create a new WinRM Shell for the given shellID
func (c *Client) NewShell(id string) *Shell {
	c.initLifecycle()
	shell := newShell(c, id)
	c.lifecycleMu.Lock()
	if c.lifecycleState == clientOpen {
		c.activeShells[shell] = struct{}{}
	} else {
		shell.closed = true
	}
	c.lifecycleMu.Unlock()
	return shell
}

func (c *Client) newOwnedShell(id string) (*Shell, error) {
	shell := newShell(c, id)
	c.lifecycleMu.Lock()
	if c.lifecycleState == clientClosed {
		c.lifecycleMu.Unlock()
		cleanupContext, cancel := context.WithTimeout(context.Background(), shellCleanupTimeout)
		defer cancel()
		return nil, errors.Join(errors.New("WinRM client closed while creating shell"), shell.CloseWithContext(cleanupContext))
	}
	c.activeShells[shell] = struct{}{}
	c.lifecycleMu.Unlock()
	return shell, nil
}

// sendRequest exec the custom http func from the client
func (c *Client) sendRequest(request *soap.SoapMessage) (string, error) {
	return c.sendRequestContext(context.Background(), request)
}

type contextTransporter interface {
	PostContext(context.Context, *Client, *soap.SoapMessage) (string, error)
}

type closeTransporter interface {
	Close() error
}

func (c *Client) sendRequestContext(ctx context.Context, request *soap.SoapMessage) (string, error) {
	if transport, ok := c.http.(contextTransporter); ok {
		return transport.PostContext(ctx, c, request)
	}
	return c.http.Post(c, request)
}

// Close releases resources held by transports that require explicit cleanup.
func (c *Client) Close() error {
	c.initLifecycle()
	c.closeOnce.Do(func() {
		c.closeErr = c.closeResources()
		close(c.closeDone)
	})
	<-c.closeDone
	return c.closeErr
}

func (c *Client) closeResources() error {
	cleanupContext, cancel := context.WithTimeout(context.Background(), commandCleanupTimeout)
	defer cancel()
	c.lifecycleMu.Lock()
	c.lifecycleState = clientClosing
	operationCancels := make([]context.CancelFunc, 0, len(c.operationCancels))
	for _, operationCancel := range c.operationCancels {
		operationCancels = append(operationCancels, operationCancel)
	}
	operationsDone := c.operationsDone
	c.lifecycleMu.Unlock()
	for _, operationCancel := range operationCancels {
		operationCancel()
	}

	var cleanupErr error
	operationsTimedOut := false
	if operationsDone != nil {
		select {
		case <-operationsDone:
		case <-cleanupContext.Done():
			cleanupErr = fmt.Errorf("close client operations: %w", cleanupContext.Err())
			operationsTimedOut = true
		}
	}

	c.lifecycleMu.Lock()
	if operationsTimedOut {
		c.lifecycleState = clientClosed
	}
	commands := make([]*Command, 0, len(c.activeCommands))
	for command := range c.activeCommands {
		commands = append(commands, command)
	}
	shells := make([]*Shell, 0, len(c.activeShells))
	for shell := range c.activeShells {
		shells = append(shells, shell)
	}
	c.lifecycleMu.Unlock()

	for _, command := range commands {
		command.cancelFn()
	}
	for _, command := range commands {
		waitTimedOut := false
		select {
		case <-command.done:
		case <-cleanupContext.Done():
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("close client commands: %w", cleanupContext.Err()))
			waitTimedOut = true
		}
		if waitTimedOut {
			break
		}
		cleanupErr = errors.Join(cleanupErr, command.signalErr)
	}
	for _, shell := range shells {
		cleanupErr = errors.Join(cleanupErr, shell.CloseWithContext(cleanupContext))
	}
	if transport, ok := c.http.(closeTransporter); ok {
		cleanupErr = errors.Join(cleanupErr, transport.Close())
	}
	c.lifecycleMu.Lock()
	c.lifecycleState = clientClosed
	c.lifecycleMu.Unlock()
	return cleanupErr
}

func (c *Client) initLifecycle() {
	c.lifecycleOnce.Do(func() {
		c.closeDone = make(chan struct{})
		c.operationCancels = make(map[uint64]context.CancelFunc)
		c.activeCommands = make(map[*Command]struct{})
		c.activeShells = make(map[*Shell]struct{})
	})
}

func (c *Client) beginOperation(ctx context.Context) (context.Context, func(), error) {
	c.initLifecycle()
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.lifecycleState != clientOpen {
		return nil, nil, errors.New("WinRM client is closing or closed")
	}
	if len(c.operationCancels) == 0 {
		c.operationsDone = make(chan struct{})
	}
	c.nextOperation++
	operationID := c.nextOperation
	operationContext, cancel := context.WithCancel(ctx)
	c.operationCancels[operationID] = cancel
	return operationContext, func() {
		cancel()
		c.lifecycleMu.Lock()
		delete(c.operationCancels, operationID)
		if len(c.operationCancels) == 0 {
			close(c.operationsDone)
			c.operationsDone = nil
		}
		c.lifecycleMu.Unlock()
	}, nil
}

func (c *Client) registerCommand(command *Command) error {
	c.initLifecycle()
	c.lifecycleMu.Lock()
	defer c.lifecycleMu.Unlock()
	if c.lifecycleState == clientClosed {
		return errors.New("WinRM client is closed")
	}
	if c.activeCommands == nil {
		c.activeCommands = make(map[*Command]struct{})
	}
	c.activeCommands[command] = struct{}{}
	return nil
}

func (c *Client) unregisterShell(shell *Shell) {
	c.lifecycleMu.Lock()
	delete(c.activeShells, shell)
	c.lifecycleMu.Unlock()
}

func (c *Client) unregisterCommand(command *Command) {
	c.lifecycleMu.Lock()
	delete(c.activeCommands, command)
	c.lifecycleMu.Unlock()
}

// Run will run command on the the remote host, writing the process stdout and stderr to
// the given writers. Note with this method it isn't possible to inject stdin.
//
// Deprecated: use RunWithContext()
func (c *Client) Run(command string, stdout io.Writer, stderr io.Writer) (int, error) {
	return c.RunWithContext(context.Background(), command, stdout, stderr)
}

// RunWithContext will run command on the the remote host, writing the process stdout and stderr to
// the given writers. Note with this method it isn't possible to inject stdin.
// If the context is canceled, the remote command is canceled.
func (c *Client) RunWithContext(ctx context.Context, command string, stdout io.Writer, stderr io.Writer) (int, error) {
	return c.RunWithContextWithInput(ctx, command, stdout, stderr, nil)
}

// RunWithString will run command on the the remote host, returning the process stdout and stderr
// as strings, and using the input stdin string as the process input
//
// Deprecated: use RunWithContextWithString()
func (c *Client) RunWithString(command string, stdin string) (string, string, int, error) {
	return c.RunWithContextWithString(context.Background(), command, stdin)
}

// RunWithContextWithString will run command on the the remote host, returning the process stdout and stderr
// as strings, and using the input stdin string as the process input
// If the context is canceled, the remote command is canceled.
func (c *Client) RunWithContextWithString(ctx context.Context, command string, stdin string) (string, string, int, error) {
	var outWriter, errWriter bytes.Buffer
	exitCode, err := c.RunWithContextWithInput(ctx, command, &outWriter, &errWriter, strings.NewReader(stdin))
	return outWriter.String(), errWriter.String(), exitCode, err
}

// RunCmdWithContext will run command on the the remote host, returning the process stdout and stderr
// as strings
// If the context is canceled, the remote command is canceled.
func (c *Client) RunCmdWithContext(ctx context.Context, command string) (string, string, int, error) {
	var outWriter, errWriter bytes.Buffer
	exitCode, err := c.RunWithContextWithInput(ctx, command, &outWriter, &errWriter, nil)
	return outWriter.String(), errWriter.String(), exitCode, err
}

// RunPSWithString will basically wrap your code to execute commands in powershell.exe. Default RunWithString
// runs commands in cmd.exe
//
// Deprecated: use RunPSWithContextWithString()
func (c *Client) RunPSWithString(command string, stdin string) (string, string, int, error) {
	return c.RunPSWithContextWithString(context.Background(), command, stdin)
}

// RunPSWithContextWithString will basically wrap your code to execute commands in powershell.exe. Default RunWithString
// runs commands in cmd.exe
func (c *Client) RunPSWithContextWithString(ctx context.Context, command string, stdin string) (string, string, int, error) {
	command = Powershell(command)

	// Let's check if we actually created a command
	if command == "" {
		return "", "", 1, errors.New("cannot encode the given command")
	}

	// Specify powershell.exe to run encoded command
	return c.RunWithContextWithString(ctx, command, stdin)
}

// RunPSWithContext will basically wrap your code to execute commands in powershell.exe.
// runs commands in cmd.exe
func (c *Client) RunPSWithContext(ctx context.Context, command string) (string, string, int, error) {
	command = Powershell(command)

	// Let's check if we actually created a command
	if command == "" {
		return "", "", 1, errors.New("cannot encode the given command")
	}

	var outWriter, errWriter bytes.Buffer
	exitCode, err := c.RunWithContextWithInput(ctx, command, &outWriter, &errWriter, nil)
	return outWriter.String(), errWriter.String(), exitCode, err
}

// RunWithInput will run command on the the remote host, writing the process stdout and stderr to
// the given writers, and injecting the process stdin with the stdin reader.
// Warning stdin (not stdout/stderr) are bufferized, which means reading only one byte in stdin will
// send a winrm http packet to the remote host. If stdin is a pipe, it might be better for
// performance reasons to buffer it.
// If stdin is nil, this is equivalent to c.Run()
//
// Deprecated: use RunWithContextWithInput()
func (c *Client) RunWithInput(command string, stdout, stderr io.Writer, stdin io.Reader) (int, error) {
	return c.RunWithContextWithInput(context.Background(), command, stdout, stderr, stdin)
}

// RunWithContextWithInput will run command on the the remote host, writing the process stdout and stderr to
// the given writers, and injecting the process stdin with the stdin reader.
// If the context is canceled, the command on the remote machine is canceled.
// Warning stdin (not stdout/stderr) are bufferized, which means reading only one byte in stdin will
// send a winrm http packet to the remote host. If stdin is a pipe, it might be better for
// performance reasons to buffer it.
// A stdin reader that can block indefinitely should implement io.Closer so cancellation can interrupt its Read.
// If stdin is nil, this is equivalent to c.RunWithContext()
func (c *Client) RunWithContextWithInput(ctx context.Context, command string, stdout, stderr io.Writer, stdin io.Reader) (exitCode int, resultErr error) {
	shell, err := c.CreateShellWithContext(ctx)
	if err != nil {
		return 1, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, shell.Close())
	}()
	cmd, err := shell.executeWithContext(ctx, command, stdin == nil)
	if err != nil {
		return 1, err
	}

	var outputWG sync.WaitGroup
	outputWG.Add(2)
	outputErrors := make(chan error, 2)
	inputDone := make(chan error, 1)
	inputFinished := false
	var inputErr error

	go func() {
		if stdin == nil {
			inputDone <- nil
			return
		}
		_, copyErr := io.Copy(cmd.Stdin, stdin)
		inputDone <- errors.Join(copyErr, cmd.Stdin.Close())
	}()
	if stdin != nil {
		select {
		case inputErr = <-inputDone:
			inputFinished = true
			if inputErr != nil {
				cmd.cancelFn()
				cmd.cleanupAfterCancellation(inputErr)
			} else {
				cmd.startOutput()
			}
		case <-ctx.Done():
			if closer, ok := stdin.(io.Closer); ok {
				_ = closer.Close()
				inputErr = <-inputDone
				inputFinished = true
			}
			cmd.cleanupAfterCancellation(ctx.Err())
		}
	}
	go func() {
		defer outputWG.Done()
		_, err := io.Copy(stdout, cmd.Stdout)
		if err != nil {
			_ = cmd.Stdout.read.CloseWithError(err)
			cmd.cancelFn()
		}
		outputErrors <- err
	}()
	go func() {
		defer outputWG.Done()
		_, err := io.Copy(stderr, cmd.Stderr)
		if err != nil {
			_ = cmd.Stderr.read.CloseWithError(err)
			cmd.cancelFn()
		}
		outputErrors <- err
	}()

	cmd.Wait()
	if closer, ok := stdin.(io.Closer); ok && !inputFinished {
		_ = closer.Close()
		inputErr = <-inputDone
		inputFinished = true
	} else {
		select {
		case inputErr = <-inputDone:
			inputFinished = true
		default:
		}
	}
	outputWG.Wait()
	close(outputErrors)
	var outputErr error
	for err := range outputErrors {
		outputErr = errors.Join(outputErr, err)
	}
	commandCloseErr := cmd.Close()

	return cmd.ExitCode(), errors.Join(cmd.Error(), inputErr, outputErr, commandCloseErr)
}
