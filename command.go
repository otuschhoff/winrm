package winrm

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/url"
	"strings"
	"sync"
	"time"
)

const commandCleanupTimeout = 5 * time.Second

type commandWriter struct {
	*Command
	mutex sync.Mutex
	eof   bool
}

type commandReader struct {
	*Command
	write  *io.PipeWriter
	read   *io.PipeReader
	stream string
}

// Command represents a given command running on a Shell. This structure allows to get access
// to the various stdout, stderr and stdin pipes.
type Command struct {
	ctx      context.Context
	cancelFn context.CancelFunc
	client   *Client
	shell    *Shell
	id       string
	exitCode int
	err      error

	Stdin  *commandWriter
	Stdout *commandReader
	Stderr *commandReader

	done      chan struct{}
	doneOnce  sync.Once
	startOnce sync.Once
	stateMu   sync.RWMutex
	signalMu  sync.Mutex
	signaled  bool
	signalErr error
}

func newCommand(ctx context.Context, shell *Shell, ids string) (*Command, error) {
	return newCommandWithOutput(ctx, shell, ids, true)
}

func newCommandWithOutput(ctx context.Context, shell *Shell, ids string, startOutput bool) (*Command, error) {
	commandContext, cancel := context.WithCancel(ctx)
	command := &Command{
		ctx:      commandContext,
		cancelFn: cancel,
		shell:    shell,
		client:   shell.client,
		id:       ids,
		exitCode: 0,
		err:      nil,
		done:     make(chan struct{}),
	}

	command.Stdout = newCommandReader("stdout", command)
	command.Stdin = &commandWriter{
		Command: command,
		eof:     false,
	}
	command.Stderr = newCommandReader("stderr", command)
	if err := command.client.registerCommand(command); err != nil {
		cancel()
		return nil, err
	}

	if startOutput {
		command.startOutput()
	}

	return command, nil
}

func (c *Command) startOutput() {
	c.startOnce.Do(func() {
		go fetchOutput(c.ctx, c)
	})
}

func newCommandReader(stream string, command *Command) *commandReader {
	read, write := io.Pipe()
	return &commandReader{
		Command: command,
		stream:  stream,
		write:   write,
		read:    read,
	}
}

func fetchOutput(ctx context.Context, command *Command) {
	for {
		if err := ctx.Err(); err != nil {
			command.cleanupAfterCancellation(err)
			return
		}
		finished, err := command.slurpAllOutput()
		if contextErr := ctx.Err(); contextErr != nil {
			command.cleanupAfterCancellation(contextErr)
			return
		}
		if finished {
			command.finish(err)
			return
		}
	}
}

func (c *Command) cleanupAfterCancellation(cause error) {
	cleanupContext, cancel := context.WithTimeout(context.Background(), commandCleanupTimeout)
	defer cancel()
	_ = c.signal(cleanupContext)
	c.finish(cause)
}

func (c *Command) finish(err error) {
	c.doneOnce.Do(func() {
		c.stateMu.Lock()
		c.err = err
		c.stateMu.Unlock()
		_ = c.Stderr.write.CloseWithError(err)
		_ = c.Stdout.write.CloseWithError(err)
		c.client.unregisterCommand(c)
		close(c.done)
	})
}

func (c *Command) check() error {
	if c.id == "" {
		return errors.New("Command has already been closed")
	}
	if c.shell == nil {
		return errors.New("Command has no associated shell")
	}
	if c.client == nil {
		return errors.New("Command has no associated client")
	}
	return nil
}

// Close will terminate the running command
func (c *Command) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), commandCleanupTimeout)
	defer cancel()
	return c.CloseWithContext(ctx)
}

// CloseWithContext terminates the remote command with bounded cleanup.
func (c *Command) CloseWithContext(ctx context.Context) error {
	if err := c.check(); err != nil {
		return err
	}
	c.cancelFn()
	return c.signal(ctx)
}

func (c *Command) signal(ctx context.Context) error {
	c.signalMu.Lock()
	defer c.signalMu.Unlock()
	if c.signaled {
		return c.signalErr
	}
	c.signaled = true
	request := NewSignalRequest(c.client.url, c.shell.id, c.id, &c.client.Parameters)
	defer request.Free()
	_, c.signalErr = c.client.sendRequestContext(ctx, request)
	return c.signalErr
}

func (c *Command) slurpAllOutput() (bool, error) {
	if err := c.check(); err != nil {
		c.Stderr.write.CloseWithError(err)
		c.Stdout.write.CloseWithError(err)
		return true, err
	}

	request := NewGetOutputRequest(c.client.url, c.shell.id, c.id, "stdout stderr", &c.client.Parameters)
	defer request.Free()

	response, err := c.client.sendRequestContext(c.ctx, request)
	if err != nil {
		var errWithTimeout *url.Error
		if errors.As(err, &errWithTimeout) && errWithTimeout.Timeout() {
			// Operation timeout because the server didn't respond in time
			return false, err
		}
		if strings.Contains(err.Error(), "OperationTimeout") {
			// Operation timeout because there was no command output
			return false, err
		}
		if strings.Contains(err.Error(), "EOF") {
			c.stateMu.Lock()
			c.exitCode = 16001
			c.stateMu.Unlock()
		}

		c.Stderr.write.CloseWithError(err)
		c.Stdout.write.CloseWithError(err)
		return true, err
	}

	var exitCode int
	var stdout, stderr bytes.Buffer
	finished, exitCode, err := ParseSlurpOutputErrResponse(response, &stdout, &stderr)
	if err != nil {
		c.Stderr.write.CloseWithError(err)
		c.Stdout.write.CloseWithError(err)
		return true, err
	}
	if stdout.Len() > 0 {
		_, _ = c.Stdout.write.Write(stdout.Bytes())
	}
	if stderr.Len() > 0 {
		_, _ = c.Stderr.write.Write(stderr.Bytes())
	}
	if finished {
		c.stateMu.Lock()
		c.exitCode = exitCode
		c.stateMu.Unlock()
		_ = c.Stderr.write.Close()
		_ = c.Stdout.write.Close()
	}

	return finished, nil
}

func (c *Command) sendInput(data []byte, eof bool) error {
	if err := c.check(); err != nil {
		return err
	}

	request := NewSendInputRequest(c.client.url, c.shell.id, c.id, data, eof, &c.client.Parameters)
	defer request.Free()

	_, err := c.client.sendRequestContext(c.ctx, request)
	return err
}

// ExitCode returns command exit code when it is finished. Before that the result is always 0.
func (c *Command) ExitCode() int {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.exitCode
}

// Error returns command execution error if any
func (c *Command) Error() error {
	c.stateMu.RLock()
	defer c.stateMu.RUnlock()
	return c.err
}

// Wait function will block the current goroutine until the remote command terminates.
func (c *Command) Wait() {
	// block until finished
	<-c.done
}

// Write data to this Pipe
// commandWriter implements io.Writer and io.Closer interface
func (w *commandWriter) Write(data []byte) (int, error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return w.write(data, false)
}

func (w *commandWriter) write(data []byte, eof bool) (int, error) {
	if w.eof {
		return 0, io.ErrClosedPipe
	}
	chunkSize := w.client.Parameters.EnvelopeSize - 1000
	if chunkSize <= 0 {
		return 0, errors.New("envelope size is too small for command input")
	}

	var (
		written int
		err     error
	)
	origLen := len(data)
	for len(data) > 0 {
		// never send more data than our EnvelopeSize.
		n := min(chunkSize, len(data))
		last := n == len(data)
		if err = w.sendInput(data[:n], eof && last); err != nil {
			break
		}
		data = data[n:]
		written += n
	}
	if eof && origLen == 0 {
		err = w.sendInput(nil, true)
	}
	if eof && err == nil {
		w.eof = true
	}

	// signal that we couldn't write all data
	if err == nil && written < origLen {
		err = io.ErrShortWrite
	}

	return written, err
}

// Write data to this Pipe and mark EOF
func (w *commandWriter) WriteClose(data []byte) (int, error) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return w.write(data, true)
}

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}

// Close method wrapper
// commandWriter implements io.Closer interface
func (w *commandWriter) Close() error {
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if w.eof {
		return io.ErrClosedPipe
	}
	w.eof = true
	return w.sendInput(nil, w.eof)
}

// Read data from this Pipe
func (r *commandReader) Read(buf []byte) (int, error) {
	n, err := r.read.Read(buf)
	if err != nil && errors.Is(err, io.EOF) {
		return 0, err
	}
	return n, err
}
