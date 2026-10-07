package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/otuschhoff/winrm"
)

func copyLines(dst io.Writer, src io.Reader) error {
	reader := bufio.NewReader(src)
	for {
		line, readErr := reader.ReadString('\n')
		if line != "" {
			if strings.HasSuffix(line, "\n") && !strings.HasSuffix(line, "\r\n") {
				line = strings.TrimSuffix(line, "\n") + "\r\n"
			}
			n, err := io.WriteString(dst, line)
			if err == nil && n != len(line) {
				err = io.ErrShortWrite
			}
			if err != nil {
				return withOperation("send remote stdin", "Could not send input to the remote process. Check the connection and whether the process is still running.", err)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return withOperation("read local stdin", "Could not read local input. Check the terminal, file, or input pipeline.", readErr)
		}
	}
}

func streamCommand(ctx context.Context, cmd *winrm.Command, stdin io.ReadCloser, stdout, stderr io.Writer) (int, error) {
	return stream(ctx, cmd.Stdin, cmd.Stdout, cmd.Stderr, cmd.Wait, cmd.Close, cmd.ExitCode, cmd.Error, stdin, stdout, stderr)
}

func stream(ctx context.Context, remoteInput io.WriteCloser, remoteOutput, remoteError io.Reader,
	wait func(), closeCommand func() error, exitCode func() int, commandError func() error,
	stdin io.ReadCloser, stdout, stderr io.Writer,
) (int, error) {
	var closingInput atomic.Bool
	var inputCloseOnce sync.Once
	var inputCloseErr error
	closeInput := func() {
		inputCloseOnce.Do(func() {
			closingInput.Store(true)
			inputCloseErr = withOperation("close local stdin", "Could not close local input. Check the terminal or input pipeline.", stdin.Close())
		})
	}
	sessionDone := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			closeInput()
		case <-sessionDone:
		}
	}()
	type inputResult struct {
		copyErr, closeErr error
	}
	inputDone := make(chan inputResult, 1)
	go func() {
		err := copyLines(remoteInput, stdin)
		if closingInput.Load() {
			var operation *operationError
			if errors.As(err, &operation) && operation.operation == "read local stdin" &&
				(errors.Is(err, os.ErrClosed) || errors.Is(err, io.ErrClosedPipe)) {
				err = nil
			}
			inputDone <- inputResult{copyErr: err}
			return
		}
		closeErr := withOperation("send stdin EOF", "Could not finish sending input to the remote process. Check the connection and process state.", remoteInput.Close())
		if err != nil || closeErr != nil && !errors.Is(closeErr, context.Canceled) {
			err = errors.Join(err, withOperation("stop remote command", "Could not terminate the remote process. It may still be running; ask an administrator to check.", closeCommand()))
		}
		inputDone <- inputResult{err, closeErr}
	}()
	outputDone := make(chan error, 2)
	for _, output := range []struct {
		dst  io.Writer
		src  io.Reader
		name string
	}{{stdout, remoteOutput, "stdout"}, {stderr, remoteError, "stderr"}} {
		go func() {
			_, err := io.Copy(output.dst, output.src)
			if err != nil {
				err = errors.Join(
					withOperation("copy remote "+output.name, "Could not stream remote "+output.name+". Check the local output destination and connection; see Details.", err),
					withOperation("stop remote command", "Could not terminate the remote process. It may still be running; ask an administrator to check.", closeCommand()),
				)
			}
			outputDone <- err
		}()
	}
	wait()
	closeInput()
	close(sessionDone)
	<-watcherDone
	input := <-inputDone
	// The command can finish while its stdin EOF request is still in flight.
	if ctx.Err() == nil && commandError() == nil && isCancellationOnly(input.closeErr) {
		input.closeErr = nil
	}
	if ctx.Err() == nil && commandError() == nil && isCancellationOnly(input.copyErr) {
		input.copyErr = nil
	}
	outputErr := errors.Join(<-outputDone, <-outputDone)
	return exitCode(), errors.Join(
		withOperation("receive remote output", "The remote command failed while receiving output. Check the connection and server diagnostics in Details.", commandError()),
		input.copyErr, input.closeErr, inputCloseErr, outputErr,
		withOperation("stop remote command", "Could not terminate the remote process. It may still be running; ask an administrator to check.", closeCommand()),
	)
}
