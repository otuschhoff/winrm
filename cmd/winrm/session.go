package main

import (
	"bufio"
	"context"
	"errors"
	"io"
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
			if _, err := io.WriteString(dst, line); err != nil {
				return err
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
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
			inputCloseErr = stdin.Close()
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
			inputDone <- inputResult{}
			return
		}
		closeErr := remoteInput.Close()
		if err != nil || closeErr != nil && !errors.Is(closeErr, context.Canceled) {
			err = errors.Join(err, closeCommand())
		}
		inputDone <- inputResult{err, closeErr}
	}()
	outputDone := make(chan error, 2)
	for _, output := range []struct {
		dst io.Writer
		src io.Reader
	}{{stdout, remoteOutput}, {stderr, remoteError}} {
		go func() {
			_, err := io.Copy(output.dst, output.src)
			if err != nil {
				err = errors.Join(err, closeCommand())
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
	if ctx.Err() == nil && commandError() == nil && errors.Is(input.closeErr, context.Canceled) {
		input.closeErr = nil
	}
	outputErr := errors.Join(<-outputDone, <-outputDone)
	return exitCode(), errors.Join(commandError(), input.copyErr, input.closeErr, inputCloseErr, outputErr, closeCommand())
}
