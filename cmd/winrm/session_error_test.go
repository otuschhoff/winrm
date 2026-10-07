package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

type shortWriter struct{}

func (shortWriter) Write(data []byte) (int, error) { return len(data) - 1, nil }

func TestInputShortWriteIsReported(t *testing.T) {
	err := copyLines(shortWriter{}, strings.NewReader("hello\n"))
	if !errors.Is(err, io.ErrShortWrite) || !strings.Contains(formatCLIError(err), "send remote stdin") {
		t.Fatalf("short write was not reported with context: %v", err)
	}
}

type eofFailureWriter struct {
	io.Writer
	done chan struct{}
	err  error
}

func (w eofFailureWriter) Close() error {
	close(w.done)
	return w.err
}

func TestNaturalExitPreservesEOFFailure(t *testing.T) {
	finished := make(chan struct{})
	cleanup := errors.New("EOF cleanup failed")
	_, err := stream(context.Background(), eofFailureWriter{io.Discard, finished, errors.Join(context.Canceled, cleanup)},
		strings.NewReader(""), strings.NewReader(""),
		func() { <-finished }, func() error { return nil }, func() int { return 0 }, func() error { return nil },
		io.NopCloser(strings.NewReader("exit\n")), io.Discard, io.Discard)
	if !errors.Is(err, cleanup) {
		t.Fatalf("cleanup error was suppressed with cancellation: %v", err)
	}
}

type notifyingReader struct {
	io.Reader
	closed chan struct{}
}

func (r notifyingReader) Close() error {
	close(r.closed)
	return nil
}

type completionFailureWriter struct {
	finished, closed chan struct{}
	err              error
}

func (w completionFailureWriter) Write([]byte) (int, error) {
	close(w.finished)
	<-w.closed
	return 0, w.err
}

func (completionFailureWriter) Close() error { return nil }

func TestCompletionDoesNotHideInputWriteFailure(t *testing.T) {
	finished, closed := make(chan struct{}), make(chan struct{})
	failure := errors.New("input send failed")
	_, err := stream(context.Background(), completionFailureWriter{finished, closed, failure},
		strings.NewReader(""), strings.NewReader(""),
		func() { <-finished }, func() error { return nil }, func() int { return 0 }, func() error { return nil },
		notifyingReader{strings.NewReader("hello\n"), closed}, io.Discard, io.Discard)
	if !errors.Is(err, failure) || !strings.Contains(formatCLIError(err), "send remote stdin") {
		t.Fatalf("completion hid the input failure: %v", err)
	}
}
