package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestInterruptHandlerSwitches(t *testing.T) {
	local, remote := 0, 0
	handler := &interruptHandler{handle: func() { local++ }}
	handler.dispatch()
	handler.set(func() { remote++ })
	handler.dispatch()
	handler.dispatch()
	handler.set(func() { local++ })
	handler.dispatch()
	if local != 2 || remote != 2 {
		t.Fatalf("local cancellations=%d remote interrupts=%d", local, remote)
	}
}

func TestForwardInterruptDoesNotCancelSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	var stderr bytes.Buffer
	handler := forwardInterrupt(ctx, func(ctx context.Context) error {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 5*time.Second {
			t.Fatal("interrupt is not bounded")
		}
		return nil
	}, &stderr)
	handler()
	handler()
	if calls != 2 || ctx.Err() != nil || stderr.Len() != 0 {
		t.Fatalf("calls=%d canceled=%v stderr=%q", calls, ctx.Err(), stderr.String())
	}
	failure := errors.New("remote rejected Ctrl+C")
	forwardInterrupt(ctx, func(context.Context) error { return failure }, &stderr)()
	if ctx.Err() != nil || !strings.Contains(stderr.String(), "session remains open") ||
		!strings.Contains(stderr.String(), "Details: forward Ctrl+C: remote rejected Ctrl+C") {
		t.Fatalf("failed interrupt did not preserve session or diagnostics: %q", stderr.String())
	}
}

func TestPipedAndSingleCommandInputNotInteractive(t *testing.T) {
	if interactiveInput(options{}, io.NopCloser(strings.NewReader(""))) ||
		interactiveInput(options{command: "whoami"}, io.NopCloser(strings.NewReader(""))) {
		t.Fatal("nonterminal input enabled interrupt forwarding")
	}
}

func TestTerminalStreamCanCloseWhileReadBlocks(t *testing.T) {
	source, writer := io.Pipe()
	defer source.Close()
	defer writer.Close()
	input := terminalStreamInput(source)
	done := make(chan error, 1)
	go func() {
		_, err := input.Read(make([]byte, 1))
		done <- err
	}()
	if err := input.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("unexpected read error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("session read remained blocked on terminal input")
	}
}
