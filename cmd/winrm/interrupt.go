package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/term"
)

type interruptHandler struct {
	mu     sync.Mutex
	handle func()
}

func (h *interruptHandler) set(handle func()) {
	h.mu.Lock()
	h.handle = handle
	h.mu.Unlock()
}

func (h *interruptHandler) dispatch() {
	h.mu.Lock()
	handle := h.handle
	h.mu.Unlock()
	handle()
}

func forwardInterrupt(ctx context.Context, interrupt func(context.Context) error, stderr io.Writer) func() {
	return func() {
		interruptContext, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		err := interrupt(interruptContext)
		if err != nil {
			fmt.Fprintln(stderr, "winrm:", formatCLIError(withOperation(
				"forward Ctrl+C", "Could not interrupt the remote process. The session remains open; check Details or disconnect with exit.", err)))
		}
	}
}

func interactiveInput(o options, stdin io.ReadCloser) bool {
	file, ok := stdin.(*os.File)
	return o.command == "" && ok && term.IsTerminal(int(file.Fd()))
}

func terminalStreamInput(stdin io.Reader) io.ReadCloser {
	reader, writer := io.Pipe()
	// A terminal Read may not unblock on Close. Only the forwarding goroutine
	// can remain blocked until process exit; the session reads a closable pipe.
	go func() {
		_, err := io.Copy(writer, stdin)
		_ = writer.CloseWithError(err)
	}()
	return reader
}
