package winrm

import (
	"context"
	"errors"
	"sync"
	"time"
)

const shellCleanupTimeout = 5 * time.Second

// Shell is the local view of a WinRM Shell of a given Client
type Shell struct {
	client   *Client
	id       string
	gate     chan struct{}
	gateOnce sync.Once
	closed   bool
	closeErr error
}

func newShell(client *Client, id string) *Shell {
	shell := &Shell{client: client, id: id}
	shell.initGate()
	return shell
}

func (s *Shell) initGate() {
	s.gateOnce.Do(func() {
		s.gate = make(chan struct{}, 1)
		s.gate <- struct{}{}
	})
}

func (s *Shell) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.initGate()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.gate:
		if err := ctx.Err(); err != nil {
			s.release()
			return err
		}
		return nil
	}
}

func (s *Shell) release() { s.gate <- struct{}{} }

// Execute command on the given Shell, returning either an error or a Command
//
// Deprecated: user ExecuteWithContext
func (s *Shell) Execute(command string, arguments ...string) (*Command, error) {
	return s.ExecuteWithContext(context.Background(), command, arguments...)
}

// ExecuteWithContext command on the given Shell, returning either an error or a Command
func (s *Shell) ExecuteWithContext(ctx context.Context, command string, arguments ...string) (*Command, error) {
	return s.executeWithContext(ctx, command, true, arguments...)
}

func (s *Shell) executeWithContext(ctx context.Context, command string, startOutput bool, arguments ...string) (*Command, error) {
	if err := s.acquire(ctx); err != nil {
		return nil, err
	}
	defer s.release()
	if s.closed {
		return nil, errors.New("WinRM shell is closed")
	}
	operationContext, finishOperation, err := s.client.beginOperation(ctx)
	if err != nil {
		return nil, err
	}
	defer finishOperation()
	request := NewExecuteCommandRequest(s.client.url, s.id, command, arguments, &s.client.Parameters)
	defer request.Free()

	response, err := s.client.sendRequestContext(operationContext, request)
	if err != nil {
		return nil, err
	}

	commandID, err := ParseExecuteCommandResponse(response)
	if err != nil {
		return nil, err
	}

	createdCommand, err := newCommandWithOutput(ctx, s, commandID, startOutput)
	if err != nil {
		cleanupContext, cancel := context.WithTimeout(context.Background(), commandCleanupTimeout)
		defer cancel()
		return nil, errors.Join(err, s.cleanupRemoteCommand(cleanupContext, commandID))
	}
	return createdCommand, nil
}

func (s *Shell) cleanupRemoteCommand(ctx context.Context, commandID string) error {
	request := NewSignalRequest(s.client.url, s.id, commandID, &s.client.Parameters)
	defer request.Free()
	_, err := s.client.sendRequestContext(ctx, request)
	return err
}

// Close will terminate this shell. No commands can be issued once the shell is closed.
func (s *Shell) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), shellCleanupTimeout)
	defer cancel()
	return s.CloseWithContext(ctx)
}

// CloseWithContext deletes the remote shell using the supplied cleanup context.
func (s *Shell) CloseWithContext(ctx context.Context) error {
	if err := s.acquire(ctx); err != nil {
		return err
	}
	defer s.release()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	request := NewDeleteShellRequest(s.client.url, s.id, &s.client.Parameters)
	defer request.Free()

	_, s.closeErr = s.client.sendRequestContext(ctx, request)
	s.client.unregisterShell(s)
	return s.closeErr
}
