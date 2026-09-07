package winrm

import (
	"context"
	"time"
)

const shellCleanupTimeout = 5 * time.Second

// Shell is the local view of a WinRM Shell of a given Client
type Shell struct {
	client *Client
	id     string
}

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
	request := NewExecuteCommandRequest(s.client.url, s.id, command, arguments, &s.client.Parameters)
	defer request.Free()

	response, err := s.client.sendRequestContext(ctx, request)
	if err != nil {
		return nil, err
	}

	commandID, err := ParseExecuteCommandResponse(response)
	if err != nil {
		return nil, err
	}

	return newCommandWithOutput(ctx, s, commandID, startOutput)
}

// Close will terminate this shell. No commands can be issued once the shell is closed.
func (s *Shell) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), shellCleanupTimeout)
	defer cancel()
	return s.CloseWithContext(ctx)
}

// CloseWithContext deletes the remote shell using the supplied cleanup context.
func (s *Shell) CloseWithContext(ctx context.Context) error {
	request := NewDeleteShellRequest(s.client.url, s.id, &s.client.Parameters)
	defer request.Free()

	_, err := s.client.sendRequestContext(ctx, request)
	return err
}
