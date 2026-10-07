package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

func resolvePassword(o options, prompt func() (string, error)) (string, error) {
	if o.ccache != "" {
		return "", nil
	}
	password := os.Getenv("WINRM_PASSWORD")
	if o.passwordFile != "" {
		data, err := os.ReadFile(o.passwordFile)
		if err != nil {
			return "", fmt.Errorf("read password file: %w", err)
		}
		password = strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	}
	if password == "" {
		var err error
		password, err = prompt()
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		if password == "" {
			return "", errors.New("password must not be empty")
		}
	}
	return password, nil
}

func promptPassword(ctx context.Context, stdin io.ReadCloser, stderr io.Writer) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	input, ok := stdin.(*os.File)
	if !ok || !term.IsTerminal(int(input.Fd())) {
		return "", errors.New("password prompt requires terminal stdin; provide -password-file or WINRM_PASSWORD, or use -ccache")
	}
	fd := int(input.Fd())
	state, err := term.GetState(fd)
	if err != nil {
		return "", err
	}
	if _, err := fmt.Fprint(stderr, "Password: "); err != nil {
		return "", err
	}
	type result struct {
		password []byte
		err      error
	}
	done := make(chan result, 1)
	go func() {
		password, err := term.ReadPassword(fd)
		done <- result{password, err}
	}()
	var password []byte
	select {
	case r := <-done:
		password, err = r.password, r.err
	case <-ctx.Done():
		// ReadPassword may still be blocked when the process exits.
		err = errors.Join(ctx.Err(), term.Restore(fd, state))
	}
	_, newlineErr := fmt.Fprintln(stderr)
	if err = errors.Join(err, newlineErr); err != nil {
		return "", err
	}
	return string(password), nil
}
