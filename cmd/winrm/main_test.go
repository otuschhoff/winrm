package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestParseOptions(t *testing.T) {
	tests := []struct {
		name string
		args []string
		port int
	}{
		{"default", []string{"-host", "windows.example.com", "-user", "alice"}, 5985},
		{"https", []string{"-host", "windows", "-user", "alice", "-https"}, 5986},
		{"cache", []string{"-host", "windows", "-ccache", "/tmp/cache"}, 5985},
		{"custom", []string{"-host", "windows", "-user", "alice", "-port", "1234"}, 1234},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o, err := parseOptions(tt.args, io.Discard)
			if err != nil || o.port != tt.port {
				t.Fatalf("port = %d, err = %v", o.port, err)
			}
		})
	}
	for _, args := range [][]string{
		{}, {"-host", "http://windows", "-user", "alice"},
		{"-host", "windows", "-user", "alice", "-auth", "basic"},
		{"-host", "windows", "-user", "alice", "-shell", "bash"},
		{"-host", "windows", "-user", "alice", "-port", "65536"},
		{"-host", "windows", "-user", "alice", "-timeout", "0s"},
		{"-host", "windows", "-user", "alice", "-ccache", "cache", "-password-file", "pw"},
		{"-host", "windows", "-user", "alice", "extra"},
	} {
		if _, err := parseOptions(args, io.Discard); err == nil {
			t.Fatalf("expected rejection: %v", args)
		}
	}
}

func TestSSHOptions(t *testing.T) {
	for _, tt := range []struct {
		name, host, login, command string
		args                       []string
		port                       int
	}{
		{"destination", "windows.example.com", "alice", "", []string{"alice@windows.example.com"}, 5985},
		{"login flag", "windows", "alice", "", []string{"-l", "alice", "windows"}, 5985},
		{"explicit login wins", "windows", "alice", "", []string{"-l", "alice", "bob@windows"}, 5985},
		{"port flag", "windows", "alice", "", []string{"-p", "1234", "alice@windows"}, 1234},
		{"attached flags", "windows", "alice", "", []string{"-p1234", "-lalice", "windows"}, 1234},
		{"grouped flags", "windows", "alice", "", []string{"-Tp1234", "-lalice", "windows"}, 1234},
		{"no tty", "windows", "alice", "", []string{"-T", "alice@windows"}, 5985},
		{"remote command", "windows", "alice", "cmd /c echo hello", []string{"alice@windows", "cmd", "/c", "echo", "hello"}, 5985},
		{"remote flags untouched", "windows", "alice", "tool -p123 -lremote -T", []string{"alice@windows", "tool", "-p123", "-lremote", "-T"}, 5985},
		{"principal login", "windows", "alice@EXAMPLE.COM", "", []string{"alice@EXAMPLE.COM@windows"}, 5985},
		{"IPv6", "::1", "alice", "", []string{"alice@[::1]"}, 5985},
		{"legacy mixed", "windows", "alice", "whoami", []string{"-user", "alice", "-command", "whoami", "windows"}, 5985},
		{"end options", "windows", "alice", "", []string{"--", "alice@windows"}, 5985},
		{"https", "windows", "alice", "", []string{"-https", "alice@windows"}, 5986},
	} {
		t.Run(tt.name, func(t *testing.T) {
			o, err := parseOptions(tt.args, io.Discard)
			if err != nil {
				t.Fatal(err)
			}
			if o.host != tt.host || o.user != tt.login || o.command != tt.command || o.port != tt.port {
				t.Fatalf("unexpected options: host=%q user=%q command=%q port=%d", o.host, o.user, o.command, o.port)
			}
		})
	}
	for _, args := range [][]string{
		{"-t", "alice@windows"}, {"-tt", "alice@windows"},
		{"-host", "windows", "alice@another"},
		{"-command", "whoami", "alice@windows", "hostname"},
		{"alice@"}, {"@windows"}, {"-pnot-a-port", "windows"},
		{"-L", "8080:localhost:80", "windows"},
		{"-l"}, {"-p"},
		{"alice@[::1"}, {"alice@::1]"}, {"alice@[windows]"},
	} {
		if _, err := parseOptions(args, io.Discard); err == nil {
			t.Fatalf("expected rejection: %v", args)
		}
	}
	o, err := parseOptions([]string{"windows"}, io.Discard)
	if err != nil || o.user == "" {
		t.Fatalf("local username default: user=%q err=%v", o.user, err)
	}
	var help bytes.Buffer
	if code, err := run(context.Background(), []string{"-h"}, io.NopCloser(strings.NewReader("")), io.Discard, &help); code != 0 || err != nil {
		t.Fatalf("help failed: code=%d err=%v", code, err)
	}
	if !strings.Contains(help.String(), "[user@]host [command") {
		t.Fatal("help does not describe SSH-style syntax")
	}
}

func TestHelpAndMissingPassword(t *testing.T) {
	code, err := run(context.Background(), []string{"-help"}, io.NopCloser(strings.NewReader("")), io.Discard, io.Discard)
	if code != 0 || err != nil {
		t.Fatalf("help: code %d, err %v", code, err)
	}
	t.Setenv("WINRM_PASSWORD", "")
	_, err = newClient(options{user: "alice"}, func() (string, error) {
		return promptPassword(context.Background(), io.NopCloser(strings.NewReader("")), io.Discard)
	})
	if err == nil || !strings.Contains(err.Error(), "password") {
		t.Fatalf("missing password: %v", err)
	}
}

func TestResolvePassword(t *testing.T) {
	dir := t.TempDir()
	passwordFile := filepath.Join(dir, "sample.password")
	if err := os.WriteFile(passwordFile, []byte(" file secret \r\n"), 0600); err != nil {
		t.Fatal(err)
	}
	emptyFile := filepath.Join(dir, "empty.password")
	if err := os.WriteFile(emptyFile, []byte("\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("prompt failed")
	for _, tt := range []struct {
		name, env, prompted, want string
		options                   options
		promptErr                 error
		wantPrompt, wantErr       bool
	}{
		{name: "prompt", prompted: " secret ", want: " secret ", wantPrompt: true},
		{name: "environment", env: "env secret", want: "env secret"},
		{name: "file precedence", env: "env secret", options: options{passwordFile: passwordFile}, want: " file secret "},
		{name: "empty file", env: "env secret", options: options{passwordFile: emptyFile}, prompted: "prompt secret", want: "prompt secret", wantPrompt: true},
		{name: "unreadable file", options: options{passwordFile: dir}, wantErr: true},
		{name: "cache", env: "env secret", options: options{ccache: "cache"}},
		{name: "empty prompt", wantPrompt: true, wantErr: true},
		{name: "prompt error", promptErr: sentinel, wantPrompt: true, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("WINRM_PASSWORD", tt.env)
			called := false
			password, err := resolvePassword(tt.options, func() (string, error) {
				called = true
				return tt.prompted, tt.promptErr
			})
			if password != tt.want || (err != nil) != tt.wantErr || called != tt.wantPrompt {
				t.Fatalf("password match=%v err=%v prompted=%v", password == tt.want, err, called)
			}
			if tt.promptErr != nil && !errors.Is(err, tt.promptErr) {
				t.Fatal("prompt error lost")
			}
		})
	}
}

func TestPasswordPromptDoesNotConsumePipe(t *testing.T) {
	input := strings.NewReader("remote command\n")
	_, err := promptPassword(context.Background(), io.NopCloser(input), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "terminal stdin") {
		t.Fatalf("nonterminal prompt error: %v", err)
	}
	if input.Len() != len("remote command\n") {
		t.Fatal("prompt consumed remote command input")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := promptPassword(ctx, io.NopCloser(input), io.Discard); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled prompt: %v", err)
	}
}

func TestCopyLines(t *testing.T) {
	input := "first\nsecond\r\n" + strings.Repeat("x", 100000) + "\nlast"
	var dst bytes.Buffer
	if err := copyLines(&dst, strings.NewReader(input)); err != nil {
		t.Fatal(err)
	}
	want := "first\r\nsecond\r\n" + strings.Repeat("x", 100000) + "\r\nlast"
	if dst.String() != want {
		t.Fatal("line endings or long input corrupted")
	}
	sentinel := errors.New("write failed")
	if err := copyLines(errorWriter{sentinel}, strings.NewReader("hello\n")); !errors.Is(err, sentinel) {
		t.Fatalf("write error lost: %v", err)
	}
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

type notificationWriter struct{ written chan string }

func (w notificationWriter) Write(p []byte) (int, error) {
	w.written <- string(p)
	return len(p), nil
}

func TestStreamOutputBeforeInputEOF(t *testing.T) {
	input, inputWriter := io.Pipe()
	defer inputWriter.Close()
	remoteInput, remoteInputWriter := io.Pipe()
	defer remoteInput.Close()
	remoteOutput, remoteOutputWriter := io.Pipe()
	defer remoteOutput.Close()
	finished := make(chan struct{})
	var finishOnce sync.Once
	finish := func() error {
		finishOnce.Do(func() { close(finished) })
		return nil
	}
	written := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		_, err := stream(context.Background(), remoteInputWriter, remoteOutput, strings.NewReader("stderr"),
			func() { <-finished }, finish, func() int { return 7 }, func() error { return nil },
			input, notificationWriter{written}, io.Discard)
		done <- err
	}()
	go func() {
		_, _ = io.WriteString(remoteOutputWriter, "prompt>")
		_ = remoteOutputWriter.Close()
	}()
	select {
	case text := <-written:
		if text != "prompt>" {
			t.Fatal(text)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("output blocked waiting for stdin EOF")
	}
	_ = finish()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("command completion did not unblock stdin")
	}
}

func TestStreamEOFAndExitCode(t *testing.T) {
	remoteInput, remoteInputWriter := io.Pipe()
	defer remoteInput.Close()
	finished := make(chan struct{})
	var received string
	go func() {
		data, _ := io.ReadAll(remoteInput)
		received = string(data)
		close(finished)
	}()
	var stdout, stderr bytes.Buffer
	code, err := stream(context.Background(), remoteInputWriter, strings.NewReader("out"), strings.NewReader("err"),
		func() { <-finished }, func() error { return nil }, func() int { return 7 }, func() error { return nil },
		io.NopCloser(strings.NewReader("exit /b 7\n")), &stdout, &stderr)
	if err != nil || code != 7 || received != "exit /b 7\r\n" || stdout.String() != "out" || stderr.String() != "err" {
		t.Fatalf("code=%d err=%v input=%q stdout=%q stderr=%q", code, err, received, stdout.String(), stderr.String())
	}
}

func TestStreamCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	input, inputWriter := io.Pipe()
	defer inputWriter.Close()
	finished := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := stream(ctx, nopWriteCloser{io.Discard}, strings.NewReader(""), strings.NewReader(""),
			func() { <-finished }, func() error { return nil }, func() int { return 0 }, ctx.Err,
			input, io.Discard, io.Discard)
		done <- err
	}()
	cancel()
	close(finished)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation lost: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation hung")
	}
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

type canceledEOFWriter struct {
	io.Writer
	done chan struct{}
}

func (w canceledEOFWriter) Close() error {
	close(w.done)
	return context.Canceled
}

func TestStreamNaturalExitDuringEOF(t *testing.T) {
	finished := make(chan struct{})
	code, err := stream(context.Background(), canceledEOFWriter{io.Discard, finished},
		strings.NewReader(""), strings.NewReader(""),
		func() { <-finished }, func() error { return nil }, func() int { return 7 }, func() error { return nil },
		io.NopCloser(strings.NewReader("exit /b 7\n")), io.Discard, io.Discard)
	if code != 7 || err != nil {
		t.Fatalf("natural completion reported as failure: code=%d err=%v", code, err)
	}
}

func TestStreamOutputError(t *testing.T) {
	sentinel := errors.New("output failed")
	finished := make(chan struct{})
	var once sync.Once
	code, err := stream(context.Background(), nopWriteCloser{io.Discard},
		strings.NewReader("output"), strings.NewReader(""),
		func() { <-finished }, func() error { once.Do(func() { close(finished) }); return nil },
		func() int { return 0 }, func() error { return nil },
		io.NopCloser(strings.NewReader("")), errorWriter{sentinel}, io.Discard)
	if code != 0 || !errors.Is(err, sentinel) {
		t.Fatalf("output error lost: code=%d err=%v", code, err)
	}
}
