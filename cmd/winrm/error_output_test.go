package main

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBinaryErrorOutput(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, summary string
		args          []string
		exit          int
	}{
		{"unknown flag", "Invalid command-line options", []string{"-unknown-option"}, 2},
		{"invalid port", "Invalid command-line options", []string{"-p", "invalid", "alice@windows.example.com"}, 2},
		{"missing credential", "stdin is not an interactive terminal", []string{"alice@windows.example.com"}, 1},
		{"missing file", "was not found", []string{"-password-file", filepath.Join(t.TempDir(), "missing.password"), "alice@windows.example.com"}, 1},
		{"help", "Usage: winrm", []string{"-help"}, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			args := append([]string{"-test.run=^TestCLIProcess$", "--"}, tt.args...)
			cmd := exec.CommandContext(ctx, executable, args...)
			cmd.Env = append(os.Environ(), "WINRM_CLI_TEST_PROCESS=1", "WINRM_PASSWORD=")
			cmd.Stdin = strings.NewReader("")
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			var exit *exec.ExitError
			code := 0
			if err != nil {
				if !errors.As(err, &exit) {
					t.Fatal(err)
				}
				code = exit.ExitCode()
			}
			if code != tt.exit || stdout.Len() != 0 || !strings.Contains(stderr.String(), tt.summary) {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if code != 0 {
				if strings.Count(stderr.String(), "Details:") != 1 || strings.Contains(stderr.String(), "Usage: winrm") {
					t.Fatalf("error output duplicated or missing diagnostics: %q", stderr.String())
				}
			} else if strings.Contains(stderr.String(), "Details:") {
				t.Fatal("help was reported as an error")
			}
		})
	}
}

func TestKerberosConfigurationErrorHint(t *testing.T) {
	t.Setenv("WINRM_PASSWORD", "representative-test-password")
	code, err := run(context.Background(),
		[]string{"-krb-config", filepath.Join(t.TempDir(), "missing.conf"), "alice@windows.example.com"},
		io.NopCloser(strings.NewReader("")), io.Discard, io.Discard)
	if code != 1 || err == nil {
		t.Fatalf("missing configuration: code=%d err=%v", code, err)
	}
	summary, details, ok := strings.Cut(formatCLIError(err), "\n  Details: ")
	if !ok || !strings.Contains(summary, "Could not load the Kerberos configuration") || !strings.Contains(details, "missing.conf") {
		t.Fatalf("configuration failure lacks specific guidance or original details: %q", formatCLIError(err))
	}
}

func TestKerberosUsernameAndRealmHints(t *testing.T) {
	t.Setenv("WINRM_PASSWORD", "representative-test-password")
	configuration := filepath.Join(t.TempDir(), "krb5.conf")
	if err := os.WriteFile(configuration, []byte("[libdefaults]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		args []string
		hint string
	}{
		{[]string{"-l", "alice@BAD@EXAMPLE.COM", "windows.example.com"}, "username is invalid"},
		{[]string{"-realm", "OTHER.EXAMPLE.COM", "alice@EXAMPLE.COM@windows.example.com"}, "realm and -realm do not match"},
		{[]string{"-krb-config", configuration, "alice@windows.example.com"}, "realm is missing"},
	} {
		code, err := run(context.Background(), tt.args, io.NopCloser(strings.NewReader("")), io.Discard, io.Discard)
		if code != 1 || err == nil {
			t.Fatalf("invalid configuration: code=%d err=%v", code, err)
		}
		summary, _, _ := strings.Cut(formatCLIError(err), "\n")
		if !strings.Contains(summary, tt.hint) {
			t.Fatalf("missing configuration guidance: %q", summary)
		}
	}
}

func TestBasicHTTPErrorPresentation(t *testing.T) {
	t.Setenv("WINRM_PASSWORD", "representative-test-password")
	for _, tt := range []struct {
		status  int
		summary string
	}{
		{401, "rejected authentication"},
		{403, "refused the request"},
		{404, "endpoint was not found"},
		{500, "server returned HTTP 500"},
		{200, "valid WinRM SOAP response"},
	} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(tt.status)
			_, _ = io.WriteString(w, "private-server-response-must-not-be-displayed")
		}))
		t.Cleanup(server.Close)
		u, err := url.Parse(server.URL)
		if err != nil {
			t.Fatal(err)
		}
		host, port, err := net.SplitHostPort(u.Host)
		if err != nil {
			t.Fatal(err)
		}
		caPath := filepath.Join(t.TempDir(), "ca.pem")
		if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		code, resultErr := run(ctx, []string{"-auth", "basic", "-https", "-ca", caPath, "-p", port, "alice@" + host},
			io.NopCloser(strings.NewReader("")), io.Discard, io.Discard)
		cancel()
		server.Close()
		if code != 1 || resultErr == nil {
			t.Fatalf("HTTP %d: exit=%d err=%v", tt.status, code, resultErr)
		}
		report := formatCLIError(resultErr)
		if !strings.Contains(report, tt.summary) || !strings.Contains(report, "\n  Details: ") ||
			strings.Contains(report, "private-server-response") || strings.Contains(report, "representative-test-password") {
			t.Fatalf("HTTP %d: invalid or sensitive error report: %q", tt.status, report)
		}
	}
}
