package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/winrm"
)

func TestResolveTarget(t *testing.T) {
	for _, host := range []string{"192.0.2.47", "2001:db8::47"} {
		o, err := resolveTarget(context.Background(), options{host: host, timeout: time.Second},
			func(ctx context.Context, address string) ([]string, error) {
				if address != host {
					t.Fatalf("lookup address=%q want=%q", address, host)
				}
				if _, ok := ctx.Deadline(); !ok {
					t.Fatal("lookup has no deadline")
				}
				return []string{"192.0.2.1", "bad/name", "win-host-47.example.com.", "other.example.com."}, nil
			})
		if err != nil || o.host != host || o.identityHost != "win-host-47.example.com" ||
			targetIdentity(o) != "win-host-47.example.com" {
			t.Fatalf("host=%q identity=%q err=%v", o.host, o.identityHost, err)
		}
	}
	o, err := resolveTarget(context.Background(), options{host: "windows.example.com"},
		func(context.Context, string) ([]string, error) {
			t.Fatal("hostname triggered reverse DNS")
			return nil, nil
		})
	if err != nil || targetIdentity(o) != "windows.example.com" {
		t.Fatalf("hostname behavior changed: %v", err)
	}
}

func TestResolveTargetFailures(t *testing.T) {
	sentinel := errors.New("PTR lookup failed")
	for _, tt := range []struct {
		names []string
		err   error
	}{
		{err: sentinel}, {},
		{names: []string{"", ".", "192.0.2.47", "2001:db8::47", "-bad.example.com", "bad-.example.com", "bad..example.com", "bad/name", "bad@name"}},
	} {
		_, err := resolveTarget(context.Background(), options{host: "192.0.2.47", timeout: time.Second},
			func(context.Context, string) ([]string, error) { return tt.names, tt.err })
		if err == nil {
			t.Fatal("lookup failure silently fell back to IP identity")
		}
		if tt.err != nil && !errors.Is(err, tt.err) {
			t.Fatal("lookup failure lost its cause")
		}
		report := formatCLIError(err)
		if !strings.Contains(report, "reverse-DNS PTR") || !strings.Contains(report, "Details:") {
			t.Fatalf("missing resolution guidance: %q", report)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := resolveTarget(ctx, options{host: "192.0.2.47", timeout: time.Second},
		func(ctx context.Context, _ string) ([]string, error) { return nil, ctx.Err() })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	_, err = resolveTarget(context.Background(), options{host: "192.0.2.47", timeout: time.Millisecond},
		func(ctx context.Context, _ string) ([]string, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lookup timeout lost: %v", err)
	}
}

func TestIPKerberosIdentity(t *testing.T) {
	t.Setenv("WINRM_PASSWORD", "representative-test-password")
	configPath := filepath.Join(t.TempDir(), "krb5.conf")
	if err := os.WriteFile(configPath, []byte("[libdefaults]\n default_realm = EXAMPLE.COM\n"), 0600); err != nil {
		t.Fatal(err)
	}
	o, err := parseOptions([]string{"-krb-config", configPath, "alice@192.0.2.47"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	o, err = resolveTarget(context.Background(), o, func(context.Context, string) ([]string, error) {
		return []string{"win-host-47.example.com."}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := newClient(o, func() (string, error) {
		t.Fatal("unexpected password prompt")
		return "", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	transport, ok := client.TransportDecorator().(*winrm.ClientKerberos)
	if !ok || transport.SPN != "HTTP/win-host-47.example.com" || o.host != "192.0.2.47" {
		t.Fatal("Kerberos did not use hostname SPN while preserving the IP target")
	}
}

func TestIPResolutionPrecedesCredentials(t *testing.T) {
	t.Setenv("WINRM_PASSWORD", "")
	failure := errors.New("no PTR record")
	code, err := runWithResolver(context.Background(), []string{"alice@192.0.2.47"},
		io.NopCloser(strings.NewReader("")), io.Discard, io.Discard,
		func(context.Context, string) ([]string, error) { return nil, failure })
	if code != 1 || !errors.Is(err, failure) {
		t.Fatalf("resolution did not precede password prompting: code=%d err=%v", code, err)
	}
}
