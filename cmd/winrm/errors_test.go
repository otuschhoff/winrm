package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/winrm"
)

func TestFormatCLIError(t *testing.T) {
	negotiate := func(err error) error {
		return &winrm.KerberosError{Stage: "negotiate", Err: err}
	}
	failedPassword := messages.KRBError{ErrorCode: errorcode.KDC_ERR_PREAUTH_FAILED}
	rejectedCredentials := "authentication failed: Kerberos rejected your credentials. Check username, password, and realm (KDC_ERR_PREAUTH_FAILED)."
	accessDenied := "authorization failed: authentication succeeded, but Windows denied WinRM access (ERROR_ACCESS_DENIED, code 5). Ask an administrator to check WinRM permissions."
	for _, tt := range []struct {
		name string
		err  error
		want string
	}{
		{"typed value", negotiate(failedPassword), rejectedCredentials},
		{"typed pointer", negotiate(&failedPassword), rejectedCredentials},
		{"structured chain", negotiate(krberror.Errorf(failedPassword, krberror.KDCError, "AS exchange failed")), rejectedCredentials},
		{"legacy chain", negotiate(fmt.Errorf("could not acquire client credential: could not get valid TGT for client's realm: %v", krberror.Errorf(failedPassword, krberror.KDCError, "AS Exchange Error"))), rejectedCredentials},
		{"wrapper details", fmt.Errorf("connect to windows.example.com: %w", negotiate(failedPassword)), rejectedCredentials},
		{"connect context", withOperation("connect to windows.example.com", "", negotiate(failedPassword)), "connect to windows.example.com: " + rejectedCredentials},
		{"unknown account", negotiate(messages.KRBError{ErrorCode: errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN}), "authentication failed: Kerberos could not find the account. Check username and realm (KDC_ERR_C_PRINCIPAL_UNKNOWN)."},
		{"expired password", negotiate(messages.KRBError{ErrorCode: errorcode.KDC_ERR_KEY_EXPIRED}), "authentication failed: your Kerberos password has expired. Change it before reconnecting (KDC_ERR_KEY_EXPIRED)."},
		{"revoked account", negotiate(messages.KRBError{ErrorCode: errorcode.KDC_ERR_CLIENT_REVOKED}), "authentication failed: Kerberos rejected the account as revoked, disabled, or locked. Contact your administrator (KDC_ERR_CLIENT_REVOKED)."},
		{"access denied", &winrm.KerberosError{Stage: "soap", StatusCode: 500, Err: &winrm.SOAPFaultError{WSManCode: "5"}}, accessDenied},
		{"HRESULT access denied", &winrm.KerberosError{Stage: "soap", StatusCode: 500, Err: &winrm.SOAPFaultError{WSManCode: "2147942405"}}, accessDenied},
		{"hex access denied", &winrm.KerberosError{Stage: "soap", StatusCode: 500, Err: &winrm.SOAPFaultError{WSManCode: "0x80070005"}}, accessDenied},
		{"plain SOAP", &winrm.SOAPFaultError{WSManCode: "5"}, "authorization failed: Windows denied WinRM access (ERROR_ACCESS_DENIED, code 5). Ask an administrator to check WinRM permissions."},
	} {
		t.Run(tt.name, func(t *testing.T) {
			want := tt.want + "\n  Details: " + tt.err.Error()
			if got := formatCLIError(tt.err); got != want {
				t.Fatalf("message=%q want=%q", got, want)
			}
		})
	}
}

func TestUnclassifiedErrorsPreserveDetails(t *testing.T) {
	for _, err := range []error{
		errors.New("network unavailable"),
		&winrm.KerberosError{Stage: "http", StatusCode: 500, Err: errors.New("server failure")},
		&winrm.KerberosError{Stage: "soap", StatusCode: 500, Err: &winrm.SOAPFaultError{WSManCode: "123", Reason: "server runtime error"}},
		&winrm.KerberosError{Stage: "negotiate", Err: errors.New("KRB Error: (25) KDC_ERR_PREAUTH_FAILED")},
		&winrm.KerberosError{Stage: "negotiate", Err: errors.New("KRB Error: (24) KDC_ERR_PREAUTH_REQUIRED")},
		&winrm.KerberosError{Stage: "negotiate", Err: errors.New("KDC_ERR_PREAUTH_FAILED without a protocol code")},
		&winrm.KerberosError{Stage: "config", Err: errors.New("KRB Error: (24) KDC_ERR_PREAUTH_FAILED")},
		&winrm.KerberosError{Stage: "negotiate", Err: messages.KRBError{ErrorCode: errorcode.KRB_AP_ERR_SKEW}},
	} {
		got := formatCLIError(err)
		if !strings.HasSuffix(got, "\n  Details: "+err.Error()) {
			t.Fatalf("unclassified error details lost: got=%q want details=%q", got, err.Error())
		}
		summary := strings.SplitN(got, "\n", 2)[0]
		if summary == "" || strings.Contains(summary, "password is wrong") && !strings.Contains(summary, "not necessarily") {
			t.Fatalf("missing or misleading summary: %q", summary)
		}
	}
}

func TestCommonErrorSummaries(t *testing.T) {
	for _, tt := range []struct {
		name, summary string
		err           error
	}{
		{"DNS", "Could not resolve", &net.DNSError{Name: "missing.example.com", IsNotFound: true}},
		{"timeout", "timed out", context.DeadlineExceeded},
		{"network timeout", "timed out", &net.DNSError{Name: "slow.example.com", IsTimeout: true}},
		{"refused", "connection was refused", &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}},
		{"unreachable", "unreachable", syscall.ENETUNREACH},
		{"CA", "certificate is not trusted", x509.UnknownAuthorityError{}},
		{"hostname", "does not match", x509.HostnameError{Certificate: &x509.Certificate{}, Host: "wrong.example.com"}},
		{"expired cert", "invalid or expired", x509.CertificateInvalidError{Cert: &x509.Certificate{}, Reason: x509.Expired}},
		{"wrong listener", "did not speak TLS", tls.RecordHeaderError{Msg: "not TLS"}},
		{"missing file", "was not found", &os.PathError{Op: "open", Path: "example.password", Err: os.ErrNotExist}},
		{"file permission", "Permission denied", &os.PathError{Op: "open", Path: "example.password", Err: os.ErrPermission}},
		{"no terminal", "stdin is not an interactive terminal", errPasswordPromptUnavailable},
		{"empty password", "No password was entered", errEmptyPassword},
		{"canceled", "was canceled", context.Canceled},
		{"broken pipe", "pipe was closed", io.ErrClosedPipe},
		{"short write", "could not be written completely", io.ErrShortWrite},
		{"truncated stream", "ended unexpectedly", io.ErrUnexpectedEOF},
		{"HTTP authentication", "rejected authentication", &winrm.KerberosError{Stage: "http", StatusCode: 401, Err: errors.New("unauthorized")}},
		{"HTTP permission", "refused the request", &winrm.KerberosError{Stage: "http", StatusCode: 403, Err: errors.New("forbidden")}},
		{"HTTP endpoint", "endpoint was not found", &winrm.KerberosError{Stage: "http", StatusCode: 404, Err: errors.New("not found")}},
		{"HTTP server", "server returned HTTP 500", &winrm.KerberosError{Stage: "http", StatusCode: 500, Err: errors.New("server error")}},
		{"integrity", "message processing failed", &winrm.KerberosError{Stage: "unwrap", Err: errors.New("bad signature")}},
		{"config", "configuration could not be used", &winrm.KerberosError{Stage: "config", Err: errors.New("invalid cache")}},
		{"SPN", "service principal", &winrm.KerberosError{Stage: "negotiate", Err: messages.KRBError{ErrorCode: errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN}}},
		{"encryption", "encryption type", &winrm.KerberosError{Stage: "negotiate", Err: messages.KRBError{ErrorCode: errorcode.KDC_ERR_ETYPE_NOSUPP}}},
		{"clock skew", "Synchronize", &winrm.KerberosError{Stage: "negotiate", Err: messages.KRBError{ErrorCode: errorcode.KRB_AP_ERR_SKEW}}},
		{"expired ticket", "ticket expired", &winrm.KerberosError{Stage: "negotiate", Err: messages.KRBError{ErrorCode: errorcode.KRB_AP_ERR_TKT_EXPIRED}}},
		{"generic", "operation failed", errors.New("opaque failure")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			report := formatCLIError(fmt.Errorf("operation context: %w", tt.err))
			summary, details, ok := strings.Cut(report, "\n  Details: ")
			if !ok || !strings.Contains(summary, tt.summary) || !strings.Contains(details, tt.err.Error()) {
				t.Fatalf("report=%q want summary containing %q and original details", report, tt.summary)
			}
		})
	}
}

func TestHelpWriteFailure(t *testing.T) {
	failure := errors.New("help destination failed")
	code, err := run(context.Background(), []string{"-help"}, io.NopCloser(strings.NewReader("")), io.Discard, errorWriter{failure})
	if code != 1 || !errors.Is(err, failure) {
		t.Fatalf("help output failure: code=%d err=%v", code, err)
	}
	if !strings.Contains(formatCLIError(err), "Could not display help") {
		t.Fatal("help output failure was misclassified as invalid options")
	}
}

func TestErrorContextsAndJoinedFailures(t *testing.T) {
	primary := errors.New("remote operation failed")
	cleanup := errors.New("delete failed\nsecondary diagnostic")
	err := errors.Join(
		withOperation("receive remote output", "Could not receive remote output. Check the connection.", primary),
		withOperation("delete remote shell", "The remote shell could not be deleted.", cleanup),
		withOperation("delete remote shell", "The remote shell could not be deleted.", cleanup),
	)
	report := formatCLIError(err)
	if strings.Count(report, "Details:") != 2 || !strings.Contains(report, "Could not receive") ||
		!strings.Contains(report, "delete remote shell: delete failed\n    secondary diagnostic") {
		t.Fatalf("joined errors not preserved and deduplicated: %q", report)
	}
	if !errors.Is(err, primary) || !errors.Is(err, cleanup) {
		t.Fatal("operation context destroyed error chains")
	}
	if withOperation("operation", "hint", nil) != nil {
		t.Fatal("successful operation became an error")
	}
	wrappedJoin := withOperation("stream", "The stream failed.", errors.Join(primary, cleanup))
	if strings.Count(formatCLIError(wrappedJoin), "Details:") != 2 {
		t.Fatal("operation-wrapped joined errors not reported independently")
	}
	if !isCancellationOnly(fmt.Errorf("canceled: %w", context.Canceled)) ||
		isCancellationOnly(errors.Join(context.Canceled, cleanup)) || isCancellationOnly(nil) {
		t.Fatal("cancellation classification would discard a real failure")
	}
}

func TestReportResult(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tt := range []struct {
		name    string
		ctx     context.Context
		code    int
		err     error
		want    int
		summary string
	}{
		{"success", context.Background(), 0, nil, 0, ""},
		{"local error", context.Background(), 0, errors.New("opaque error"), 1, "operation failed"},
		{"invalid options", context.Background(), 2, withOperation("parse options", "", errors.New("unknown flag")), 2, "Invalid command-line options"},
		{"remote failure", context.Background(), 7, nil, 7, "remote process exited with status 7"},
		{"large exit", context.Background(), 300, nil, 1, "remote process exited with status 300"},
		{"cancel", canceled, 0, nil, 130, "was canceled"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var stderr bytes.Buffer
			if got := reportResult(tt.ctx, tt.code, tt.err, &stderr); got != tt.want {
				t.Fatalf("exit=%d want=%d", got, tt.want)
			}
			if tt.summary == "" {
				if stderr.Len() != 0 {
					t.Fatal("successful command produced an error report")
				}
			} else if !strings.HasPrefix(stderr.String(), "winrm: ") ||
				!strings.Contains(stderr.String(), tt.summary) || !strings.Contains(stderr.String(), "\n  Details: ") {
				t.Fatalf("missing two-level error output: %q", stderr.String())
			}
		})
	}
}
