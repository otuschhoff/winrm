package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"syscall"

	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/winrm"
)

var legacyKDCError = regexp.MustCompile(`KRB Error: \(([0-9]+)\) ((?:KDC_ERR|KRB_AP_ERR)_[A-Z0-9_]+)\b`)

type operationError struct {
	operation string
	hint      string
	err       error
}

func (e *operationError) Error() string { return e.operation + ": " + e.err.Error() }
func (e *operationError) Unwrap() error { return e.err }

func withOperation(operation, hint string, err error) error {
	if err == nil {
		return nil
	}
	return &operationError{operation: operation, hint: hint, err: err}
}

type remoteExitError struct{ code int }

func (e *remoteExitError) Error() string {
	return fmt.Sprintf("remote process exit code %d", e.code)
}

func formatCLIError(err error) string {
	var reports []string
	seen := make(map[string]bool)
	for _, cause := range errorParts(err) {
		detail := cause.Error()
		if seen[detail] {
			continue
		}
		seen[detail] = true
		summary := summarizeCLIError(cause)
		reports = append(reports, summary+"\n  Details: "+strings.ReplaceAll(detail, "\n", "\n    "))
	}
	return strings.Join(reports, "\n")
}

func errorParts(err error) []error {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var parts []error
		for _, cause := range joined.Unwrap() {
			parts = append(parts, errorParts(cause)...)
		}
		return parts
	}
	if operation, ok := err.(*operationError); ok {
		var parts []error
		for _, cause := range errorParts(operation.err) {
			parts = append(parts, withOperation(operation.operation, operation.hint, cause))
		}
		return parts
	}
	return []error{err}
}

func summarizeCLIError(err error) string {
	if operation, ok := err.(*operationError); ok {
		if operation.operation == "parse options" {
			return "Invalid command-line options. " + operation.err.Error() + " Run winrm -help for usage."
		}
		if summary := knownErrorSummary(operation.err); summary != "" {
			return operation.operation + ": " + summary
		}
		return operation.hint
	}
	if summary := knownErrorSummary(err); summary != "" {
		return summary
	}
	return "The operation failed. See Details below for the cause."
}

func knownErrorSummary(err error) string {
	if operation, ok := err.(*operationError); ok {
		return summarizeCLIError(operation)
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var summaries []string
		for _, cause := range joined.Unwrap() {
			summaries = append(summaries, summarizeCLIError(cause))
		}
		return strings.Join(summaries, " ")
	}
	if summary := systemErrorSummary(err); summary != "" {
		return summary
	}
	if kerberos, ok := err.(*winrm.KerberosError); ok {
		var fault *winrm.SOAPFaultError
		if kerberos.Stage == "soap" && errors.As(kerberos.Err, &fault) && isAccessDenied(fault) {
			return "authorization failed: authentication succeeded, but Windows denied WinRM access (ERROR_ACCESS_DENIED, code 5). Ask an administrator to check WinRM permissions."
		}
		if kerberos.Stage == "negotiate" {
			if message := kerberosAuthenticationMessage(kerberos.Err); message != "" {
				return message
			}
		}
		if errors.As(kerberos.Err, &fault) {
			return soapFaultSummary(fault)
		}
		if summary := httpStatusSummary(kerberos.StatusCode); summary != "" {
			return summary
		}
		switch kerberos.Stage {
		case "config":
			return "Kerberos configuration could not be used. Check the realm, krb5.conf, and credential cache."
		case "negotiate":
			return "Kerberos authentication could not be completed. Check the realm, KDC connectivity, and server SPN; this does not necessarily mean the password is wrong."
		case "wrap", "unwrap":
			return "Secure WinRM message processing failed. Check Kerberos interoperability and server logs; do not disable message protection as a workaround."
		case "http":
			return "The WinRM request failed. Check connectivity and the server listener; see Details for the transport error."
		case "close":
			return "Kerberos connection cleanup failed. Remote resources may need administrator attention."
		default:
			return "The Kerberos session failed. See Details for the failing stage."
		}
	}
	var fault *winrm.SOAPFaultError
	if errors.As(err, &fault) {
		return soapFaultSummary(fault)
	}
	var status interface{ HTTPStatusCode() int }
	if errors.As(err, &status) {
		if status.HTTPStatusCode() == 200 {
			return "The server did not return a valid WinRM SOAP response. Check the destination, port, and any proxy in between."
		}
		return httpStatusSummary(status.HTTPStatusCode())
	}
	var remoteExit *remoteExitError
	if errors.As(err, &remoteExit) {
		return fmt.Sprintf("The remote process exited with status %d. Check its output above; this is not a connection failure.", remoteExit.code)
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		if cause := wrapped.Unwrap(); cause != nil && strings.HasSuffix(err.Error(), cause.Error()) {
			if summary := knownErrorSummary(cause); summary != "" {
				return summary
			}
		}
	}
	return ""
}

func systemErrorSummary(err error) string {
	switch {
	case errors.Is(err, errPasswordPromptUnavailable):
		return "A password is required, but stdin is not an interactive terminal. Supply -password-file, WINRM_PASSWORD, or -ccache."
	case errors.Is(err, errEmptyPassword):
		return "No password was entered. Enter a nonempty password or supply credentials using -password-file, WINRM_PASSWORD, or -ccache."
	case errors.Is(err, context.Canceled):
		return "The operation was canceled. If you pressed Ctrl+C, the client is disconnecting."
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		if dns.IsTimeout {
			return fmt.Sprintf("The DNS lookup for %q timed out. Check DNS connectivity and configuration.", dns.Name)
		}
		return fmt.Sprintf("Could not resolve %q. Check the hostname and DNS configuration.", dns.Name)
	}
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var certificate x509.CertificateInvalidError
	var tlsHeader tls.RecordHeaderError
	switch {
	case errors.As(err, &authority):
		return "The HTTPS certificate is not trusted. Use -ca with the issuing CA certificate or install the correct CA."
	case errors.As(err, &hostname):
		return "The HTTPS certificate does not match the destination hostname. Use the certified hostname or correct the server certificate."
	case errors.As(err, &certificate):
		return "The HTTPS certificate is invalid or expired. Check its validity and the local clock."
	case errors.As(err, &tlsHeader):
		return "The server did not speak TLS. Check -https and -p against the configured WinRM listener."
	}
	var file *os.PathError
	if errors.As(err, &file) {
		switch {
		case errors.Is(err, os.ErrNotExist):
			return fmt.Sprintf("The file %q was not found. Check the supplied file path.", file.Path)
		case errors.Is(err, os.ErrPermission):
			return fmt.Sprintf("Permission denied for %q. Check the file's access permissions.", file.Path)
		default:
			return fmt.Sprintf("Could not access %q. Check the file or input/output device; see Details.", file.Path)
		}
	}
	var network net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &network) && network.Timeout():
		return "The operation timed out. Check network reachability and the server; increase -timeout if appropriate."
	case errors.Is(err, syscall.ECONNREFUSED):
		return "The connection was refused. Check the destination, -p, and whether the WinRM listener is running."
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "The network or host is unreachable. Check routing, VPN access, and firewall rules."
	case errors.Is(err, syscall.EPIPE), errors.Is(err, io.ErrClosedPipe):
		return "An input/output pipe was closed. Check the local pipeline and whether the remote process has exited."
	case errors.Is(err, io.ErrShortWrite):
		return "Output could not be written completely. Check the destination stream or file."
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "The connection or data stream ended unexpectedly. Check connectivity and the remote process; see Details."
	}
	return ""
}

func soapFaultSummary(fault *winrm.SOAPFaultError) string {
	if isAccessDenied(fault) {
		return "authorization failed: Windows denied WinRM access (ERROR_ACCESS_DENIED, code 5). Ask an administrator to check WinRM permissions."
	}
	return "Windows reported a WinRM fault. Check the fault code and reason in Details and the server's WinRM logs; this is not automatically an authentication failure."
}

func httpStatusSummary(status int) string {
	switch status {
	case 0, 200:
		return ""
	case 401:
		return "The server rejected authentication (HTTP 401). Check credentials and the authentication methods enabled on the WinRM listener."
	case 403:
		return "The server refused the request (HTTP 403). Check access policies and any proxy restrictions."
	case 404:
		return "The WinRM endpoint was not found (HTTP 404). Check the destination, -p, and listener configuration."
	default:
		return fmt.Sprintf("The server returned HTTP %d. Check Details and server or proxy logs; the status alone does not identify an authentication failure.", status)
	}
}

func isAccessDenied(fault *winrm.SOAPFaultError) bool {
	return fault.WSManCode == "5" || fault.WSManCode == "2147942405" || strings.EqualFold(fault.WSManCode, "0x80070005")
}

func isCancellationOnly(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		if len(joined.Unwrap()) == 0 {
			return false
		}
		for _, cause := range joined.Unwrap() {
			if !isCancellationOnly(cause) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok && wrapped.Unwrap() != nil {
		return isCancellationOnly(wrapped.Unwrap())
	}
	return errors.Is(err, context.Canceled)
}

func kerberosAuthenticationMessage(err error) string {
	var code int32
	var value messages.KRBError
	var pointer *messages.KRBError
	switch {
	case errors.As(err, &value):
		code = value.ErrorCode
	case errors.As(err, &pointer):
		code = pointer.ErrorCode
	default:
		// gokrb5's credential acquisition path uses %v and loses the error chain.
		match := legacyKDCError.FindStringSubmatch(err.Error())
		if len(match) == 0 {
			return ""
		}
		for _, candidate := range []struct {
			code int32
			name string
		}{
			{errorcode.KDC_ERR_PREAUTH_FAILED, "KDC_ERR_PREAUTH_FAILED"},
			{errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN, "KDC_ERR_C_PRINCIPAL_UNKNOWN"},
			{errorcode.KDC_ERR_KEY_EXPIRED, "KDC_ERR_KEY_EXPIRED"},
			{errorcode.KDC_ERR_CLIENT_REVOKED, "KDC_ERR_CLIENT_REVOKED"},
			{errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN, "KDC_ERR_S_PRINCIPAL_UNKNOWN"},
			{errorcode.KDC_ERR_ETYPE_NOSUPP, "KDC_ERR_ETYPE_NOSUPP"},
			{errorcode.KRB_AP_ERR_SKEW, "KRB_AP_ERR_SKEW"},
			{errorcode.KRB_AP_ERR_TKT_EXPIRED, "KRB_AP_ERR_TKT_EXPIRED"},
		} {
			if match[1] == fmt.Sprint(candidate.code) && match[2] == candidate.name {
				code = candidate.code
				break
			}
		}
	}
	switch code {
	case errorcode.KDC_ERR_PREAUTH_FAILED:
		return "authentication failed: Kerberos rejected your credentials. Check username, password, and realm (KDC_ERR_PREAUTH_FAILED)."
	case errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN:
		return "authentication failed: Kerberos could not find the account. Check username and realm (KDC_ERR_C_PRINCIPAL_UNKNOWN)."
	case errorcode.KDC_ERR_KEY_EXPIRED:
		return "authentication failed: your Kerberos password has expired. Change it before reconnecting (KDC_ERR_KEY_EXPIRED)."
	case errorcode.KDC_ERR_CLIENT_REVOKED:
		return "authentication failed: Kerberos rejected the account as revoked, disabled, or locked. Contact your administrator (KDC_ERR_CLIENT_REVOKED)."
	case errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN:
		return "Kerberos could not find the server's service principal. Check the destination FQDN and HTTP SPN registration (KDC_ERR_S_PRINCIPAL_UNKNOWN)."
	case errorcode.KDC_ERR_ETYPE_NOSUPP:
		return "Kerberos could not agree on an encryption type. Ask an administrator to check supported AES encryption settings (KDC_ERR_ETYPE_NOSUPP)."
	case errorcode.KRB_AP_ERR_SKEW:
		return "Kerberos rejected the clock difference. Synchronize the client, server, and domain-controller clocks (KRB_AP_ERR_SKEW)."
	case errorcode.KRB_AP_ERR_TKT_EXPIRED:
		return "authentication failed: the Kerberos ticket expired. Renew the credential cache or sign in again (KRB_AP_ERR_TKT_EXPIRED)."
	default:
		return ""
	}
}
