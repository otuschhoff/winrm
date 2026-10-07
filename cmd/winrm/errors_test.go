package main

import (
	"errors"
	"fmt"
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
		{"connect context", fmt.Errorf("connect to windows.example.com: %w", negotiate(failedPassword)), "connect to windows.example.com: " + rejectedCredentials},
		{"unknown account", negotiate(messages.KRBError{ErrorCode: errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN}), "authentication failed: Kerberos could not find the account. Check username and realm (KDC_ERR_C_PRINCIPAL_UNKNOWN)."},
		{"expired password", negotiate(messages.KRBError{ErrorCode: errorcode.KDC_ERR_KEY_EXPIRED}), "authentication failed: your Kerberos password has expired. Change it before reconnecting (KDC_ERR_KEY_EXPIRED)."},
		{"revoked account", negotiate(messages.KRBError{ErrorCode: errorcode.KDC_ERR_CLIENT_REVOKED}), "authentication failed: Kerberos rejected the account as revoked, disabled, or locked. Contact your administrator (KDC_ERR_CLIENT_REVOKED)."},
		{"access denied", &winrm.KerberosError{Stage: "soap", StatusCode: 500, Err: &winrm.SOAPFaultError{WSManCode: "5"}}, accessDenied},
		{"HRESULT access denied", &winrm.KerberosError{Stage: "soap", StatusCode: 500, Err: &winrm.SOAPFaultError{WSManCode: "2147942405"}}, accessDenied},
		{"hex access denied", &winrm.KerberosError{Stage: "soap", StatusCode: 500, Err: &winrm.SOAPFaultError{WSManCode: "0x80070005"}}, accessDenied},
		{"plain SOAP", &winrm.SOAPFaultError{WSManCode: "5"}, "authorization failed: Windows denied WinRM access (ERROR_ACCESS_DENIED, code 5). Ask an administrator to check WinRM permissions."},
		{"joined cleanup error", errors.Join(fmt.Errorf("connect to windows.example.com: %w", negotiate(failedPassword)), errors.New("cleanup failed")), "connect to windows.example.com: " + rejectedCredentials + "\ncleanup failed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatCLIError(tt.err); got != tt.want {
				t.Fatalf("message=%q want=%q", got, tt.want)
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
		if got := formatCLIError(err); got != err.Error() {
			t.Fatalf("unclassified error changed: got=%q want=%q", got, err.Error())
		}
	}
}
