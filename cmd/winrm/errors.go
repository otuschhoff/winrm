package main

import (
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/winrm"
)

var legacyKDCError = regexp.MustCompile(`KRB Error: \(([0-9]+)\) (KDC_ERR_[A-Z0-9_]+)\b`)

func formatCLIError(err error) string {
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var messages []string
		for _, cause := range joined.Unwrap() {
			messages = append(messages, formatCLIError(cause))
		}
		return strings.Join(messages, "\n")
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
		return err.Error()
	}
	if fault, ok := err.(*winrm.SOAPFaultError); ok && isAccessDenied(fault) {
		return "authorization failed: Windows denied WinRM access (ERROR_ACCESS_DENIED, code 5). Ask an administrator to check WinRM permissions."
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		if cause := wrapped.Unwrap(); cause != nil && strings.HasSuffix(err.Error(), cause.Error()) {
			return strings.TrimSuffix(err.Error(), cause.Error()) + formatCLIError(cause)
		}
	}
	return err.Error()
}

func isAccessDenied(fault *winrm.SOAPFaultError) bool {
	return fault.WSManCode == "5" || fault.WSManCode == "2147942405" || strings.EqualFold(fault.WSManCode, "0x80070005")
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
	default:
		return ""
	}
}
