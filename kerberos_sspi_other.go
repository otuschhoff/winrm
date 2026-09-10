//go:build !windows

package winrm

import "errors"

func newKerberosSSPIAuthenticator() (kerberosSSPIAuthenticator, error) {
	return nil, errors.New("Windows SSPI Kerberos authentication is only available on Windows")
}
