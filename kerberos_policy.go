package winrm

import "fmt"

// KerberosRuntimeMode controls how Kerberos requests are handled.
type KerberosRuntimeMode string

const (
	// KerberosModeAuthOnly uses Kerberos for authentication only and sends plain SOAP payloads.
	KerberosModeAuthOnly KerberosRuntimeMode = "kerberos-auth-only"
	// KerberosModeMessageEncryptionRequired requires multipart encrypted WinRM payloads.
	KerberosModeMessageEncryptionRequired KerberosRuntimeMode = "kerberos-message-encryption-required"
)

// KerberosFailurePolicy controls how strictly Kerberos message protection failures are handled.
type KerberosFailurePolicy struct {
	RejectUnencryptedResponse bool
	RejectInvalidSignature    bool
	RejectTokenDecryptFailure bool
}

// defaultKerberosFailurePolicyForMode returns the default fail policy for a runtime mode.
func defaultKerberosFailurePolicyForMode(mode KerberosRuntimeMode) KerberosFailurePolicy {
	switch mode {
	case KerberosModeMessageEncryptionRequired:
		return KerberosFailurePolicy{
			RejectUnencryptedResponse: true,
			RejectInvalidSignature:    true,
			RejectTokenDecryptFailure: true,
		}
	case KerberosModeAuthOnly:
		return KerberosFailurePolicy{}
	default:
		return KerberosFailurePolicy{}
	}
}

func validateKerberosRuntimeMode(mode KerberosRuntimeMode) error {
	switch mode {
	case KerberosModeAuthOnly, KerberosModeMessageEncryptionRequired:
		return nil
	default:
		return fmt.Errorf("unsupported kerberos runtime mode: %q", mode)
	}
}
