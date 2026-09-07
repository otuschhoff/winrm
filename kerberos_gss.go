package winrm

import (
	"errors"
	"fmt"

	"github.com/otuschhoff/gokrb5/v8/gssapi"
)

// RFC 4121 section 4.2.6.2 defines a fixed 16-byte Wrap token header.
const kerberosGSSHeaderLength = 16

var kerberosGSSWrapTokenID = [2]byte{0x05, 0x04}

type kerberosGSSContext interface {
	Wrap(message []byte, confidential bool) ([]byte, error)
	Unwrap(token []byte) ([]byte, bool, error)
}

type kerberosGSSAdapter struct {
	context kerberosGSSContext
}

func newKerberosGSSAdapter(context kerberosGSSContext) (*kerberosGSSAdapter, error) {
	if context == nil {
		return nil, errors.New("Kerberos GSS context is required")
	}
	return &kerberosGSSAdapter{context: context}, nil
}

func (adapter *kerberosGSSAdapter) wrap(message []byte) (header, payload []byte, err error) {
	token, err := adapter.context.Wrap(message, true)
	if err != nil {
		return nil, nil, fmt.Errorf("wrap Kerberos message: %w", err)
	}
	if len(token) <= kerberosGSSHeaderLength {
		return nil, nil, fmt.Errorf("wrapped Kerberos token length %d is too short", len(token))
	}
	if err := validateKerberosGSSHeader(token[:kerberosGSSHeaderLength]); err != nil {
		return nil, nil, err
	}
	return append([]byte(nil), token[:kerberosGSSHeaderLength]...), append([]byte(nil), token[kerberosGSSHeaderLength:]...), nil
}

func (adapter *kerberosGSSAdapter) unwrap(header, payload []byte) ([]byte, error) {
	if err := validateKerberosGSSHeader(header); err != nil {
		return nil, err
	}
	token := make([]byte, 0, len(header)+len(payload))
	token = append(token, header...)
	token = append(token, payload...)
	message, confidential, err := adapter.context.Unwrap(token)
	if err != nil {
		return nil, fmt.Errorf("unwrap Kerberos message: %w", err)
	}
	if !confidential {
		return nil, errors.New("Kerberos message is not confidential")
	}
	return message, nil
}

func validateKerberosGSSHeader(header []byte) error {
	if len(header) != kerberosGSSHeaderLength {
		return fmt.Errorf("Kerberos security header length %d, want %d", len(header), kerberosGSSHeaderLength)
	}
	if header[0] != kerberosGSSWrapTokenID[0] || header[1] != kerberosGSSWrapTokenID[1] || header[3] != gssapi.FillerByte {
		return errors.New("invalid Kerberos RFC 4121 wrap token header")
	}
	if header[2]&gssapi.MICTokenFlagSealed == 0 {
		return errors.New("Kerberos RFC 4121 wrap token is not sealed")
	}
	return nil
}

var _ kerberosGSSContext = (*gssapi.SecurityContext)(nil)
