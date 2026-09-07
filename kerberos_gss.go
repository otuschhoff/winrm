package winrm

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/otuschhoff/gokrb5/v8/gssapi"
)

// RFC 4121 section 4.2.6.2 defines a fixed 16-byte Wrap token header.
const kerberosGSSHeaderLength = 16

// RFC 3961 AES profiles use a 16-byte random confounder.
const kerberosGSSConfounderLength = 16

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
	overhead := len(token) - len(message)
	if overhead < kerberosGSSHeaderLength+kerberosGSSConfounderLength || overhead > kerberosMaxWrapOverhead {
		return nil, nil, fmt.Errorf("wrapped Kerberos token overhead %d is invalid", overhead)
	}
	body := append([]byte(nil), token[kerberosGSSHeaderLength:]...)
	rrc := overhead - kerberosGSSHeaderLength - kerberosGSSConfounderLength
	if rrc > int(^uint16(0)) {
		return nil, nil, errors.New("wrapped Kerberos token rotation is too large")
	}
	binary.BigEndian.PutUint16(token[6:8], uint16(rrc))
	rotateKerberosRight(body, rrc)
	header = append([]byte(nil), token[:kerberosGSSHeaderLength]...)
	header = append(header, body[:overhead-kerberosGSSHeaderLength]...)
	payload = append([]byte(nil), body[overhead-kerberosGSSHeaderLength:]...)
	return header, payload, nil
}

func (adapter *kerberosGSSAdapter) unwrap(header, payload []byte) ([]byte, error) {
	if len(header) < kerberosGSSHeaderLength || len(header) > kerberosMaxWrapOverhead {
		return nil, fmt.Errorf("Kerberos security header length %d is invalid", len(header))
	}
	if err := validateKerberosGSSHeader(header[:kerberosGSSHeaderLength]); err != nil {
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

func rotateKerberosRight(value []byte, count int) {
	if len(value) == 0 {
		return
	}
	count %= len(value)
	if count == 0 {
		return
	}
	rotated := append(append([]byte(nil), value[len(value)-count:]...), value[:len(value)-count]...)
	copy(value, rotated)
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
