package winrm

import (
	"context"
	"errors"
	"fmt"

	"github.com/masterzen/winrm/soap"
)

const (
	KerberosEncryptionAuto   = "auto"
	KerberosEncryptionAlways = "always"
	KerberosEncryptionNever  = "never"
)

// Settings holds all the information necessary to configure the provider
type Settings struct {
	WinRMUsername        string
	WinRMPassword        string
	WinRMHost            string
	WinRMPort            int
	WinRMProto           string
	WinRMInsecure        bool
	KrbRealm             string
	KrbConfig            string
	KrbSpn               string
	KrbCCache            string
	KrbKeytab            string
	KrbMessageEncryption string
	WinRMUseNTLM         bool
	WinRMPassCredentials bool
}

type ClientKerberos struct {
	clientRequest
	Username          string
	Password          string
	Realm             string
	Hostname          string
	Port              int
	Proto             string
	SPN               string
	KrbConf           string
	KrbCCache         string
	KrbKeytab         string
	MessageEncryption string
	session           *kerberosSession
}

func NewClientKerberos(settings *Settings) *ClientKerberos {
	return &ClientKerberos{
		Username:          settings.WinRMUsername,
		Password:          settings.WinRMPassword,
		Realm:             settings.KrbRealm,
		Hostname:          settings.WinRMHost,
		Port:              settings.WinRMPort,
		Proto:             settings.WinRMProto,
		KrbConf:           settings.KrbConfig,
		KrbCCache:         settings.KrbCCache,
		KrbKeytab:         settings.KrbKeytab,
		SPN:               settings.KrbSpn,
		MessageEncryption: settings.KrbMessageEncryption,
	}
}

func (c *ClientKerberos) Transport(endpoint *Endpoint) error {
	if c.session != nil {
		return errors.New("Kerberos transport is already initialized")
	}
	if err := c.clientRequest.Transport(endpoint); err != nil {
		return err
	}
	session, err := newKerberosSession(c, endpoint)
	if err != nil {
		return err
	}
	c.session = session
	return nil
}

func (c *ClientKerberos) Post(clt *Client, request *soap.SoapMessage) (string, error) {
	return c.PostContext(context.Background(), clt, request)
}

// PostContext sends a Kerberos-authenticated request with cancellation support.
func (c *ClientKerberos) PostContext(ctx context.Context, clt *Client, request *soap.SoapMessage) (string, error) {
	if c.session == nil {
		return "", &KerberosError{Stage: "config", Err: errors.New("Kerberos transport is not initialized")}
	}
	return c.session.post(ctx, request.String(), clt.EnvelopeSize)
}

// Close releases cached Kerberos credentials and idle HTTP connections.
func (c *ClientKerberos) Close() error {
	if c.session == nil {
		return nil
	}
	return c.session.close()
}

// KerberosError identifies the stage at which a Kerberos transport operation failed.
type KerberosError struct {
	Stage      string
	StatusCode int
	Err        error
}

func (e *KerberosError) Error() string {
	if e.StatusCode != 0 {
		return fmt.Sprintf("Kerberos %s failed with HTTP status %d: %v", e.Stage, e.StatusCode, e.Err)
	}
	return fmt.Sprintf("Kerberos %s failed: %v", e.Stage, e.Err)
}

func (e *KerberosError) Unwrap() error { return e.Err }
