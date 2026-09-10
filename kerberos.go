package winrm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/winrm/soap"
)

const (
	// KerberosEncryptionAuto seals SOAP on HTTP and relies on TLS on HTTPS.
	KerberosEncryptionAuto = "auto"
	// KerberosEncryptionAlways seals SOAP on both HTTP and HTTPS.
	KerberosEncryptionAlways = "always"
	// KerberosEncryptionNever explicitly disables GSS message encryption.
	KerberosEncryptionNever = "never"
)

// Settings holds all the information necessary to configure the provider
type Settings struct {
	WinRMUsername string
	WinRMPassword string
	WinRMHost     string
	WinRMPort     int
	WinRMProto    string
	WinRMInsecure bool
	KrbRealm      string
	KrbConfig     string
	KrbSpn        string
	// KrbUseSSPI uses the current Windows user's Kerberos credentials instead of gokrb5 credentials.
	KrbUseSSPI bool
	// KrbCCacheData is a borrowed in-memory ccache that must not be modified while the client is in use.
	KrbCCacheData        *credentials.CCache
	KrbCCache            string
	KrbKeytab            string
	KrbMessageEncryption string
	WinRMPassCredentials bool
}

type ClientKerberos struct {
	clientRequest
	Username string
	Password string
	Realm    string
	Hostname string
	Port     int
	Proto    string
	SPN      string
	// UseSSPI uses the current Windows user's Kerberos credentials instead of gokrb5 credentials.
	UseSSPI bool
	KrbConf string
	// KrbCCacheData is a borrowed in-memory ccache that must not be modified while the client is in use.
	KrbCCacheData     *credentials.CCache
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
		UseSSPI:           settings.KrbUseSSPI,
		KrbConf:           settings.KrbConfig,
		KrbCCacheData:     settings.KrbCCacheData,
		KrbCCache:         settings.KrbCCache,
		KrbKeytab:         settings.KrbKeytab,
		SPN:               settings.KrbSpn,
		MessageEncryption: settings.KrbMessageEncryption,
	}
}

// NewClientKerberosWithDial creates a Kerberos transport using a custom dialer.
func NewClientKerberosWithDial(settings *Settings, dial func(network, addr string) (net.Conn, error)) *ClientKerberos {
	transport := NewClientKerberos(settings)
	transport.dial = dial
	return transport
}

// NewClientKerberosWithProxyFunc creates a Kerberos transport using a custom proxy selector.
func NewClientKerberosWithProxyFunc(settings *Settings, proxyfunc func(*http.Request) (*url.URL, error)) *ClientKerberos {
	transport := NewClientKerberos(settings)
	transport.proxyfunc = proxyfunc
	return transport
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
