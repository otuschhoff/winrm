package winrm

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/masterzen/winrm/soap"

	krbclient "github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
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
	WinRMUseNTLM         bool
	WinRMPassCredentials bool
}

type ClientKerberos struct {
	clientRequest
	Username  string
	Password  string
	Realm     string
	Hostname  string
	Port      int
	Proto     string
	SPN       string
	KrbConf   string
	KrbCCache string

	contextMu sync.Mutex
	context   *kerberosContext
}

// kerberosContext stores state reused across requests for a single client session.
type kerberosContext struct {
	mu sync.Mutex

	client            *krbclient.Client
	spn               string
	serviceTicket     messages.Ticket
	serviceSessionKey types.EncryptionKey
	acceptorSubKey    *types.EncryptionKey
	initiatorSeq      uint64
	acceptorSeq       uint64
}

func NewClientKerberos(settings *Settings) *ClientKerberos {
	return &ClientKerberos{
		Username:  settings.WinRMUsername,
		Password:  settings.WinRMPassword,
		Realm:     settings.KrbRealm,
		Hostname:  settings.WinRMHost,
		Port:      settings.WinRMPort,
		Proto:     settings.WinRMProto,
		KrbConf:   settings.KrbConfig,
		KrbCCache: settings.KrbCCache,
		SPN:       settings.KrbSpn,
	}
}

func (c *ClientKerberos) Transport(endpoint *Endpoint) error {
	return c.clientRequest.Transport(endpoint)
}

func (c *ClientKerberos) resolveSPN() string {
	if c.SPN != "" {
		return c.SPN
	}

	host := strings.TrimSpace(c.Hostname)
	if host == "" {
		return ""
	}

	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}

	host = strings.Trim(host, "[]")
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" {
		return ""
	}

	return fmt.Sprintf("HTTP/%s", host)
}

func (c *ClientKerberos) newKerberosClient(cfg *config.Config) (*krbclient.Client, error) {
	if c.KrbCCache != "" {
		b, err := os.ReadFile(c.KrbCCache)
		if err != nil {
			return nil, fmt.Errorf("unable to read ccache file %s: %w", c.KrbCCache, err)
		}

		cc := new(credentials.CCache)
		if err := cc.Unmarshal(b); err != nil {
			return nil, fmt.Errorf("unable to parse ccache file %s: %w", c.KrbCCache, err)
		}

		kerberosClient, err := krbclient.NewFromCCache(cc, cfg, krbclient.DisablePAFXFAST(true))
		if err != nil {
			return nil, fmt.Errorf("unable to create kerberos client from ccache: %w", err)
		}
		return kerberosClient, nil
	}

	return krbclient.NewWithPassword(c.Username, c.Realm, c.Password, cfg,
		krbclient.DisablePAFXFAST(true), krbclient.AssumePreAuthentication(true)), nil
}

func (c *ClientKerberos) getOrCreateContext() (*kerberosContext, error) {
	c.contextMu.Lock()
	defer c.contextMu.Unlock()

	if c.context != nil {
		return c.context, nil
	}

	cfg, err := config.Load(c.KrbConf)
	if err != nil {
		return nil, err
	}

	kerberosClient, err := c.newKerberosClient(cfg)
	if err != nil {
		return nil, err
	}

	if err := kerberosClient.AffirmLogin(); err != nil {
		return nil, fmt.Errorf("unable to initialize kerberos login: %w", err)
	}

	spn := c.resolveSPN()
	if spn == "" {
		return nil, fmt.Errorf("unable to resolve SPN from hostname %q", c.Hostname)
	}

	ticket, sessionKey, err := kerberosClient.GetServiceTicket(spn)
	if err != nil {
		return nil, fmt.Errorf("unable to get service ticket for %s: %w", spn, err)
	}

	c.context = &kerberosContext{
		client:            kerberosClient,
		spn:               spn,
		serviceTicket:     ticket,
		serviceSessionKey: sessionKey,
	}

	return c.context, nil
}

func (c *ClientKerberos) Post(clt *Client, request *soap.SoapMessage) (string, error) {
	context, err := c.getOrCreateContext()
	if err != nil {
		return "", err
	}

	//create an http request
	winrmURL := fmt.Sprintf("%s://%s:%d/wsman", c.Proto, c.Hostname, c.Port)
	//nolint:noctx
	winRMRequest, err := http.NewRequest("POST", winrmURL, strings.NewReader(request.String()))
	if err != nil {
		return "", fmt.Errorf("unable to create http request: %w", err)
	}
	winRMRequest.Header.Add("Content-Type", "application/soap+xml;charset=UTF-8")

	err = spnego.SetSPNEGOHeader(context.client, winRMRequest, context.spn)
	if err != nil {
		return "", fmt.Errorf("unable to set SPNego Header: %w", err)
	}

	httpClient := &http.Client{Transport: c.transport}

	resp, err := httpClient.Do(winRMRequest)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		var bodyMsg string
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			bodyMsg = fmt.Sprintf("Error retrieving the response's body: %s", err)
		} else {
			bodyMsg = fmt.Sprintf("Response body:\n%s", string(respBody))
		}
		return "", fmt.Errorf("request returned: %d - %s. %s", resp.StatusCode, resp.Status, bodyMsg)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), err
}
