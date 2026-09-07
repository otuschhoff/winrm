package winrm

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/masterzen/winrm/soap"

	"github.com/otuschhoff/gokrb5/v8/client"
	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/spnego"
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
	KrbKeytab string
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
		KrbKeytab: settings.KrbKeytab,
		SPN:       settings.KrbSpn,
	}
}

func (c *ClientKerberos) Transport(endpoint *Endpoint) error {
	return c.clientRequest.Transport(endpoint)
}

func (c *ClientKerberos) Post(clt *Client, request *soap.SoapMessage) (string, error) {
	cfg, err := config.Load(c.KrbConf)
	if err != nil {
		return "", err
	}

	// setup the kerberos client
	var kerberosClient *client.Client
	if len(c.KrbCCache) > 0 {
		b, err := os.ReadFile(c.KrbCCache)
		if err != nil {
			return "", fmt.Errorf("unable to read ccache file %s: %w", c.KrbCCache, err)
		}

		cc := new(credentials.CCache)
		err = cc.Unmarshal(b)
		if err != nil {
			return "", fmt.Errorf("unable to parse ccache file %s: %w", c.KrbCCache, err)
		}
		kerberosClient, err = client.NewFromCCache(cc, cfg, client.DisablePAFXFAST(true))
		if err != nil {
			return "", fmt.Errorf("unable to create kerberos client from ccache: %w", err)
		}
	} else if len(c.KrbKeytab) > 0 {
		kt, err := keytab.Load(c.KrbKeytab)
		if err != nil {
			return "", fmt.Errorf("unable to read keytab file %s: %w", c.KrbKeytab, err)
		}
		kerberosClient = client.NewWithKeytab(c.Username, c.Realm, kt, cfg,
			client.DisablePAFXFAST(true), client.AssumePreAuthentication(true))
	} else {
		kerberosClient = client.NewWithPassword(c.Username, c.Realm, c.Password, cfg,
			client.DisablePAFXFAST(true), client.AssumePreAuthentication(true))
	}

	//create an http request
	winrmURL := fmt.Sprintf("%s://%s:%d/wsman", c.Proto, c.Hostname, c.Port)
	//nolint:noctx
	winRMRequest, _ := http.NewRequest("POST", winrmURL, strings.NewReader(request.String()))
	winRMRequest.Header.Add("Content-Type", "application/soap+xml;charset=UTF-8")

	err = spnego.SetSPNEGOHeader(kerberosClient, winRMRequest, c.SPN)
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
