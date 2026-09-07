package winrm

import (
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestKerberosTransportCustomDialer(t *testing.T) {
	settings := kerberosCompatibilitySettings(t)
	wantErr := errors.New("custom dialer called")
	transport := NewClientKerberosWithDial(&settings, func(string, string) (net.Conn, error) {
		return nil, wantErr
	})
	if err := transport.Transport(NewEndpoint("host.example.test", 5985, false, false, nil, nil, nil, 0)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = transport.Close() })
	httpTransport := transport.session.httpClient.Transport.(*http.Transport)
	if _, err := httpTransport.Dial("tcp", "host.example.test:5985"); !errors.Is(err, wantErr) {
		t.Fatalf("dial error = %v, want custom dialer error", err)
	}
}

func TestKerberosTransportCustomProxy(t *testing.T) {
	settings := kerberosCompatibilitySettings(t)
	wantProxy, _ := url.Parse("http://proxy.example.test:8080")
	transport := NewClientKerberosWithProxyFunc(&settings, func(*http.Request) (*url.URL, error) {
		return wantProxy, nil
	})
	if err := transport.Transport(NewEndpoint("host.example.test", 5985, false, false, nil, nil, nil, 0)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = transport.Close() })
	httpTransport := transport.session.httpClient.Transport.(*http.Transport)
	proxy, err := httpTransport.Proxy(&http.Request{URL: &url.URL{Scheme: "http", Host: "host.example.test"}})
	if err != nil || proxy == nil || proxy.String() != wantProxy.String() {
		t.Fatalf("proxy = %v, %v; want %v", proxy, err, wantProxy)
	}
}

func TestKerberosTransportEncryptionModes(t *testing.T) {
	tests := []struct {
		name, mode     string
		https          bool
		wantEncryption bool
	}{
		{name: "auto HTTP", wantEncryption: true},
		{name: "auto HTTPS", https: true},
		{name: "always HTTPS", mode: KerberosEncryptionAlways, https: true, wantEncryption: true},
		{name: "never HTTP", mode: KerberosEncryptionNever},
		{name: "trimmed mixed case", mode: "  AlWaYs  ", https: true, wantEncryption: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			settings := kerberosCompatibilitySettings(t)
			settings.KrbMessageEncryption = test.mode
			transport := NewClientKerberos(&settings)
			port := 5985
			if test.https {
				port = 5986
			}
			if err := transport.Transport(NewEndpoint("host.example.test", port, test.https, false, nil, nil, nil, 0)); err != nil {
				t.Fatal(err)
			}
			defer transport.Close()
			if transport.session.requireEncryption != test.wantEncryption {
				t.Fatalf("message encryption = %t, want %t", transport.session.requireEncryption, test.wantEncryption)
			}
		})
	}
}

func TestKerberosTransportHTTPSCertificateVerification(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "ok")
	}))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)
	host, portText, _ := net.SplitHostPort(serverURL.Host)
	port, _ := strconv.Atoi(portText)
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})

	tests := []struct {
		name      string
		ca        []byte
		insecure  bool
		wantError bool
	}{
		{name: "trusted CA", ca: certificate},
		{name: "unknown CA", wantError: true},
		{name: "explicit insecure", insecure: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			settings := kerberosCompatibilitySettings(t)
			transport := NewClientKerberos(&settings)
			if err := transport.Transport(NewEndpoint(host, port, true, test.insecure, test.ca, nil, nil, 0)); err != nil {
				t.Fatal(err)
			}
			defer transport.Close()
			response, err := transport.session.httpClient.Get(server.URL)
			if test.wantError {
				if err == nil {
					response.Body.Close()
					t.Fatal("HTTPS request with an unknown CA succeeded")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
		})
	}
}

func TestKerberosTransportRejectsInvalidCA(t *testing.T) {
	settings := kerberosCompatibilitySettings(t)
	transport := NewClientKerberos(&settings)
	err := transport.Transport(NewEndpoint("host.example.test", 5986, true, false, []byte("not PEM"), nil, nil, 0))
	if err == nil || !strings.Contains(err.Error(), "certificates") {
		t.Fatalf("invalid CA error = %v", err)
	}
}

func kerberosCompatibilitySettings(t *testing.T) Settings {
	t.Helper()
	configPath := t.TempDir() + "/krb5.conf"
	configuration := "[libdefaults]\n default_realm = EXAMPLE.TEST\n[realms]\n EXAMPLE.TEST = {\n  kdc = 127.0.0.1\n }\n"
	if err := os.WriteFile(configPath, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	return Settings{WinRMUsername: "user", WinRMPassword: "password", KrbRealm: "EXAMPLE.TEST", KrbConfig: configPath}
}
