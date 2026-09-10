package winrm

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/otuschhoff/winrm/soap"
)

// ClientAuthRequest ClientAuthRequest
type ClientAuthRequest struct {
	transport http.RoundTripper
	dial      func(network, addr string) (net.Conn, error)
	timeout   time.Duration
}

// Transport Transport
func (c *ClientAuthRequest) Transport(endpoint *Endpoint) error {
	cert, err := tls.X509KeyPair(endpoint.Cert, endpoint.Key)
	if err != nil {
		return err
	}

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	//nolint:gosec
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			Renegotiation:      tls.RenegotiateOnceAsClient,
			InsecureSkipVerify: endpoint.Insecure,
			Certificates:       []tls.Certificate{cert},
		},
		DialContext:           dialer.DialContext,
		ResponseHeaderTimeout: endpoint.Timeout,
	}
	if c.dial != nil {
		transport.DialContext = nil
		transport.Dial = c.dial
	}

	if len(endpoint.CACert) > 0 {
		certPool, err := readCACerts(endpoint.CACert)
		if err != nil {
			return err
		}

		transport.TLSClientConfig.RootCAs = certPool
	}

	c.transport = transport
	c.timeout = endpoint.Timeout

	return nil
}

// Post Post
func (c ClientAuthRequest) Post(client *Client, request *soap.SoapMessage) (string, error) {
	return c.PostContext(context.Background(), client, request)
}

// PostContext makes a certificate-authenticated POST request with caller cancellation.
func (c ClientAuthRequest) PostContext(ctx context.Context, client *Client, request *soap.SoapMessage) (string, error) {
	httpClient := &http.Client{Transport: c.transport, Timeout: c.timeout}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, client.url, strings.NewReader(request.String()))
	if err != nil {
		return "", fmt.Errorf("impossible to create http request %w", err)
	}

	req.Header.Set("Content-Type", soapXML+";charset=UTF-8")
	req.Header.Set("Authorization", "http://schemas.dmtf.org/wbem/wsman/1/wsman/secprofile/https/mutual")

	resp, err := httpClient.Do(req)
	debugHTTPRoundTrip(req, resp, err)
	if err != nil {
		if os.IsTimeout(err) {
			return "", fmt.Errorf("HTTP request timeout: %w", err)
		}
		return "", fmt.Errorf("unknown error %w", err)
	}

	body, err := readSOAPResponse(resp, client.EnvelopeSize)
	if err != nil {
		return "", fmt.Errorf("HTTP response error: %w", err)
	}
	return body, nil
}

// Close releases idle connections owned by the certificate transport.
func (c *ClientAuthRequest) Close() error {
	if closer, ok := c.transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	return nil
}

// NewClientAuthRequestWithDial NewClientAuthRequestWithDial
func NewClientAuthRequestWithDial(dial func(network, addr string) (net.Conn, error)) *ClientAuthRequest {
	return &ClientAuthRequest{
		dial: dial,
	}
}
