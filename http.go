package winrm

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/otuschhoff/winrm/soap"
)

var soapXML = "application/soap+xml"

type httpResponseError struct {
	statusCode int
	body       string
}

func (responseError *httpResponseError) Error() string {
	return fmt.Sprintf("HTTP response status %d", responseError.statusCode)
}

func readSOAPResponse(response *http.Response, maxBodySize int) (result string, err error) {
	if response == nil || response.Body == nil {
		return "", errors.New("HTTP response body is missing")
	}
	defer func() {
		err = errors.Join(err, response.Body.Close())
	}()
	if maxBodySize <= 0 {
		return "", errors.New("positive envelope size is required")
	}

	contentType := response.Header.Get("Content-Type")
	mediaType, _, mediaTypeErr := mime.ParseMediaType(contentType)
	if mediaTypeErr != nil || !strings.EqualFold(mediaType, soapXML) {
		return "", fmt.Errorf("HTTP response status %d has invalid SOAP content type %q", response.StatusCode, contentType)
	}

	body, readErr := readBoundedResponseBody(response.Body, maxBodySize)
	debugHTTPResponseBody(body, readErr)
	if readErr != nil {
		return "", fmt.Errorf("read HTTP response body: %w", readErr)
	}
	if response.StatusCode != http.StatusOK {
		return "", &httpResponseError{statusCode: response.StatusCode, body: string(body)}
	}
	return string(body), nil
}

func readBoundedResponseBody(reader io.Reader, limit int) ([]byte, error) {
	if limit < 0 {
		return nil, errors.New("response body limit cannot be negative")
	}
	readLimit := int64(limit)
	if readLimit < int64(^uint64(0)>>1) {
		readLimit++
	}
	body, err := io.ReadAll(io.LimitReader(reader, readLimit))
	if err != nil {
		return body, err
	}
	if len(body) > limit {
		return body, fmt.Errorf("response body exceeds limit %d", limit)
	}
	return body, nil
}

type clientRequest struct {
	transport http.RoundTripper
	dial      func(network, addr string) (net.Conn, error)
	proxyfunc func(req *http.Request) (*url.URL, error)
	timeout   time.Duration
}

func (c *clientRequest) Transport(endpoint *Endpoint) error {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	proxyfunc := http.ProxyFromEnvironment
	if c.proxyfunc != nil {
		proxyfunc = c.proxyfunc
	}

	//nolint:gosec
	transport := &http.Transport{
		Proxy: proxyfunc,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: endpoint.Insecure,
			ServerName:         endpoint.TLSServerName,
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

// Post make post to the winrm soap service
func (c clientRequest) Post(client *Client, request *soap.SoapMessage) (string, error) {
	return c.PostContext(context.Background(), client, request)
}

// PostContext makes a POST request using the caller's cancellation and deadline.
func (c clientRequest) PostContext(ctx context.Context, client *Client, request *soap.SoapMessage) (string, error) {
	httpClient := &http.Client{Transport: c.transport, Timeout: c.timeout}

	req, err := http.NewRequestWithContext(ctx, "POST", client.url, strings.NewReader(request.String()))
	if err != nil {
		return "", fmt.Errorf("impossible to create http request %w", err)
	}
	req.Header.Set("Content-Type", soapXML+";charset=UTF-8")
	req.SetBasicAuth(client.username, client.password)
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

// Close releases idle connections owned by the built-in HTTP transport.
func (c *clientRequest) Close() error {
	if closer, ok := c.transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	return nil
}

// NewClientWithDial NewClientWithDial
func NewClientWithDial(dial func(network, addr string) (net.Conn, error)) *clientRequest {
	return &clientRequest{
		dial: dial,
	}
}

// NewClientWithProxyFunc NewClientWithProxyFunc
func NewClientWithProxyFunc(proxyfunc func(req *http.Request) (*url.URL, error)) *clientRequest {
	return &clientRequest{
		proxyfunc: proxyfunc,
	}
}
