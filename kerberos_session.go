package winrm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"strings"
	"sync"

	"github.com/otuschhoff/gokrb5/v8/client"
	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/spnego"
)

const (
	kerberosMaxBootstrapExchanges = 5
	kerberosMaxBootstrapBody      = 4096
)

type kerberosSessionState uint8

const (
	kerberosSessionCredentialsReady kerberosSessionState = iota
	kerberosSessionNegotiating
	kerberosSessionEstablished
	kerberosSessionInvalid
	kerberosSessionClosed
)

type kerberosNegotiator interface {
	Do(*http.Request) (*http.Response, error)
	Context() gssapi.Context
}

type kerberosSession struct {
	gate              chan struct{}
	gateOnce          sync.Once
	state             kerberosSessionState
	endpoint          string
	spn               string
	requireEncryption bool
	kerberosClient    *client.Client
	httpClient        *http.Client
	newNegotiator     func(*http.Client) kerberosNegotiator
	adapter           *kerberosGSSAdapter
	connection        net.Conn
}

func newKerberosSession(owner *ClientKerberos, endpoint *Endpoint) (*kerberosSession, error) {
	endpointURL, spn, requireEncryption, err := validateKerberosConfiguration(owner, endpoint)
	if err != nil {
		return nil, &KerberosError{Stage: "config", Err: err}
	}
	kerberosClient, err := newKerberosCredentialClient(owner)
	if err != nil {
		return nil, &KerberosError{Stage: "credentials", Err: err}
	}
	if transport, ok := owner.transport.(*http.Transport); ok {
		transport.MaxConnsPerHost = 1
		transport.MaxIdleConnsPerHost = 1
	}
	httpClient := &http.Client{
		Transport: owner.transport,
		Timeout:   endpoint.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are not permitted during Kerberos authentication")
		},
	}
	session := &kerberosSession{
		state: kerberosSessionCredentialsReady, endpoint: endpointURL, spn: spn,
		requireEncryption: requireEncryption, kerberosClient: kerberosClient, httpClient: httpClient,
	}
	session.newNegotiator = func(httpClient *http.Client) kerberosNegotiator {
		return spnego.NewClientWithOptions(kerberosClient, httpClient, spn, spnego.KRB5TokenAPREQOptions{
			GSSAPIFlags: []int{gssapi.ContextFlagMutual, gssapi.ContextFlagSequence, gssapi.ContextFlagInteg, gssapi.ContextFlagConf},
		})
	}
	return session, nil
}

func validateKerberosConfiguration(owner *ClientKerberos, endpoint *Endpoint) (string, string, bool, error) {
	if endpoint == nil || strings.TrimSpace(endpoint.Host) == "" || endpoint.Port < 1 || endpoint.Port > 65535 {
		return "", "", false, errors.New("valid WinRM endpoint is required")
	}
	scheme := "http"
	if endpoint.HTTPS {
		scheme = "https"
	}
	if owner.Hostname != "" && !strings.EqualFold(owner.Hostname, endpoint.Host) {
		return "", "", false, fmt.Errorf("Kerberos hostname %q conflicts with endpoint host %q", owner.Hostname, endpoint.Host)
	}
	if owner.Port != 0 && owner.Port != endpoint.Port {
		return "", "", false, fmt.Errorf("Kerberos port %d conflicts with endpoint port %d", owner.Port, endpoint.Port)
	}
	if owner.Proto != "" && !strings.EqualFold(owner.Proto, scheme) {
		return "", "", false, fmt.Errorf("Kerberos protocol %q conflicts with endpoint scheme %q", owner.Proto, scheme)
	}
	mode := strings.ToLower(strings.TrimSpace(owner.MessageEncryption))
	if mode == "" {
		mode = KerberosEncryptionAuto
	}
	if mode != KerberosEncryptionAuto && mode != KerberosEncryptionAlways && mode != KerberosEncryptionNever {
		return "", "", false, fmt.Errorf("unsupported Kerberos message encryption mode %q", owner.MessageEncryption)
	}
	spn := owner.SPN
	if spn == "" {
		spn = "HTTP/" + endpoint.Host
	}
	requireEncryption := mode == KerberosEncryptionAlways || mode == KerberosEncryptionAuto && !endpoint.HTTPS
	return endpoint.url(), spn, requireEncryption, nil
}

func newKerberosCredentialClient(owner *ClientKerberos) (*client.Client, error) {
	cfg, err := config.Load(owner.KrbConf)
	if err != nil {
		return nil, fmt.Errorf("load Kerberos configuration: %w", err)
	}
	if owner.KrbCCache != "" {
		encoded, err := os.ReadFile(owner.KrbCCache)
		if err != nil {
			return nil, fmt.Errorf("read ccache file %q: %w", owner.KrbCCache, err)
		}
		cache := new(credentials.CCache)
		if err := cache.Unmarshal(encoded); err != nil {
			return nil, fmt.Errorf("parse ccache file %q: %w", owner.KrbCCache, err)
		}
		kerberosClient, err := client.NewFromCCache(cache, cfg, client.DisablePAFXFAST(true))
		if err != nil {
			return nil, fmt.Errorf("create Kerberos client from ccache: %w", err)
		}
		return kerberosClient, nil
	}
	if owner.KrbKeytab != "" {
		kt, err := keytab.Load(owner.KrbKeytab)
		if err != nil {
			return nil, fmt.Errorf("read keytab file %q: %w", owner.KrbKeytab, err)
		}
		return client.NewWithKeytab(owner.Username, owner.Realm, kt, cfg,
			client.DisablePAFXFAST(true), client.AssumePreAuthentication(true)), nil
	}
	return client.NewWithPassword(owner.Username, owner.Realm, owner.Password, cfg,
		client.DisablePAFXFAST(true), client.AssumePreAuthentication(true)), nil
}

func (session *kerberosSession) post(ctx context.Context, message string, maxPlaintextSize int) (string, error) {
	if err := session.acquire(ctx); err != nil {
		return "", &KerberosError{Stage: "queue", Err: err}
	}
	defer session.release()
	if session.state == kerberosSessionClosed {
		return "", &KerberosError{Stage: "config", Err: errors.New("Kerberos session is closed")}
	}
	if err := session.establishLocked(ctx); err != nil {
		return "", err
	}
	if session.requireEncryption {
		return session.postEncryptedLocked(ctx, message, maxPlaintextSize)
	}
	return session.postPlaintextLocked(ctx, message, maxPlaintextSize)
}

func (session *kerberosSession) acquire(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	session.gateOnce.Do(func() {
		session.gate = make(chan struct{}, 1)
		session.gate <- struct{}{}
	})
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-session.gate:
		if err := ctx.Err(); err != nil {
			session.release()
			return err
		}
		return nil
	}
}

func (session *kerberosSession) release() {
	session.gate <- struct{}{}
}

func (session *kerberosSession) postEncryptedLocked(ctx context.Context, message string, maxPlaintextSize int) (string, error) {
	exchangeID := nextWinRMCaptureExchangeID()
	framer, err := newKerberosMessageFramer(maxPlaintextSize)
	if err != nil {
		return "", &KerberosError{Stage: "config", Err: err}
	}
	contentType, body, err := framer.seal([]byte(message), session.adapter)
	if err != nil {
		session.invalidateLocked()
		return "", &KerberosError{Stage: "wrap", Err: err}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, session.endpoint, bytes.NewReader(body))
	if err != nil {
		return "", &KerberosError{Stage: "config", Err: err}
	}
	request.Header.Set("Content-Type", contentType)
	debugSOAPPayload("request", "encrypted", []byte(message))
	emitWinRMCaptureRecord(exchangeID, "request", "encrypted", "unencrypted_payload", []byte(message), request, 0, kerberosSOAPContentType, nil)
	emitWinRMCaptureRecord(exchangeID, "request", "encrypted", "final_packet", body, request, 0, contentType, request.Header)
	tracker := &kerberosConnectionTracker{expected: session.connection}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), tracker.trace()))
	response, err := session.httpClient.Do(request)
	debugHTTPRoundTrip(request, response, err)
	if err != nil {
		session.invalidateLocked()
		return "", &KerberosError{Stage: "http", Err: err}
	}
	responseLimit := maxPlaintextSize + kerberosMaxWrapOverhead + kerberosMaxMetadataSize
	encryptedBody, readErr := readBoundedBody(response.Body, responseLimit)
	debugHTTPResponseBody(encryptedBody, readErr)
	emitWinRMCaptureRecord(exchangeID, "response", "encrypted", "final_packet", encryptedBody, request, response.StatusCode, response.Header.Get("Content-Type"), response.Header)
	connection, changed := tracker.result()
	if connection == nil || changed {
		session.invalidateLocked()
		return "", &KerberosError{Stage: "http", Err: errors.New("Kerberos HTTP connection changed; SOAP was not replayed")}
	}
	if readErr != nil {
		session.invalidateLocked()
		return "", &KerberosError{Stage: "http", StatusCode: response.StatusCode, Err: readErr}
	}
	plaintext, err := framer.open(response.Header.Get("Content-Type"), encryptedBody, session.adapter)
	if err != nil {
		session.invalidateLocked()
		return "", &KerberosError{Stage: "unwrap", StatusCode: response.StatusCode, Err: err}
	}
	debugSOAPPayload("response", "encrypted", plaintext)
	emitWinRMCaptureRecord(exchangeID, "response", "encrypted", "unencrypted_payload", plaintext, request, response.StatusCode, kerberosSOAPContentType, response.Header)
	return string(plaintext), nil
}

func (session *kerberosSession) establishLocked(ctx context.Context) error {
	if session.state == kerberosSessionEstablished {
		return nil
	}
	if session.state == kerberosSessionInvalid {
		session.state = kerberosSessionCredentialsReady
	}
	session.state = kerberosSessionNegotiating
	counting := &kerberosCountingRoundTripper{base: session.httpClient.Transport, remaining: kerberosMaxBootstrapExchanges}
	clientCopy := *session.httpClient
	clientCopy.Transport = counting
	for counting.remaining > 0 {
		exchangeID := nextWinRMCaptureExchangeID()
		counting.resetAuthenticatedConnection()
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, session.endpoint, nil)
		if err != nil {
			session.state = kerberosSessionInvalid
			return &KerberosError{Stage: "config", Err: err}
		}
		request.Header.Set("Content-Type", soapXML+";charset=UTF-8")
		emitWinRMCaptureRecord(exchangeID, "request", "bootstrap", "unencrypted_payload", nil, request, 0, request.Header.Get("Content-Type"), request.Header)
		emitWinRMCaptureRecord(exchangeID, "request", "bootstrap", "final_packet", nil, request, 0, request.Header.Get("Content-Type"), request.Header)
		negotiator := session.newNegotiator(&clientCopy)
		response, err := negotiator.Do(request)
		debugHTTPRoundTrip(request, response, err)
		if err != nil {
			if response != nil {
				emitWinRMCaptureRecord(exchangeID, "response", "bootstrap", "final_packet", nil, request, response.StatusCode, response.Header.Get("Content-Type"), response.Header)
			}
			if response != nil && response.Body != nil {
				response.Body.Close()
			}
			session.state = kerberosSessionInvalid
			return &KerberosError{Stage: "negotiate", Err: err}
		}
		bootstrapBody, bodyErr := readBoundedBody(response.Body, kerberosMaxBootstrapBody)
		debugHTTPResponseBody(bootstrapBody, bodyErr)
		emitWinRMCaptureRecord(exchangeID, "response", "bootstrap", "final_packet", bootstrapBody, request, response.StatusCode, response.Header.Get("Content-Type"), response.Header)
		emitWinRMCaptureRecord(exchangeID, "response", "bootstrap", "unencrypted_payload", bootstrapBody, request, response.StatusCode, response.Header.Get("Content-Type"), response.Header)
		if bodyErr != nil {
			session.state = kerberosSessionInvalid
			return &KerberosError{Stage: "http", StatusCode: response.StatusCode, Err: bodyErr}
		}
		connection, changed := counting.authenticatedConnection()
		if changed {
			continue
		}
		if response.StatusCode != http.StatusOK {
			session.state = kerberosSessionInvalid
			return &KerberosError{Stage: "http", StatusCode: response.StatusCode, Err: errors.New("Kerberos bootstrap did not return HTTP 200")}
		}
		context := negotiator.Context()
		if context == nil {
			session.state = kerberosSessionInvalid
			return &KerberosError{Stage: "negotiate", StatusCode: response.StatusCode, Err: errors.New("HTTP 200 response did not complete mutual authentication")}
		}
		if connection == nil {
			session.state = kerberosSessionInvalid
			return &KerberosError{Stage: "negotiate", Err: errors.New("Kerberos bootstrap did not identify its HTTP connection")}
		}
		adapter, err := newKerberosGSSAdapter(context)
		if err != nil {
			session.state = kerberosSessionInvalid
			return &KerberosError{Stage: "negotiate", Err: err}
		}
		session.adapter = adapter
		session.connection = connection
		session.state = kerberosSessionEstablished
		return nil
	}
	session.state = kerberosSessionInvalid
	return &KerberosError{Stage: "negotiate", Err: errors.New("Kerberos bootstrap exceeded five HTTP exchanges")}
}

func (session *kerberosSession) postPlaintextLocked(ctx context.Context, message string, maxBodySize int) (string, error) {
	exchangeID := nextWinRMCaptureExchangeID()
	if maxBodySize <= 0 {
		return "", &KerberosError{Stage: "config", Err: errors.New("positive envelope size is required")}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, session.endpoint, strings.NewReader(message))
	if err != nil {
		return "", &KerberosError{Stage: "config", Err: err}
	}
	request.Header.Set("Content-Type", soapXML+";charset=UTF-8")
	debugSOAPPayload("request", "plaintext", []byte(message))
	emitWinRMCaptureRecord(exchangeID, "request", "plaintext", "unencrypted_payload", []byte(message), request, 0, request.Header.Get("Content-Type"), request.Header)
	emitWinRMCaptureRecord(exchangeID, "request", "plaintext", "final_packet", []byte(message), request, 0, request.Header.Get("Content-Type"), request.Header)
	tracker := &kerberosConnectionTracker{expected: session.connection}
	request = request.WithContext(httptrace.WithClientTrace(request.Context(), tracker.trace()))
	response, err := session.httpClient.Do(request)
	debugHTTPRoundTrip(request, response, err)
	if err != nil {
		session.invalidateLocked()
		return "", &KerberosError{Stage: "http", Err: err}
	}
	body, readErr := readBoundedBody(response.Body, maxBodySize)
	debugHTTPResponseBody(body, readErr)
	debugSOAPPayload("response", "plaintext", body)
	emitWinRMCaptureRecord(exchangeID, "response", "plaintext", "final_packet", body, request, response.StatusCode, response.Header.Get("Content-Type"), response.Header)
	emitWinRMCaptureRecord(exchangeID, "response", "plaintext", "unencrypted_payload", body, request, response.StatusCode, response.Header.Get("Content-Type"), response.Header)
	connection, changed := tracker.result()
	if connection == nil || changed {
		session.invalidateLocked()
		return "", &KerberosError{Stage: "http", Err: errors.New("Kerberos HTTP connection changed; SOAP was not replayed")}
	}
	if readErr != nil {
		session.invalidateLocked()
		return "", &KerberosError{Stage: "http", StatusCode: response.StatusCode, Err: readErr}
	}
	if response.StatusCode != http.StatusOK {
		return "", &KerberosError{Stage: "http", StatusCode: response.StatusCode, Err: errors.New("WinRM request failed")}
	}
	mediaType, _, contentTypeErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if contentTypeErr != nil || !strings.EqualFold(mediaType, soapXML) {
		session.invalidateLocked()
		return "", &KerberosError{Stage: "soap", StatusCode: response.StatusCode, Err: errors.New("invalid plaintext response content type")}
	}
	return string(body), nil
}

func (session *kerberosSession) invalidateLocked() {
	session.adapter = nil
	session.connection = nil
	session.state = kerberosSessionInvalid
}

func (session *kerberosSession) close() error {
	ctx, cancel := context.WithTimeout(context.Background(), commandCleanupTimeout)
	defer cancel()
	return session.closeWithContext(ctx)
}

func (session *kerberosSession) closeWithContext(ctx context.Context) error {
	if err := session.acquire(ctx); err != nil {
		return &KerberosError{Stage: "close", Err: err}
	}
	defer session.release()
	if session.state == kerberosSessionClosed {
		return nil
	}
	session.adapter = nil
	session.connection = nil
	session.state = kerberosSessionClosed
	if session.kerberosClient != nil {
		session.kerberosClient.Destroy()
	}
	if closer, ok := session.httpClient.Transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	return nil
}

type kerberosCountingRoundTripper struct {
	mu             sync.Mutex
	base           http.RoundTripper
	remaining      int
	connection     net.Conn
	connectionLost bool
}

func (transport *kerberosCountingRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.mu.Lock()
	if transport.remaining == 0 {
		transport.mu.Unlock()
		return nil, errors.New("Kerberos bootstrap exceeded five HTTP exchanges")
	}
	transport.remaining--
	transport.mu.Unlock()
	if request.Header.Get(spnego.HTTPHeaderAuthRequest) != "" {
		request = request.Clone(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) {
				transport.mu.Lock()
				defer transport.mu.Unlock()
				if transport.connection != nil && transport.connection != info.Conn {
					transport.connectionLost = true
				}
				transport.connection = info.Conn
			},
		}))
	}
	response, err := transport.base.RoundTrip(request)
	if response != nil && response.Body != nil {
		response.Body = &kerberosBoundedReadCloser{reader: response.Body, closer: response.Body, remaining: kerberosMaxBootstrapBody}
	}
	return response, err
}

func (transport *kerberosCountingRoundTripper) resetAuthenticatedConnection() {
	transport.mu.Lock()
	transport.connection = nil
	transport.connectionLost = false
	transport.mu.Unlock()
}

func (transport *kerberosCountingRoundTripper) authenticatedConnection() (net.Conn, bool) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return transport.connection, transport.connectionLost
}

type kerberosConnectionTracker struct {
	mu       sync.Mutex
	expected net.Conn
	current  net.Conn
	changed  bool
}

func (tracker *kerberosConnectionTracker) trace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		tracker.mu.Lock()
		defer tracker.mu.Unlock()
		if tracker.current != nil && tracker.current != info.Conn || tracker.expected != nil && tracker.expected != info.Conn {
			tracker.changed = true
		}
		tracker.current = info.Conn
	}}
}

func (tracker *kerberosConnectionTracker) result() (net.Conn, bool) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return tracker.current, tracker.changed
}

type kerberosBoundedReadCloser struct {
	reader    io.Reader
	closer    io.Closer
	remaining int
	overflow  bool
}

func (reader *kerberosBoundedReadCloser) Read(buffer []byte) (int, error) {
	if reader.overflow {
		return 0, errors.New("Kerberos HTTP response exceeds configured limit")
	}
	if len(buffer) > reader.remaining+1 {
		buffer = buffer[:reader.remaining+1]
	}
	count, err := reader.reader.Read(buffer)
	if count > reader.remaining {
		reader.overflow = true
		return count, errors.New("Kerberos HTTP response exceeds configured limit")
	}
	reader.remaining -= count
	return count, err
}

func (reader *kerberosBoundedReadCloser) Close() error { return reader.closer.Close() }

func discardBoundedBody(body io.ReadCloser, limit int) error {
	_, err := readBoundedBody(body, limit)
	return err
}

func readBoundedBody(body io.ReadCloser, limit int) (result []byte, err error) {
	if body == nil {
		return nil, nil
	}
	defer func() {
		err = errors.Join(err, body.Close())
	}()
	return readBoundedResponseBody(body, limit)
}
