package winrm

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/spnego"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestValidateKerberosConfiguration(t *testing.T) {
	httpEndpoint := NewEndpoint("host.example.test", 5985, false, false, nil, nil, nil, 0)
	httpsEndpoint := NewEndpoint("host.example.test", 5986, true, false, nil, nil, nil, 0)
	tests := []struct {
		name              string
		owner             ClientKerberos
		endpoint          *Endpoint
		wantSPN           string
		wantEncryption    bool
		wantErrorContains string
	}{
		{name: "HTTP auto", endpoint: httpEndpoint, wantSPN: "HTTP/host.example.test", wantEncryption: true},
		{name: "HTTPS auto", endpoint: httpsEndpoint, wantSPN: "HTTP/host.example.test"},
		{name: "always", owner: ClientKerberos{MessageEncryption: KerberosEncryptionAlways}, endpoint: httpsEndpoint, wantSPN: "HTTP/host.example.test", wantEncryption: true},
		{name: "never", owner: ClientKerberos{MessageEncryption: KerberosEncryptionNever, SPN: "WSMAN/custom"}, endpoint: httpEndpoint, wantSPN: "WSMAN/custom"},
		{name: "host conflict", owner: ClientKerberos{Hostname: "other.example.test"}, endpoint: httpEndpoint, wantErrorContains: "conflicts"},
		{name: "port conflict", owner: ClientKerberos{Port: 5986}, endpoint: httpEndpoint, wantErrorContains: "conflicts"},
		{name: "scheme conflict", owner: ClientKerberos{Proto: "https"}, endpoint: httpEndpoint, wantErrorContains: "conflicts"},
		{name: "invalid mode", owner: ClientKerberos{MessageEncryption: "sometimes"}, endpoint: httpEndpoint, wantErrorContains: "unsupported"},
		{name: "missing endpoint", endpoint: nil, wantErrorContains: "endpoint"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			endpoint, spn, encrypted, err := validateKerberosConfiguration(&test.owner, test.endpoint)
			if test.wantErrorContains != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErrorContains) {
					t.Fatalf("error = %v, want containing %q", err, test.wantErrorContains)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if endpoint != test.endpoint.url() || spn != test.wantSPN || encrypted != test.wantEncryption {
				t.Fatalf("configuration = %q, %q, %v", endpoint, spn, encrypted)
			}
		})
	}
}

func TestKerberosCredentialPrecedence(t *testing.T) {
	configPath := t.TempDir() + "/krb5.conf"
	configuration := "[libdefaults]\n default_realm = EXAMPLE.TEST\n[realms]\n EXAMPLE.TEST = {\n  kdc = 127.0.0.1\n }\n"
	if err := os.WriteFile(configPath, []byte(configuration), 0o600); err != nil {
		t.Fatal(err)
	}
	owner := &ClientKerberos{
		Username: "user", Password: "password", Realm: "EXAMPLE.TEST", KrbConf: configPath,
		KrbCCache: "/missing/ccache", KrbKeytab: "/missing/keytab",
	}
	if _, err := newKerberosCredentialClient(owner); err == nil || !strings.Contains(err.Error(), "ccache") {
		t.Fatalf("ccache precedence error = %v", err)
	}
	owner.KrbCCache = ""
	if _, err := newKerberosCredentialClient(owner); err == nil || !strings.Contains(err.Error(), "keytab") {
		t.Fatalf("keytab precedence error = %v", err)
	}
	owner.KrbKeytab = ""
	kerberosClient, err := newKerberosCredentialClient(owner)
	if err != nil {
		t.Fatal(err)
	}
	kerberosClient.Destroy()
}

func TestKerberosSessionBootstrapAndReuse(t *testing.T) {
	connection := &fixtureConnection{id: "one"}
	transport := &scriptedKerberosTransport{steps: []kerberosHTTPFixture{
		{status: http.StatusUnauthorized, connection: connection},
		{status: http.StatusUnauthorized, connection: connection},
		{status: http.StatusOK, connection: connection},
	}}
	factoryCalls := 0
	session := newFixtureKerberosSession(transport, func(client *http.Client) kerberosNegotiator {
		factoryCalls++
		return &fixtureKerberosNegotiator{client: client, rounds: 3, context: fixtureSecurityContext(t)}
	})

	if err := session.establishForTest(); err != nil {
		t.Fatal(err)
	}
	if err := session.establishForTest(); err != nil {
		t.Fatal(err)
	}
	if factoryCalls != 1 || transport.calls() != 3 || session.connection != connection || session.state != kerberosSessionEstablished {
		t.Fatalf("bootstrap state = factory %d, calls %d, connection %v, state %d", factoryCalls, transport.calls(), session.connection, session.state)
	}
	for index, body := range transport.bodies() {
		if body != "" {
			t.Fatalf("bootstrap request %d body = %q", index, body)
		}
	}
}

func TestKerberosSessionTracksRealHTTPConnection(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if requests == 1 {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	session := &kerberosSession{
		state: kerberosSessionCredentialsReady, endpoint: server.URL + "/wsman", spn: "HTTP/host.example.test",
		httpClient: server.Client(),
	}
	session.newNegotiator = func(client *http.Client) kerberosNegotiator {
		return &fixtureKerberosNegotiator{client: client, rounds: 2, context: fixtureSecurityContext(t)}
	}
	if err := session.establishForTest(); err != nil {
		t.Fatal(err)
	}
	if session.connection == nil || requests != 2 {
		t.Fatalf("connection/requests = %v/%d", session.connection, requests)
	}
}

func TestKerberosSessionRejectsIncompleteAndInvalidAuthentication(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		context   gssapi.Context
		negotiate error
		want      string
	}{
		{name: "200 without final token", status: http.StatusOK, want: "did not complete"},
		{name: "invalid AP-REP", status: http.StatusOK, negotiate: errors.New("invalid AP-REP"), want: "invalid AP-REP"},
		{name: "non-200 completion", status: http.StatusUnauthorized, context: fixtureSecurityContext(t), want: "HTTP status 401"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := &scriptedKerberosTransport{steps: []kerberosHTTPFixture{{status: test.status, connection: &fixtureConnection{id: test.name}}}}
			session := newFixtureKerberosSession(transport, func(client *http.Client) kerberosNegotiator {
				return &fixtureKerberosNegotiator{client: client, rounds: 1, context: test.context, err: test.negotiate}
			})
			err := session.establishForTest()
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want containing %q", err, test.want)
			}
			if session.state != kerberosSessionInvalid || session.adapter != nil {
				t.Fatalf("failed bootstrap state = %d, adapter = %v", session.state, session.adapter)
			}
			var kerberosError *KerberosError
			if !errors.As(err, &kerberosError) || kerberosError.Stage == "" {
				t.Fatalf("structured error = %#v", err)
			}
		})
	}
}

func TestKerberosSessionHonorsCanceledContext(t *testing.T) {
	transport := &cancelableKerberosTransport{started: make(chan struct{})}
	session := newFixtureKerberosSession(transport, func(client *http.Client) kerberosNegotiator {
		return &fixtureKerberosNegotiator{client: client, rounds: 1, context: fixtureSecurityContext(t)}
	})
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := session.post(ctx, "<soap/>", 1024)
		result <- err
	}()
	<-transport.started
	cancel()
	err := <-result
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v", err)
	}
}

func TestKerberosSessionLimitsBootstrapAndResponseBodies(t *testing.T) {
	connection := &fixtureConnection{id: "limit"}
	steps := make([]kerberosHTTPFixture, kerberosMaxBootstrapExchanges)
	for index := range steps {
		steps[index] = kerberosHTTPFixture{status: http.StatusUnauthorized, connection: connection}
	}
	transport := &scriptedKerberosTransport{steps: steps}
	session := newFixtureKerberosSession(transport, func(client *http.Client) kerberosNegotiator {
		return &fixtureKerberosNegotiator{client: client, rounds: kerberosMaxBootstrapExchanges + 1, context: fixtureSecurityContext(t)}
	})
	if err := session.establishForTest(); err == nil || !strings.Contains(err.Error(), "exceeded five") {
		t.Fatalf("exchange limit error = %v", err)
	}
	if transport.calls() != kerberosMaxBootstrapExchanges {
		t.Fatalf("HTTP exchanges = %d", transport.calls())
	}

	transport = &scriptedKerberosTransport{steps: []kerberosHTTPFixture{{
		status: http.StatusOK, connection: connection, body: strings.Repeat("x", kerberosMaxBootstrapBody+1),
	}}}
	session = newFixtureKerberosSession(transport, func(client *http.Client) kerberosNegotiator {
		return &fixtureKerberosNegotiator{client: client, rounds: 1, context: fixtureSecurityContext(t)}
	})
	if err := session.establishForTest(); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("body limit error = %v", err)
	}
}

func TestKerberosSessionRetriesBootstrapOnConnectionReplacement(t *testing.T) {
	first := &fixtureConnection{id: "first"}
	second := &fixtureConnection{id: "second"}
	transport := &scriptedKerberosTransport{steps: []kerberosHTTPFixture{
		{status: http.StatusUnauthorized, connection: first},
		{status: http.StatusOK, connection: second},
		{status: http.StatusUnauthorized, connection: second},
		{status: http.StatusOK, connection: second},
	}}
	factoryCalls := 0
	session := newFixtureKerberosSession(transport, func(client *http.Client) kerberosNegotiator {
		factoryCalls++
		return &fixtureKerberosNegotiator{client: client, rounds: 2, unauthenticatedFirst: true, context: fixtureSecurityContext(t)}
	})
	if err := session.establishForTest(); err != nil {
		t.Fatal(err)
	}
	if factoryCalls != 1 || session.connection != second {
		t.Fatalf("reconnect result = factories %d, connection %v", factoryCalls, session.connection)
	}
}

func TestKerberosSessionRejectsRedirects(t *testing.T) {
	transport := &scriptedKerberosTransport{steps: []kerberosHTTPFixture{{
		status: http.StatusFound, connection: &fixtureConnection{id: "redirect"}, location: "http://other.example.test/wsman",
	}}}
	session := newFixtureKerberosSession(transport, func(client *http.Client) kerberosNegotiator {
		return &fixtureKerberosNegotiator{client: client, rounds: 1, context: fixtureSecurityContext(t)}
	})
	if err := session.establishForTest(); err == nil || !strings.Contains(err.Error(), "redirects are not permitted") {
		t.Fatalf("redirect error = %v", err)
	}
}

func TestKerberosSessionPostModesAndConnectionLoss(t *testing.T) {
	connection := &fixtureConnection{id: "bound"}
	initiator, acceptor := newTestKerberosGSSPair(t, 18, []byte("0123456789abcdef0123456789abcdef"), true)
	encryptedTransport := &encryptedKerberosTransport{
		connection: connection, serverAdapter: acceptor, response: "<encrypted-response/>",
	}
	session := newFixtureKerberosSession(encryptedTransport, func(client *http.Client) kerberosNegotiator {
		return &fixtureKerberosNegotiator{client: client, rounds: 1, context: initiator.context.(gssapi.Context)}
	})
	session.requireEncryption = true
	result, err := session.post(context.Background(), "<encrypted-soap/>", 1024)
	if err != nil || result != "<encrypted-response/>" {
		t.Fatalf("protected post = %q, %v", result, err)
	}
	if encryptedTransport.request != "<encrypted-soap/>" || encryptedTransport.calls != 2 {
		t.Fatalf("protected request/calls = %q/%d", encryptedTransport.request, encryptedTransport.calls)
	}

	transport := &scriptedKerberosTransport{steps: []kerberosHTTPFixture{{status: http.StatusOK, connection: connection}}}
	session = newFixtureKerberosSession(transport, func(client *http.Client) kerberosNegotiator {
		return &fixtureKerberosNegotiator{client: client, rounds: 1, context: fixtureSecurityContext(t)}
	})
	transport.steps = []kerberosHTTPFixture{
		{status: http.StatusOK, connection: connection},
		{status: http.StatusOK, connection: connection, contentType: soapXML, body: "<response/>"},
	}
	session = newFixtureKerberosSession(transport, func(client *http.Client) kerberosNegotiator {
		return &fixtureKerberosNegotiator{client: client, rounds: 1, context: fixtureSecurityContext(t)}
	})
	result, err = session.post(context.Background(), "<soap/>", 1024)
	if err != nil || result != "<response/>" {
		t.Fatalf("plaintext post = %q, %v", result, err)
	}
	if bodies := transport.bodies(); len(bodies) != 2 || bodies[0] != "" || bodies[1] != "<soap/>" {
		t.Fatalf("plaintext request bodies = %q", bodies)
	}
	transport.steps = append(transport.steps, kerberosHTTPFixture{
		status: http.StatusOK, connection: connection, contentType: soapXML, body: "<second/>",
	})
	result, err = session.post(context.Background(), "<soap-two/>", 1024)
	if err != nil || result != "<second/>" || transport.calls() != 3 {
		t.Fatalf("reused plaintext post = %q, %v, calls %d", result, err, transport.calls())
	}

	replacement := &fixtureConnection{id: "replacement"}
	transport = &scriptedKerberosTransport{steps: []kerberosHTTPFixture{
		{status: http.StatusOK, connection: connection},
		{status: http.StatusOK, connection: replacement, contentType: soapXML, body: "<response/>"},
	}}
	session = newFixtureKerberosSession(transport, func(client *http.Client) kerberosNegotiator {
		return &fixtureKerberosNegotiator{client: client, rounds: 1, context: fixtureSecurityContext(t)}
	})
	if _, err := session.post(context.Background(), "<soap/>", 1024); err == nil || !strings.Contains(err.Error(), "was not replayed") {
		t.Fatalf("connection replacement error = %v", err)
	}
	if transport.calls() != 2 || session.state != kerberosSessionInvalid {
		t.Fatalf("replacement calls/state = %d/%d", transport.calls(), session.state)
	}
	transport.steps = append(transport.steps,
		kerberosHTTPFixture{status: http.StatusOK, connection: replacement},
		kerberosHTTPFixture{status: http.StatusOK, connection: replacement, contentType: soapXML, body: "<fresh/>"})
	result, err = session.post(context.Background(), "<fresh-soap/>", 1024)
	if err != nil || result != "<fresh/>" || transport.calls() != 4 {
		t.Fatalf("fresh post after replacement = %q, %v, calls %d", result, err, transport.calls())
	}
	if bodies := transport.bodies(); bodies[2] != "" || bodies[3] != "<fresh-soap/>" {
		t.Fatalf("post-replacement request bodies = %q", bodies)
	}
}

func TestKerberosSessionEncryptedResponseHandling(t *testing.T) {
	t.Run("authenticated SOAP fault", func(t *testing.T) {
		session, transport := newEncryptedFixtureSession(t, executeCommandResponseWithError)
		transport.responseStatus = http.StatusInternalServerError
		response, err := session.post(context.Background(), "<soap/>", 4096)
		if err != nil {
			t.Fatal(err)
		}
		_, parseErr := ParseExecuteCommandResponse(response)
		var commandError *ExecuteCommandError
		if !errors.As(parseErr, &commandError) || commandError.Body != executeCommandResponseWithError {
			t.Fatalf("SOAP fault = %#v", parseErr)
		}
		if session.state != kerberosSessionEstablished || transport.calls != 2 {
			t.Fatalf("fault state/calls = %d/%d", session.state, transport.calls)
		}
	})

	tests := []struct {
		name      string
		configure func(*encryptedKerberosTransport)
		wantStage string
	}{
		{name: "plaintext fallback", configure: func(transport *encryptedKerberosTransport) { transport.plaintext = true }, wantStage: "unwrap"},
		{name: "tampered ciphertext", configure: func(transport *encryptedKerberosTransport) { transport.tamper = true }, wantStage: "unwrap"},
		{name: "oversized response", configure: func(transport *encryptedKerberosTransport) { transport.oversized = true }, wantStage: "http"},
		{name: "replacement connection", configure: func(transport *encryptedKerberosTransport) {
			transport.responseConnection = &fixtureConnection{id: "replacement"}
		}, wantStage: "http"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			session, transport := newEncryptedFixtureSession(t, "<response/>")
			test.configure(transport)
			_, err := session.post(context.Background(), "<soap/>", 1024)
			var kerberosError *KerberosError
			if !errors.As(err, &kerberosError) || kerberosError.Stage != test.wantStage {
				t.Fatalf("error = %#v, want stage %q", err, test.wantStage)
			}
			if session.state != kerberosSessionInvalid || transport.calls != 2 {
				t.Fatalf("failure state/calls = %d/%d", session.state, transport.calls)
			}
		})
	}
}

func TestKerberosBoundedReadCloserReportsBytesWrittenOnOverflow(t *testing.T) {
	body := io.NopCloser(strings.NewReader("12345"))
	reader := &kerberosBoundedReadCloser{reader: body, closer: body, remaining: 4}
	buffer := make([]byte, 8)

	count, err := reader.Read(buffer)
	if count != 5 || err == nil || !strings.Contains(err.Error(), "exceeds configured limit") {
		t.Fatalf("overflow read = (%d, %v), want (5, limit error)", count, err)
	}
	if string(buffer[:count]) != "12345" {
		t.Fatalf("overflow bytes = %q", buffer[:count])
	}
}

func newEncryptedFixtureSession(t *testing.T, response string) (*kerberosSession, *encryptedKerberosTransport) {
	t.Helper()
	connection := &fixtureConnection{id: "encrypted"}
	initiator, acceptor := newTestKerberosGSSPair(t, 18, []byte("0123456789abcdef0123456789abcdef"), true)
	transport := &encryptedKerberosTransport{connection: connection, serverAdapter: acceptor, response: response}
	session := newFixtureKerberosSession(transport, func(client *http.Client) kerberosNegotiator {
		return &fixtureKerberosNegotiator{client: client, rounds: 1, context: initiator.context.(gssapi.Context)}
	})
	session.requireEncryption = true
	return session, transport
}

func TestKerberosSessionCloseIsIdempotent(t *testing.T) {
	transport := &scriptedKerberosTransport{}
	session := newFixtureKerberosSession(transport, nil)
	if err := session.close(); err != nil {
		t.Fatal(err)
	}
	if err := session.close(); err != nil {
		t.Fatal(err)
	}
	if session.state != kerberosSessionClosed || transport.closeCalls != 1 {
		t.Fatalf("close state/calls = %d/%d", session.state, transport.closeCalls)
	}
	if _, err := session.post(context.Background(), "<soap/>", 1024); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("post after close error = %v", err)
	}
}

func (session *kerberosSession) establishForTest() error {
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.establishLocked(context.Background())
}

func newFixtureKerberosSession(transport http.RoundTripper, factory func(*http.Client) kerberosNegotiator) *kerberosSession {
	httpClient := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("redirects are not permitted during Kerberos authentication")
	}}
	return &kerberosSession{
		state: kerberosSessionCredentialsReady, endpoint: "http://host.example.test:5985/wsman", spn: "HTTP/host.example.test",
		httpClient: httpClient, newNegotiator: factory,
	}
}

func fixtureSecurityContext(t *testing.T) gssapi.Context {
	t.Helper()
	context, err := gssapi.NewSecurityContext(types.EncryptionKey{
		KeyType: 18, KeyValue: []byte("0123456789abcdef0123456789abcdef"),
	}, true, 0, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	return context
}

type fixtureKerberosNegotiator struct {
	client               *http.Client
	rounds               int
	unauthenticatedFirst bool
	context              gssapi.Context
	err                  error
}

func (negotiator *fixtureKerberosNegotiator) Do(request *http.Request) (*http.Response, error) {
	var response *http.Response
	for round := 0; round < negotiator.rounds; round++ {
		if response != nil && response.Body != nil {
			response.Body.Close()
		}
		var err error
		current := request.Clone(request.Context())
		if round > 0 || !negotiator.unauthenticatedFirst {
			current.Header.Set(spnego.HTTPHeaderAuthRequest, "Negotiate fixture")
		}
		response, err = negotiator.client.Do(current)
		if err != nil {
			return response, err
		}
	}
	return response, negotiator.err
}

func (negotiator *fixtureKerberosNegotiator) Context() gssapi.Context { return negotiator.context }

type kerberosHTTPFixture struct {
	status      int
	connection  net.Conn
	body        string
	contentType string
	location    string
}

type scriptedKerberosTransport struct {
	mu         sync.Mutex
	steps      []kerberosHTTPFixture
	requests   []string
	closeCalls int
}

type cancelableKerberosTransport struct {
	started chan struct{}
	once    sync.Once
}

type encryptedKerberosTransport struct {
	connection         net.Conn
	responseConnection net.Conn
	serverAdapter      *kerberosGSSAdapter
	response           string
	responseStatus     int
	request            string
	calls              int
	plaintext          bool
	tamper             bool
	oversized          bool
}

func (transport *encryptedKerberosTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.calls++
	connection := transport.connection
	if transport.calls > 1 && transport.responseConnection != nil {
		connection = transport.responseConnection
	}
	if trace := httptrace.ContextClientTrace(request.Context()); trace != nil && trace.GotConn != nil {
		trace.GotConn(httptrace.GotConnInfo{Conn: connection, Reused: transport.calls > 1})
	}
	if transport.calls == 1 {
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, Request: request,
		}, nil
	}
	requestBody, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	framer, err := newKerberosMessageFramer(4096)
	if err != nil {
		return nil, err
	}
	plaintext, err := framer.open(request.Header.Get("Content-Type"), requestBody, transport.serverAdapter)
	if err != nil {
		return nil, err
	}
	transport.request = string(plaintext)
	status := transport.responseStatus
	if status == 0 {
		status = http.StatusOK
	}
	if transport.plaintext {
		header := make(http.Header)
		header.Set("Content-Type", soapXML)
		return &http.Response{
			StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(transport.response)), Request: request,
		}, nil
	}
	if transport.oversized {
		return &http.Response{
			StatusCode: status, Header: make(http.Header),
			Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 1024+kerberosMaxWrapOverhead+kerberosMaxMetadataSize+1))), Request: request,
		}, nil
	}
	contentType, responseBody, err := framer.seal([]byte(transport.response), transport.serverAdapter)
	if err != nil {
		return nil, err
	}
	header := make(http.Header)
	header.Set("Content-Type", contentType)
	if transport.tamper {
		terminalLength := len("--" + kerberosMultipartBoundary + "--\r\n")
		responseBody[len(responseBody)-terminalLength-1] ^= 0xff
	}
	return &http.Response{
		StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(string(responseBody))), Request: request,
	}, nil
}

func (transport *cancelableKerberosTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.once.Do(func() { close(transport.started) })
	<-request.Context().Done()
	return nil, request.Context().Err()
}

func (transport *scriptedKerberosTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if err := request.Context().Err(); err != nil {
		return nil, err
	}
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.requests) >= len(transport.steps) {
		return nil, errors.New("unexpected HTTP request")
	}
	step := transport.steps[len(transport.requests)]
	var body []byte
	if request.Body != nil {
		var err error
		body, err = io.ReadAll(request.Body)
		if err != nil {
			return nil, err
		}
	}
	transport.requests = append(transport.requests, string(body))
	if trace := httptrace.ContextClientTrace(request.Context()); trace != nil && trace.GotConn != nil {
		trace.GotConn(httptrace.GotConnInfo{Conn: step.connection, Reused: len(transport.requests) > 1})
	}
	header := make(http.Header)
	if step.contentType != "" {
		header.Set("Content-Type", step.contentType)
	}
	if step.location != "" {
		header.Set("Location", step.location)
	}
	return &http.Response{
		StatusCode: step.status, Status: http.StatusText(step.status), Header: header,
		Body: io.NopCloser(strings.NewReader(step.body)), Request: request,
	}, nil
}

func (transport *scriptedKerberosTransport) CloseIdleConnections() {
	transport.mu.Lock()
	transport.closeCalls++
	transport.mu.Unlock()
}

func (transport *scriptedKerberosTransport) calls() int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return len(transport.requests)
}

func (transport *scriptedKerberosTransport) bodies() []string {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return append([]string(nil), transport.requests...)
}

type fixtureConnection struct{ id string }

func (*fixtureConnection) Read([]byte) (int, error)         { return 0, io.EOF }
func (*fixtureConnection) Write(buffer []byte) (int, error) { return len(buffer), nil }
func (*fixtureConnection) Close() error                     { return nil }
func (connection *fixtureConnection) LocalAddr() net.Addr {
	return fixtureAddress(connection.id + "-local")
}
func (connection *fixtureConnection) RemoteAddr() net.Addr {
	return fixtureAddress(connection.id + "-remote")
}
func (*fixtureConnection) SetDeadline(time.Time) error      { return nil }
func (*fixtureConnection) SetReadDeadline(time.Time) error  { return nil }
func (*fixtureConnection) SetWriteDeadline(time.Time) error { return nil }

type fixtureAddress string

func (fixtureAddress) Network() string        { return "fixture" }
func (address fixtureAddress) String() string { return string(address) }
