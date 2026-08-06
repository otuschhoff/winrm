package winrm

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/bodgit/ntlmssp"
	ntlmhttp "github.com/bodgit/ntlmssp/http"
	krbcrypto "github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/masterzen/winrm/soap"
)

type Encryption struct {
	ntlm           *ClientNTLM
	kerberos       *ClientKerberos
	kerberosMode   KerberosRuntimeMode
	failurePolicy  KerberosFailurePolicy
	protocol       string
	protocolString []byte
	httpClient     *http.Client
	ntlmClient     *ntlmssp.Client
	ntlmhttp       *ntlmhttp.Client
}

const (
	sixTenKB       = 16384
	mimeBoundary   = "--Encrypted Boundary"
	defaultCipher  = "RC4-HMAC-NTLM"
	boundaryLength = len(mimeBoundary)
)

/*
Encrypted Message Types
When using Encryption, there are three options available

 1. Negotiate/SPNEGO

 2. Kerberos

 3. CredSSP

    protocol: The protocol string used for the particular auth protocol

    The auth protocol used, will determine the wrapping and unwrapping method plus
    the protocol string to use. Currently only NTLM is supported

    based on the python code from https://pypi.org/project/pywinrm/

    see https://github.com/diyan/pywinrm/blob/master/winrm/encryption.py

    uses the most excellent NTLM library from https://github.com/bodgit/ntlmssp
*/
func NewEncryption(protocol string) (*Encryption, error) {
	encryption := &Encryption{
		ntlm:     &ClientNTLM{},
		protocol: protocol,
	}

	switch protocol {
	case "ntlm":
		encryption.protocolString = []byte("application/HTTP-SPNEGO-session-encrypted")
		return encryption, nil
	case "kerberos":
		encryption.protocolString = []byte("application/HTTP-SPNEGO-session-encrypted")
		encryption.kerberos = &ClientKerberos{}
		encryption.kerberosMode = KerberosModeMessageEncryptionRequired
		encryption.failurePolicy = defaultKerberosFailurePolicyForMode(encryption.kerberosMode)
		return encryption, nil
		/* credssp is currently unimplemented, leave holder for future to keep in sync with python implementation
		case "credssp":
			encryption.protocolString = []byte("application/HTTP-CredSSP-session-encrypted")
		*/
	}

	return nil, fmt.Errorf("Encryption for protocol '%s' not supported", protocol)
}

func (e *Encryption) Transport(endpoint *Endpoint) error {
	e.httpClient = &http.Client{}

	switch e.protocol {
	case "ntlm":
		return e.ntlm.Transport(endpoint)
	case "kerberos":
		if e.kerberos == nil {
			e.kerberos = &ClientKerberos{}
		}
		return e.kerberos.Transport(endpoint)
	default:
		return fmt.Errorf("Encryption for protocol '%s' not supported", e.protocol)
	}
}

func (e *Encryption) Post(client *Client, message *soap.SoapMessage) (string, error) {
	switch e.protocol {
	case "ntlm":
		return e.postNTLM(client, message)
	case "kerberos":
		return e.postKerberos(client, message)
	default:
		return "", fmt.Errorf("Encryption for protocol '%s' not supported", e.protocol)
	}
}

// SetKerberosRuntimeMode configures how the kerberos protocol path should behave.
func (e *Encryption) SetKerberosRuntimeMode(mode KerberosRuntimeMode) error {
	if err := validateKerberosRuntimeMode(mode); err != nil {
		return err
	}
	e.kerberosMode = mode
	e.failurePolicy = defaultKerberosFailurePolicyForMode(mode)
	return nil
}

// SetKerberosFailurePolicy overrides the default fail policy for kerberos mode.
func (e *Encryption) SetKerberosFailurePolicy(policy KerberosFailurePolicy) {
	e.failurePolicy = policy
}

func (e *Encryption) postNTLM(client *Client, message *soap.SoapMessage) (string, error) {
	var userName, domain string
	if strings.Contains(client.username, "@") {
		parts := strings.Split(client.username, "@")
		domain = parts[1]
		userName = parts[0]
	} else if strings.Contains(client.username, "\\") {
		parts := strings.Split(client.username, "\\")
		domain = parts[0]
		userName = parts[1]
	} else {
		userName = client.username
	}

	e.ntlmClient, _ = ntlmssp.NewClient(ntlmssp.SetUserInfo(userName, client.password), ntlmssp.SetDomain(domain), ntlmssp.SetVersion(ntlmssp.DefaultVersion()))
	e.ntlmhttp, _ = ntlmhttp.NewClient(e.httpClient, e.ntlmClient)

	if err := e.PrepareRequest(client, client.url); err == nil {
		return e.PrepareEncryptedRequest(client, client.url, []byte(message.String()))
	}

	return e.ntlm.Post(client, message)
}

func (e *Encryption) postKerberos(client *Client, message *soap.SoapMessage) (string, error) {
	if err := e.primeKerberosClient(client); err != nil {
		return "", err
	}

	if e.kerberosMode == KerberosModeAuthOnly {
		return e.kerberos.Post(client, message)
	}

	if err := e.PrepareRequest(client, client.url); err != nil {
		return "", fmt.Errorf("kerberos encrypted session setup failed: %w", err)
	}

	return e.PrepareEncryptedRequest(client, client.url, []byte(message.String()))
}

func (e *Encryption) primeKerberosClient(client *Client) error {
	if e.kerberos == nil {
		e.kerberos = &ClientKerberos{}
	}

	if e.kerberos.Username == "" {
		e.kerberos.Username = client.username
	}
	if e.kerberos.Password == "" {
		e.kerberos.Password = client.password
	}

	if e.kerberos.KrbConf == "" {
		e.kerberos.KrbConf = "/etc/krb5.conf"
	}

	if e.kerberos.Realm == "" && strings.Contains(client.username, "@") {
		parts := strings.Split(client.username, "@")
		if len(parts) > 1 {
			e.kerberos.Realm = parts[len(parts)-1]
		}
	}

	parsedURL, err := url.Parse(client.url)
	if err != nil {
		return fmt.Errorf("invalid client URL for kerberos transport: %w", err)
	}

	if e.kerberos.Hostname == "" {
		e.kerberos.Hostname = parsedURL.Hostname()
	}

	if e.kerberos.Proto == "" {
		e.kerberos.Proto = parsedURL.Scheme
	}

	if e.kerberos.Port == 0 {
		port := parsedURL.Port()
		if port != "" {
			parsedPort, err := strconv.Atoi(port)
			if err != nil {
				return fmt.Errorf("invalid port in client URL %q: %w", client.url, err)
			}
			e.kerberos.Port = parsedPort
		} else if parsedURL.Scheme == "https" {
			e.kerberos.Port = 5986
		} else {
			e.kerberos.Port = 5985
		}
	}

	return nil
}

func (e *Encryption) doRequest(req *http.Request) (*http.Response, error) {
	switch e.protocol {
	case "ntlm":
		if e.ntlmhttp == nil {
			return nil, errors.New("ntlm encrypted transport is not initialized")
		}
		return e.ntlmhttp.Do(req)
	case "kerberos":
		if e.kerberos == nil {
			return nil, errors.New("kerberos encrypted transport is not initialized")
		}

		context, err := e.kerberos.getOrCreateContext()
		if err != nil {
			return nil, err
		}

		err = spnego.SetSPNEGOHeader(context.client, req, context.spn)
		if err != nil {
			return nil, fmt.Errorf("unable to set SPNego Header: %w", err)
		}

		httpClient := &http.Client{Transport: e.kerberos.transport}
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}

		if err := e.processKerberosResponseAuth(resp); err != nil {
			if e.failurePolicy.RejectTokenDecryptFailure {
				_ = resp.Body.Close()
				return nil, err
			}
		}

		return resp, nil
	default:
		return nil, fmt.Errorf("Encryption for protocol '%s' not supported", e.protocol)
	}
}

func (e *Encryption) processKerberosResponseAuth(resp *http.Response) error {
	if resp == nil || resp.Header == nil || e.kerberos == nil {
		return nil
	}

	authHeaders := resp.Header.Values("WWW-Authenticate")
	for _, authHeader := range authHeaders {
		authHeader = strings.TrimSpace(authHeader)
		if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "negotiate ") {
			continue
		}

		tokenB64 := strings.TrimSpace(authHeader[len("Negotiate "):])
		if tokenB64 == "" {
			continue
		}

		tokenBytes, err := base64.StdEncoding.DecodeString(tokenB64)
		if err != nil {
			return fmt.Errorf("unable to decode SPNEGO response token: %w", err)
		}

		var spnegoToken spnego.SPNEGOToken
		if err := spnegoToken.Unmarshal(tokenBytes); err != nil {
			return fmt.Errorf("unable to parse SPNEGO response token: %w", err)
		}

		if !spnegoToken.Resp || len(spnegoToken.NegTokenResp.ResponseToken) == 0 {
			return nil
		}

		var krbToken spnego.KRB5Token
		if err := krbToken.Unmarshal(spnegoToken.NegTokenResp.ResponseToken); err != nil {
			return fmt.Errorf("unable to parse kerberos response token: %w", err)
		}

		if !krbToken.IsAPRep() {
			return nil
		}

		context, err := e.kerberos.getOrCreateContext()
		if err != nil {
			return err
		}

		context.mu.Lock()
		defer context.mu.Unlock()

		if len(context.serviceSessionKey.KeyValue) == 0 {
			return errors.New("kerberos service session key is not initialized for AP_REP")
		}

		encPartBytes, err := krbcrypto.DecryptEncPart(krbToken.APRep.EncPart, context.serviceSessionKey, keyusage.AP_REP_ENCPART)
		if err != nil {
			return fmt.Errorf("unable to decrypt AP_REP enc part: %w", err)
		}

		var encPart messages.EncAPRepPart
		if err := encPart.Unmarshal(encPartBytes); err != nil {
			return fmt.Errorf("unable to parse AP_REP enc part: %w", err)
		}

		e.applyKerberosAPRep(context, encPart)
		return nil
	}

	return nil
}

func (e *Encryption) applyKerberosAPRep(context *kerberosContext, encPart messages.EncAPRepPart) {
	if context == nil {
		return
	}

	if encPart.Subkey.KeyType != 0 && len(encPart.Subkey.KeyValue) > 0 {
		subKey := encPart.Subkey
		context.acceptorSubKey = &subKey
	}

	if encPart.SequenceNumber > 0 {
		context.acceptorSeq = uint64(encPart.SequenceNumber)
	}
}

func (e *Encryption) kerberosOutboundKey(context *kerberosContext) (types.EncryptionKey, error) {
	if context == nil {
		return types.EncryptionKey{}, errors.New("kerberos context is not initialized")
	}

	if context.acceptorSubKey != nil && len(context.acceptorSubKey.KeyValue) > 0 {
		return *context.acceptorSubKey, nil
	}

	if len(context.serviceSessionKey.KeyValue) == 0 {
		return types.EncryptionKey{}, errors.New("kerberos service session key is not initialized")
	}

	return context.serviceSessionKey, nil
}

func (e *Encryption) kerberosInboundKey(context *kerberosContext) (types.EncryptionKey, error) {
	if context == nil {
		return types.EncryptionKey{}, errors.New("kerberos context is not initialized")
	}

	if context.acceptorSubKey != nil && len(context.acceptorSubKey.KeyValue) > 0 {
		return *context.acceptorSubKey, nil
	}

	if len(context.serviceSessionKey.KeyValue) == 0 {
		return types.EncryptionKey{}, errors.New("kerberos inbound security key is not initialized")
	}

	return context.serviceSessionKey, nil
}

func (e *Encryption) PrepareRequest(client *Client, endpoint string) error {
	req, err := http.NewRequest("POST", endpoint, nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", "WinRM client")
	req.Header.Set("Content-Length", "0")
	req.Header.Set("Content-Type", "application/soap+xml;charset=UTF-8")
	req.Header.Set("Connection", "Keep-Alive")

	resp, err := e.doRequest(req)
	if err != nil {
		return fmt.Errorf("unknown error %w", err)
	}

	if _, err := io.ReadAll(resp.Body); err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	if err := resp.Body.Close(); err != nil {
		return fmt.Errorf("close request body: %w", err)
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("http error %d", resp.StatusCode)
	}

	return nil
}

/*
Creates a prepared request to send to the server with an encrypted message
and correct headers

:param endpoint: The endpoint/server to prepare requests to
:param message: The unencrypted message to send to the server
:return: A prepared request that has an decrypted message
*/
func (e *Encryption) PrepareEncryptedRequest(client *Client, endpoint string, message []byte) (string, error) {
	url, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	host := strings.Split(url.Hostname(), ":")[0]

	var content_type string
	var encrypted_message []byte

	if e.protocol == "credssp" && len(message) > sixTenKB {
		content_type = "multipart/x-multi-encrypted"
		encrypted_message = []byte{}
		message_chunks := [][]byte{}
		for i := 0; i < len(message); i += sixTenKB {
			end := i + sixTenKB
			if end > len(message) {
				end = len(message)
			}
			message_chunks = append(message_chunks, message[i:end])
		}
		for _, message_chunk := range message_chunks {
			encrypted_chunk, err := e.encryptMessage(message_chunk, host)
			if err != nil {
				return "", err
			}
			encrypted_message = append(encrypted_message, encrypted_chunk...)
		}
	} else {
		content_type = "multipart/encrypted"
		encrypted_message, err = e.encryptMessage(message, host)
		if err != nil {
			return "", err
		}
	}

	encrypted_message = append(encrypted_message, []byte(mimeBoundary)...)
	encrypted_message = append(encrypted_message, []byte("--\r\n")...)

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(encrypted_message))
	if err != nil {
		return "", err
	}

	req.Header.Set("User-Agent", "WinRM client")
	req.Header.Set("Connection", "Keep-Alive")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(encrypted_message)))
	req.Header.Set("Content-Type", fmt.Sprintf(`%s;protocol="%s";boundary="Encrypted Boundary"`, content_type, e.protocolString))

	resp, err := e.doRequest(req)
	if err != nil {
		return "", fmt.Errorf("unknown error %w", err)
	}

	body, err := e.ParseEncryptedResponse(resp)

	return string(body), err
}

/*
Takes in the encrypted response from the server and decrypts it

:param response: The response that needs to be decrytped
:return: The unencrypted message from the server
*/
func (e *Encryption) ParseEncryptedResponse(response *http.Response) ([]byte, error) {
	contentType := response.Header.Get("Content-Type")
	if strings.Contains(contentType, fmt.Sprintf(`protocol="%s"`, e.protocolString)) {
		return e.decryptResponse(response, response.Request.URL.Hostname())
	}

	if e.protocol == "kerberos" && e.kerberosMode == KerberosModeMessageEncryptionRequired && e.failurePolicy.RejectUnencryptedResponse {
		if response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, errors.New("kerberos message encryption is required but server response is not encrypted")
	}

	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (e *Encryption) encryptMessage(message []byte, host string) ([]byte, error) {
	encryptedStream, err := e.buildMessage(message, host)
	if err != nil {
		return nil, err
	}

	messagePayload := bytes.Join([][]byte{
		[]byte(mimeBoundary),
		[]byte("\r\n"),
		[]byte("\tContent-Type: " + string(e.protocolString) + "\r\n"),
		[]byte("\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=" + strconv.Itoa(len(message)) + "\r\n"),
		[]byte(mimeBoundary),
		[]byte("\r\n"),
		[]byte("\tContent-Type: application/octet-stream\r\n"),
		encryptedStream,
	}, []byte{})

	return messagePayload, nil
}

func deleteEmpty(b [][]byte) [][]byte {
	var r [][]byte
	for _, by := range b {
		if len(by) != 0 {
			r = append(r, by)
		}
	}
	return r
}

// tried using pkg.go.dev/mime/multipart here but parsing fails with with
// because in the header we have "\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n"
// on call to textproto.ReadMIMEHeader
// because of "The first line cannot start with a leading space."
func (e *Encryption) decryptResponse(response *http.Response, host string) ([]byte, error) {
	if response == nil || response.Body == nil {
		return nil, errors.New("encrypted response body is empty")
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to read encrypted response body: %w", err)
	}
	if err := response.Body.Close(); err != nil {
		return nil, fmt.Errorf("unable to close encrypted response body: %w", err)
	}

	parts := deleteEmpty(bytes.Split(body, []byte(mimeBoundary+"\r\n")))
	if len(parts) < 2 {
		return nil, errors.New("encrypted response has invalid MIME structure")
	}

	var message []byte

	for i := 0; i < len(parts); i += 2 {
		if i+1 >= len(parts) {
			return nil, errors.New("encrypted response has unpaired MIME header/payload block")
		}

		header := parts[i]
		payload := parts[i+1]

		lengthPos := bytes.Index(header, []byte("Length="))
		if lengthPos == -1 {
			return nil, errors.New("encrypted response header is missing OriginalContent length")
		}

		expectedLengthStr := header[lengthPos+len("Length="):]
		if lineEnd := bytes.Index(expectedLengthStr, []byte("\r\n")); lineEnd != -1 {
			expectedLengthStr = expectedLengthStr[:lineEnd]
		}

		expectedLength, err := strconv.Atoi(string(bytes.TrimSpace(expectedLengthStr)))
		if err != nil {
			return nil, fmt.Errorf("unable to parse encrypted response length: %w", err)
		}

		// remove the end MIME block if it exists
		if bytes.HasSuffix(payload, []byte(mimeBoundary+"--\r\n")) {
			payload = payload[:len(payload)-boundaryLength-4]
		}
		encryptedData := bytes.ReplaceAll(payload, []byte("\tContent-Type: application/octet-stream\r\n"), []byte{})
		decryptedMessage, err := e.decryptMessage(encryptedData, host)
		if err != nil {
			return nil, err
		}

		actualLength := int(len(decryptedMessage))
		if actualLength != expectedLength {
			return nil, errors.New("encrypted length from server does not match the expected size, message has been tampered with")
		}

		message = append(message, decryptedMessage...)
	}

	return message, nil
}

func (e *Encryption) decryptMessage(encryptedData []byte, host string) ([]byte, error) {
	switch e.protocol {
	case "ntlm":
		return e.decryptNtlmMessage(encryptedData, host)
	case "kerberos":
		return e.decryptKerberosMessage(encryptedData, host)
		/* credssp is currently unimplemented, leave holder for future to keep in sync with python implementation
		case "credssp":
			return e.decryptCredsspMessage(encryptedData, host)
		*/
	default:
		return nil, errors.New("Encryption for protocol " + e.protocol + " not supported")
	}
}

func (e *Encryption) decryptNtlmMessage(encryptedData []byte, host string) ([]byte, error) {
	if len(encryptedData) < 4 {
		return nil, errors.New("ntlm encrypted payload is truncated: missing signature length")
	}

	signatureLength := int(binary.LittleEndian.Uint32(encryptedData[:4]))
	if signatureLength <= 0 {
		return nil, fmt.Errorf("ntlm encrypted payload has invalid signature length: %d", signatureLength)
	}

	if len(encryptedData) < 4+signatureLength {
		return nil, fmt.Errorf("ntlm encrypted payload is truncated: need at least %d bytes", 4+signatureLength)
	}

	signature := encryptedData[4 : signatureLength+4]
	encryptedMessage := encryptedData[signatureLength+4:]
	if len(encryptedMessage) == 0 {
		return nil, errors.New("ntlm encrypted payload is missing sealed message")
	}

	message, err := e.ntlmClient.SecuritySession().Unwrap(encryptedMessage, signature)
	if err != nil {
		return nil, err
	}
	return message, nil
}

func (enc *Encryption) decryptKerberosMessage(encryptedData []byte, host string) ([]byte, error) {
	_ = host

	if enc.kerberos == nil {
		return nil, errors.New("kerberos encrypted transport is not initialized")
	}

	if len(encryptedData) < 4 {
		return nil, errors.New("kerberos encrypted payload is truncated: missing signature length")
	}

	signatureLength := int(binary.LittleEndian.Uint32(encryptedData[:4]))
	if signatureLength <= 0 {
		return nil, fmt.Errorf("kerberos encrypted payload has invalid signature length: %d", signatureLength)
	}

	if len(encryptedData) < 4+signatureLength {
		return nil, fmt.Errorf("kerberos encrypted payload is truncated: need at least %d bytes", 4+signatureLength)
	}

	signature := encryptedData[4 : 4+signatureLength]
	sealedPayload := encryptedData[4+signatureLength:]
	if len(sealedPayload) == 0 {
		return nil, errors.New("kerberos encrypted payload is missing sealed message")
	}

	context, err := enc.kerberos.getOrCreateContext()
	if err != nil {
		return nil, err
	}

	context.mu.Lock()
	defer context.mu.Unlock()

	inboundKey, err := enc.kerberosInboundKey(context)
	if err != nil {
		return nil, err
	}

	decryptedMessage, err := krbcrypto.DecryptMessage(sealedPayload, inboundKey, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		if enc.failurePolicy.RejectTokenDecryptFailure {
			return nil, fmt.Errorf("unable to kerberos-unseal message: %w", err)
		}
		return nil, fmt.Errorf("unable to kerberos-unseal message: %w", err)
	}

	var wrapToken gssapi.WrapToken
	if err := wrapToken.Unmarshal(signature, true); err != nil {
		if enc.failurePolicy.RejectInvalidSignature {
			return nil, fmt.Errorf("unable to parse kerberos wrap signature: %w", err)
		}
		return nil, fmt.Errorf("unable to parse kerberos wrap signature: %w", err)
	}

	if ok, err := wrapToken.Verify(inboundKey, keyusage.GSSAPI_ACCEPTOR_SEAL); err != nil || !ok {
		if enc.failurePolicy.RejectInvalidSignature {
			if err != nil {
				return nil, fmt.Errorf("kerberos wrap signature verification failed: %w", err)
			}
			return nil, errors.New("kerberos wrap signature verification failed")
		}
		if err != nil {
			return nil, fmt.Errorf("kerberos wrap signature verification failed: %w", err)
		}
		return nil, errors.New("kerberos wrap signature verification failed")
	}

	if wrapToken.SndSeqNum != context.acceptorSeq {
		return nil, fmt.Errorf("kerberos acceptor sequence mismatch: expected %d got %d", context.acceptorSeq, wrapToken.SndSeqNum)
	}

	if !bytes.Equal(wrapToken.Payload, decryptedMessage) {
		return nil, errors.New("kerberos wrap payload mismatch after decrypt")
	}

	context.acceptorSeq++
	return decryptedMessage, nil
}

/* credssp is currently unimplemented, leave holder for future to keep in sync with python implementation
func (e *Encryption) decryptCredsspMessage(encryptedData []byte, host string) ([]byte, error) {
	// // TODO
	// encryptedMessage := encryptedData[4:]

	// credsspContext, ok := e.session.Auth.Contexts()[host]
	// if !ok {
	// 	return nil, fmt.Errorf("credssp context not found for host: %s", host)
	// }

	// message, err := credsspContext.Unwrap(encryptedMessage)
	// if err != nil {
	// 	return nil, err
	// }
	// return message, nil
}
*/

func (e *Encryption) buildMessage(encryptedData []byte, host string) ([]byte, error) {
	switch e.protocol {
	case "ntlm":
		return e.buildNTLMMessage(encryptedData, host)
	case "kerberos":
		return e.buildKerberosMessage(encryptedData, host)
		/* credssp is currently unimplemented, leave holder for future to keep in sync with python implementation
		case "credssp":
			return e.buildCredSSPMessage(encryptedData, host)
		*/
	default:
		return nil, errors.New("Encryption for protocol " + e.protocol + " not supported")
	}
}

func (enc *Encryption) buildNTLMMessage(message []byte, host string) ([]byte, error) {
	if enc.ntlmClient.SecuritySession() == nil {
		return nil, nil
	}
	sealedMessage, signature, err := enc.ntlmClient.SecuritySession().Wrap(message)
	if err != nil {
		return nil, err
	}

	buf := new(bytes.Buffer)
	if err = binary.Write(buf, binary.LittleEndian, uint32(len(signature))); err != nil {
		return nil, err
	}

	buf.Write(signature)
	buf.Write(sealedMessage)

	return buf.Bytes(), nil
}

func (e *Encryption) buildKerberosMessage(message []byte, host string) ([]byte, error) {
	_ = host

	if e.kerberos == nil {
		return nil, errors.New("kerberos encrypted transport is not initialized")
	}

	context, err := e.kerberos.getOrCreateContext()
	if err != nil {
		return nil, err
	}

	context.mu.Lock()
	defer context.mu.Unlock()

	outboundKey, err := e.kerberosOutboundKey(context)
	if err != nil {
		return nil, err
	}

	etype, err := krbcrypto.GetEtype(outboundKey.KeyType)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve kerberos etype: %w", err)
	}

	_, sealedMessage, err := etype.EncryptMessage(outboundKey.KeyValue, message, keyusage.GSSAPI_INITIATOR_SEAL)
	if err != nil {
		return nil, fmt.Errorf("unable to kerberos-seal message: %w", err)
	}

	flags := byte(0x02) // sealed flag set, initiator token
	if context.acceptorSubKey != nil {
		flags |= 0x04
	}

	wrapToken := &gssapi.WrapToken{
		Flags:     flags,
		EC:        uint16(etype.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: context.initiatorSeq,
		Payload:   message,
	}

	if err := wrapToken.SetCheckSum(outboundKey, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, fmt.Errorf("unable to sign kerberos wrap token: %w", err)
	}

	signature, err := wrapToken.Marshal()
	if err != nil {
		return nil, fmt.Errorf("unable to serialize kerberos wrap token: %w", err)
	}

	context.initiatorSeq++

	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, uint32(len(signature))); err != nil {
		return nil, err
	}
	buf.Write(signature)
	buf.Write(sealedMessage)

	return buf.Bytes(), nil
}

/* credssp is currently unimplemented, leave holder for future to keep in sync with python implementation
func (e *Encryption) buildCredSSPMessage(message []byte, host string) ([]byte, error) {
	// //TODO
	// context := e.session.Auth.Contexts[host]
	// sealedMessage := context.Wrap(message)

	// cipherNegotiated := context.TLSConnection.ConnectionState().CipherSuite.Name
	// trailerLength := e.getCredSSPTrailerLength(len(message), cipherNegotiated)

	// trailer := make([]byte, 4)
	// binary.LittleEndian.PutUint32(trailer, uint32(trailerLength))

	// return append(trailer, sealedMessage...), nil
}
func (e *Encryption) getCredSSPTrailerLength(messageLength int, cipherSuite string) int {
	var trailerLength int

	if match, _ := regexp.MatchString("^.*-GCM-[\\w\\d]*$", cipherSuite); match {
		trailerLength = 16
	} else {
		hashAlgorithm := cipherSuite[strings.LastIndex(cipherSuite, "-")+1:]
		var hashLength int

		if hashAlgorithm == "MD5" {
			hashLength = 16
		} else if hashAlgorithm == "SHA" {
			hashLength = 20
		} else if hashAlgorithm == "SHA256" {
			hashLength = 32
		} else if hashAlgorithm == "SHA384" {
			hashLength = 48
		} else {
			hashLength = 0
		}

		prePadLength := messageLength + hashLength
		paddingLength := 0

		if strings.Contains(cipherSuite, "RC4") {
			paddingLength = 0
		} else if strings.Contains(cipherSuite, "DES") || strings.Contains(cipherSuite, "3DES") {
			paddingLength = 8 - (prePadLength % 8)

		} else {
			// AES is a 128 bit block cipher
			paddingLength = 16 - (prePadLength % 16)
		}

		trailerLength = (prePadLength + paddingLength) - messageLength
	}
	return trailerLength
}
*/
