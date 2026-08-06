package winrm

import (
	"bytes"
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
	"github.com/jcmturner/gokrb5/v8/spnego"
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
		return httpClient.Do(req)
	default:
		return nil, fmt.Errorf("Encryption for protocol '%s' not supported", e.protocol)
	}
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
			message_chunks = append(message_chunks, message[i:i+sixTenKB])
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
	body, _ := io.ReadAll(response.Body)
	parts := deleteEmpty(bytes.Split(body, []byte(mimeBoundary+"\r\n")))
	var message []byte

	for i := 0; i < len(parts); i += 2 {
		header := parts[i]
		payload := parts[i+1]

		expectedLengthStr := bytes.SplitAfter(header, []byte("Length="))[1]
		expectedLength, err := strconv.Atoi(string(bytes.TrimSpace(expectedLengthStr)))
		if err != nil {
			return nil, err
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
	signatureLength := int(binary.LittleEndian.Uint32(encryptedData[:4]))
	signature := encryptedData[4 : signatureLength+4]
	encryptedMessage := encryptedData[signatureLength+4:]

	message, err := e.ntlmClient.SecuritySession().Unwrap(encryptedMessage, signature)
	if err != nil {
		return nil, err
	}
	return message, nil
}

func (enc *Encryption) decryptKerberosMessage(encryptedData []byte, host string) ([]byte, error) {
	err := errors.New("kerberos wrap/unwrap is not implemented yet (phase 4)")
	if enc.failurePolicy.RejectTokenDecryptFailure {
		return nil, err
	}
	return nil, err
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

	if len(context.serviceSessionKey.KeyValue) == 0 {
		return nil, errors.New("kerberos service session key is not initialized")
	}

	etype, err := krbcrypto.GetEtype(context.serviceSessionKey.KeyType)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve kerberos etype: %w", err)
	}

	_, sealedMessage, err := etype.EncryptMessage(context.serviceSessionKey.KeyValue, message, keyusage.GSSAPI_INITIATOR_SEAL)
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

	if err := wrapToken.SetCheckSum(context.serviceSessionKey, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
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
