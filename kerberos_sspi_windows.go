//go:build windows

package winrm

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"

	"github.com/alexbrainman/sspi"
	sspikerberos "github.com/alexbrainman/sspi/kerberos"
)

type windowsKerberosSSPIAuthenticator struct {
	credentials *sspi.Credentials
	context     *sspikerberos.ClientContext
}

type windowsKerberosSSPIProtector struct {
	context         *sspikerberos.ClientContext
	securityTrailer uint32
	sendSequence    uint32
	receiveSequence uint32
}

func newKerberosSSPIAuthenticator() (kerberosSSPIAuthenticator, error) {
	credentials, err := sspikerberos.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, fmt.Errorf("acquire current-user SSPI Kerberos credentials: %w", err)
	}
	return &windowsKerberosSSPIAuthenticator{credentials: credentials}, nil
}

func (authenticator *windowsKerberosSSPIAuthenticator) establish(ctx context.Context, client *http.Client, endpoint, spn string) (kerberosMessageProtector, net.Conn, error) {
	if err := authenticator.reset(); err != nil {
		return nil, nil, err
	}
	flags := uint32(sspi.ISC_REQ_CONNECTION | sspi.ISC_REQ_MUTUAL_AUTH | sspi.ISC_REQ_REPLAY_DETECT |
		sspi.ISC_REQ_SEQUENCE_DETECT | sspi.ISC_REQ_CONFIDENTIALITY | sspi.ISC_REQ_INTEGRITY)
	securityContext, complete, token, err := sspikerberos.NewClientContextWithFlags(authenticator.credentials, spn, flags)
	if err != nil {
		return nil, nil, fmt.Errorf("start SSPI Kerberos context: %w", err)
	}
	authenticator.context = securityContext
	var connection net.Conn
	for exchange := 0; exchange < kerberosMaxBootstrapExchanges; exchange++ {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
		if err != nil {
			return nil, nil, err
		}
		request.Header.Set("Content-Type", soapXML+";charset=UTF-8")
		request.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(token))
		tracker := &kerberosConnectionTracker{expected: connection}
		request = request.WithContext(httptrace.WithClientTrace(request.Context(), tracker.trace()))
		response, err := client.Do(request)
		debugHTTPRoundTrip(request, response, err)
		if err != nil {
			return nil, nil, err
		}
		body, bodyErr := readBoundedBody(response.Body, kerberosMaxBootstrapBody)
		debugHTTPResponseBody(body, bodyErr)
		if bodyErr != nil {
			return nil, nil, bodyErr
		}
		currentConnection, changed := tracker.result()
		if currentConnection == nil || changed {
			return nil, nil, errors.New("SSPI Kerberos authentication changed HTTP connections")
		}
		connection = currentConnection
		challenge, challengeErr := kerberosSSPIChallenge(response.Header.Values("WWW-Authenticate"))
		if challengeErr != nil {
			return nil, nil, challengeErr
		}
		if len(challenge) > 0 {
			complete, token, err = securityContext.Update(challenge)
			if err != nil {
				return nil, nil, fmt.Errorf("continue SSPI Kerberos context: %w", err)
			}
		}
		if response.StatusCode == http.StatusOK {
			if !complete {
				return nil, nil, errors.New("HTTP 200 response did not complete SSPI mutual authentication")
			}
			if err := securityContext.VerifyFlags(); err != nil {
				return nil, nil, fmt.Errorf("verify SSPI Kerberos context flags: %w", err)
			}
			_, _, _, securityTrailer, err := securityContext.Sizes()
			if err != nil {
				return nil, nil, fmt.Errorf("query SSPI Kerberos context sizes: %w", err)
			}
			if securityTrailer == 0 || securityTrailer > kerberosMaxWrapOverhead {
				return nil, nil, fmt.Errorf("SSPI Kerberos security trailer length %d is invalid", securityTrailer)
			}
			return &windowsKerberosSSPIProtector{context: securityContext, securityTrailer: securityTrailer}, connection, nil
		}
		if response.StatusCode != http.StatusUnauthorized {
			return nil, nil, fmt.Errorf("SSPI Kerberos bootstrap returned HTTP status %d", response.StatusCode)
		}
		if len(challenge) == 0 || len(token) == 0 {
			return nil, nil, errors.New("SSPI Kerberos challenge exchange did not provide a token")
		}
	}
	return nil, nil, errors.New("SSPI Kerberos bootstrap exceeded five HTTP exchanges")
}

func kerberosSSPIChallenge(values []string) ([]byte, error) {
	for _, value := range values {
		for _, challenge := range strings.Split(value, ",") {
			fields := strings.Fields(strings.TrimSpace(challenge))
			if len(fields) == 0 || !strings.EqualFold(fields[0], "Negotiate") {
				continue
			}
			if len(fields) == 1 {
				return nil, nil
			}
			if len(fields) != 2 {
				return nil, errors.New("invalid SSPI Negotiate challenge")
			}
			token, err := base64.StdEncoding.DecodeString(fields[1])
			if err != nil {
				return nil, fmt.Errorf("decode SSPI Negotiate challenge: %w", err)
			}
			return token, nil
		}
	}
	return nil, nil
}

func (protector *windowsKerberosSSPIProtector) wrap(message []byte) ([]byte, []byte, error) {
	encrypted, err := protector.context.EncryptMessage(append([]byte(nil), message...), 0, protector.sendSequence)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt SSPI Kerberos message: %w", err)
	}
	if uint32(len(encrypted)) < protector.securityTrailer {
		return nil, nil, errors.New("encrypted SSPI Kerberos message is shorter than its security trailer")
	}
	protector.sendSequence++
	return encrypted[:protector.securityTrailer], encrypted[protector.securityTrailer:], nil
}

func (protector *windowsKerberosSSPIProtector) unwrap(header, payload []byte) ([]byte, error) {
	if uint32(len(header)) != protector.securityTrailer {
		return nil, fmt.Errorf("SSPI Kerberos security header length %d, want %d", len(header), protector.securityTrailer)
	}
	stream := append(append(make([]byte, 0, len(header)+len(payload)), header...), payload...)
	qop, message, err := protector.context.DecryptMessage(stream, protector.receiveSequence)
	if err != nil {
		return nil, fmt.Errorf("decrypt SSPI Kerberos message: %w", err)
	}
	if qop != 0 {
		return nil, fmt.Errorf("SSPI Kerberos message used unsupported QOP %d", qop)
	}
	protector.receiveSequence++
	return message, nil
}

func (authenticator *windowsKerberosSSPIAuthenticator) reset() error {
	if authenticator.context == nil {
		return nil
	}
	err := authenticator.context.Release()
	authenticator.context = nil
	return err
}

func (authenticator *windowsKerberosSSPIAuthenticator) close() error {
	contextErr := authenticator.reset()
	var credentialErr error
	if authenticator.credentials != nil {
		credentialErr = authenticator.credentials.Release()
		authenticator.credentials = nil
	}
	return errors.Join(contextErr, credentialErr)
}
