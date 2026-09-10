package winrm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/client"
	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/service"
	"github.com/otuschhoff/gokrb5/v8/spnego"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestKerberosGSSAdapterBidirectional(t *testing.T) {
	tests := []struct {
		name         string
		keyType      int32
		key          []byte
		headerLength int
		rrc          uint16
	}{
		{name: "AES128 SHA1", keyType: 17, key: []byte("0123456789abcdef"), headerLength: 60, rrc: 28},
		{name: "AES256 SHA1", keyType: 18, key: []byte("0123456789abcdef0123456789abcdef"), headerLength: 60, rrc: 28},
		{name: "AES128 SHA256", keyType: 19, key: []byte("0123456789abcdef"), headerLength: 64, rrc: 32},
		{name: "AES256 SHA384", keyType: 20, key: []byte("0123456789abcdef0123456789abcdef"), headerLength: 72, rrc: 40},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			initiator, acceptor := newTestKerberosGSSPair(t, test.keyType, test.key, true)
			for sequence, message := range [][]byte{nil, []byte("small"), []byte("reply"), bytes.Repeat([]byte("large payload "), 4096)} {
				sender, receiver := initiator, acceptor
				if sequence%2 == 1 {
					sender, receiver = acceptor, initiator
				}
				header, payload, err := sender.wrap(message)
				if err != nil {
					t.Fatal(err)
				}
				if len(header) != test.headerLength || len(payload) != len(message) {
					t.Fatalf("wrapped lengths = (%d, %d)", len(header), len(payload))
				}
				if rrc := binary.BigEndian.Uint16(header[6:8]); rrc != test.rrc {
					t.Fatalf("wrapped RRC = %d, want %d", rrc, test.rrc)
				}
				plaintext, err := receiver.unwrap(header, payload)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(plaintext, message) {
					t.Fatalf("plaintext length %d does not match message length %d", len(plaintext), len(message))
				}
			}
		})
	}
}

func TestKerberosGSSAdapterRejectsTamperAndReplay(t *testing.T) {
	initiator, acceptor := newTestKerberosGSSPair(t, 18, []byte("0123456789abcdef0123456789abcdef"), true)
	header, payload, err := initiator.wrap([]byte("protected"))
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), payload...)
	tampered[len(tampered)-1] ^= 1
	if _, err := acceptor.unwrap(header, tampered); err == nil {
		t.Fatal("tampered token was accepted")
	}
	if _, err := acceptor.unwrap(header, payload); err != nil {
		t.Fatalf("valid token after tamper rejection: %v", err)
	}
	if _, err := acceptor.unwrap(header, payload); err == nil || !strings.Contains(err.Error(), "sequence") {
		t.Fatalf("replay error = %v", err)
	}
}

func TestKerberosGSSAdapterRejectsInvalidHeaders(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{name: "token ID", mutate: func(header []byte) []byte { header[0] ^= 1; return header }},
		{name: "filler", mutate: func(header []byte) []byte { header[3] = 0; return header }},
		{name: "unsealed", mutate: func(header []byte) []byte { header[2] &^= gssapi.MICTokenFlagSealed; return header }},
		{name: "short", mutate: func(header []byte) []byte { return header[:len(header)-1] }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			initiator, acceptor := newTestKerberosGSSPair(t, 18, []byte("0123456789abcdef0123456789abcdef"), true)
			header, payload, err := initiator.wrap([]byte("protected"))
			if err != nil {
				t.Fatal(err)
			}
			header = test.mutate(header)
			if _, err := acceptor.unwrap(header, payload); err == nil {
				t.Fatal("invalid header was accepted")
			}
		})
	}
}

func FuzzKerberosGSSAdapterUnwrap(f *testing.F) {
	f.Add(fixtureKerberosGSSHeader(), []byte("payload"))
	f.Add([]byte{0x05, 0x04}, []byte{})
	f.Fuzz(func(t *testing.T, header, payload []byte) {
		if len(header)+len(payload) > 1<<20 {
			t.Skip()
		}
		context := &fixtureKerberosGSSContext{
			header: fixtureKerberosGSSHeader(), payload: fixtureKerberosGSSBody([]byte("payload")), message: []byte("message"),
		}
		adapter, err := newKerberosGSSAdapter(context)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = adapter.unwrap(header, payload)
	})
}

func TestKerberosGSSAdapterEnctypesSequencesAndSubkeys(t *testing.T) {
	tests := []struct {
		name    string
		keyType int32
		key     []byte
	}{
		{name: "AES128 SHA1", keyType: 17, key: []byte("0123456789abcdef")},
		{name: "AES256 SHA1", keyType: 18, key: []byte("0123456789abcdef0123456789abcdef")},
		{name: "AES128 SHA256", keyType: 19, key: []byte("0123456789abcdef")},
		{name: "AES256 SHA384", keyType: 20, key: []byte("0123456789abcdef0123456789abcdef")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key := types.EncryptionKey{KeyType: test.keyType, KeyValue: test.key}
			initiatorContext, err := gssapi.NewSecurityContext(key, true, 7, 11, true)
			if err != nil {
				t.Fatal(err)
			}
			acceptorContext, err := gssapi.NewSecurityContext(key, false, 11, 7, true)
			if err != nil {
				t.Fatal(err)
			}
			initiator, _ := newKerberosGSSAdapter(initiatorContext)
			acceptor, _ := newKerberosGSSAdapter(acceptorContext)
			header, payload, err := initiator.wrap([]byte("request"))
			if err != nil {
				t.Fatal(err)
			}
			if header[2]&gssapi.MICTokenFlagAcceptorSubkey == 0 {
				t.Fatal("acceptor-subkey flag is missing")
			}
			if _, err := acceptor.unwrap(header, payload); err != nil {
				t.Fatal(err)
			}
			header, payload, err = acceptor.wrap([]byte("response"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := initiator.unwrap(header, payload); err != nil {
				t.Fatal(err)
			}
		})
	}

	rc4 := types.EncryptionKey{KeyType: 23, KeyValue: []byte("0123456789abcdef")}
	if _, err := gssapi.NewSecurityContext(rc4, true, 0, 0, false); err == nil {
		t.Fatal("RC4 security context was accepted")
	}

	key := types.EncryptionKey{KeyType: 18, KeyValue: []byte("0123456789abcdef0123456789abcdef")}
	withSubkey, _ := gssapi.NewSecurityContext(key, true, 0, 0, true)
	withoutSubkey, _ := gssapi.NewSecurityContext(key, false, 0, 0, false)
	token, err := withSubkey.Wrap([]byte("mismatch"), true)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := withoutSubkey.Unwrap(token); err == nil || !strings.Contains(err.Error(), "flags") {
		t.Fatalf("subkey mismatch error = %v", err)
	}
}

func TestKerberosSPNEGOMutualAuthentication(t *testing.T) {
	initiator, acceptor, initial := newSyntheticKerberosSPNEGOExchange(t)
	if initiator.SecurityContext() != nil || acceptor.SecurityContext() != nil {
		t.Fatal("security context available before mutual authentication")
	}
	authenticated, _, status := acceptor.AcceptSecContext(initial)
	if !authenticated || status.Code != gssapi.StatusComplete {
		t.Fatalf("acceptor status = %v", status)
	}
	if acceptor.SecurityContext() == nil || initiator.SecurityContext() != nil {
		t.Fatal("unexpected security context state before AP-REP verification")
	}
	response := acceptor.ResponseToken()
	if response == nil {
		t.Fatal("acceptor omitted mutual-authentication response")
	}
	authenticated, _, status = initiator.ContinueSecContext(response)
	if !authenticated || status.Code != gssapi.StatusComplete {
		t.Fatalf("initiator status = %v", status)
	}
	initiatorAdapter, err := newKerberosGSSAdapter(initiator.SecurityContext())
	if err != nil {
		t.Fatal(err)
	}
	acceptorAdapter, err := newKerberosGSSAdapter(acceptor.SecurityContext())
	if err != nil {
		t.Fatal(err)
	}
	header, payload, err := initiatorAdapter.wrap([]byte("request"))
	if err != nil {
		t.Fatal(err)
	}
	message, err := acceptorAdapter.unwrap(header, payload)
	if err != nil || string(message) != "request" {
		t.Fatalf("acceptor unwrap = %q, %v", message, err)
	}
	header, payload, err = acceptorAdapter.wrap([]byte("response"))
	if err != nil {
		t.Fatal(err)
	}
	message, err = initiatorAdapter.unwrap(header, payload)
	if err != nil || string(message) != "response" {
		t.Fatalf("initiator unwrap = %q, %v", message, err)
	}
}

func TestKerberosSPNEGOMutualAuthenticationRequiresAPREP(t *testing.T) {
	initiator, acceptor, initial := newSyntheticKerberosSPNEGOExchange(t)
	authenticated, _, status := acceptor.AcceptSecContext(initial)
	if !authenticated || status.Code != gssapi.StatusComplete {
		t.Fatalf("acceptor status = %v", status)
	}
	response := acceptor.ResponseToken().(*spnego.SPNEGOToken)
	response.NegTokenResp.ResponseToken = nil
	authenticated, _, status = initiator.ContinueSecContext(response)
	if authenticated || status.Code != gssapi.StatusDefectiveToken || !strings.Contains(status.Message, "required AP_REP") {
		t.Fatalf("missing AP-REP status = %v", status)
	}
}

func newSyntheticKerberosSPNEGOExchange(t *testing.T) (*spnego.SPNEGO, *spnego.SPNEGO, gssapi.ContextToken) {
	t.Helper()
	keytabBytes, err := hex.DecodeString(testdata.HTTP_KEYTAB)
	if err != nil {
		t.Fatal(err)
	}
	serviceKeytab := keytab.New()
	if err := serviceKeytab.Unmarshal(keytabBytes); err != nil {
		t.Fatal(err)
	}
	const realm = "TEST.GOKRB5"
	const servicePrincipal = "HTTP/host.test.gokrb5"
	clientPrincipal := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "phase1-user")
	servicePrincipalName := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, servicePrincipal)
	now := time.Now().UTC()
	flags := types.NewKrbFlags()
	ticket, sessionKey, err := messages.NewTicket(
		clientPrincipal, realm, servicePrincipalName, realm, flags, serviceKeytab,
		18, 1, now, now, now.Add(time.Hour), now.Add(2*time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	ticketBytes, err := ticket.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	cache := credentials.NewCCache(clientPrincipal, realm)
	cache.AddCredential(&credentials.Credential{
		Client: credentials.Principal{Realm: realm, PrincipalName: clientPrincipal},
		Server: credentials.Principal{Realm: realm, PrincipalName: servicePrincipalName},
		Key:    sessionKey, AuthTime: now, StartTime: now, EndTime: now.Add(time.Hour), RenewTill: now.Add(2 * time.Hour),
		TicketFlags: flags, Ticket: ticketBytes,
	})
	kerberosClient, err := client.NewFromCCache(cache, config.New())
	if err != nil {
		t.Fatal(err)
	}
	options := spnego.KRB5TokenAPREQOptions{GSSAPIFlags: []int{
		gssapi.ContextFlagMutual, gssapi.ContextFlagSequence, gssapi.ContextFlagInteg, gssapi.ContextFlagConf,
	}}
	initiator := spnego.SPNEGOClientWithOptions(kerberosClient, servicePrincipal, options)
	initial, err := initiator.InitSecContext()
	if err != nil {
		t.Fatal(err)
	}
	acceptor := spnego.SPNEGOService(serviceKeytab, service.DecodePAC(false))
	return initiator, acceptor, initial
}

func newTestKerberosGSSPair(t testing.TB, keyType int32, key []byte, acceptorSubkey bool) (*kerberosGSSAdapter, *kerberosGSSAdapter) {
	t.Helper()
	encryptionKey := types.EncryptionKey{KeyType: keyType, KeyValue: key}
	initiatorContext, err := gssapi.NewSecurityContext(encryptionKey, true, 0, 0, acceptorSubkey)
	if err != nil {
		t.Fatal(err)
	}
	acceptorContext, err := gssapi.NewSecurityContext(encryptionKey, false, 0, 0, acceptorSubkey)
	if err != nil {
		t.Fatal(err)
	}
	initiator, err := newKerberosGSSAdapter(initiatorContext)
	if err != nil {
		t.Fatal(err)
	}
	acceptor, err := newKerberosGSSAdapter(acceptorContext)
	if err != nil {
		t.Fatal(err)
	}
	return initiator, acceptor
}

func BenchmarkKerberosGSSWrapUnwrap64KiB(b *testing.B) {
	initiator, acceptor := newTestKerberosGSSPair(b, 18, []byte("0123456789abcdef0123456789abcdef"), true)
	payload := bytes.Repeat([]byte("x"), 64<<10)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		header, sealed, err := initiator.wrap(payload)
		if err != nil {
			b.Fatal(err)
		}
		opened, err := acceptor.unwrap(header, sealed)
		if err != nil {
			b.Fatal(err)
		}
		if len(opened) != len(payload) {
			b.Fatalf("opened bytes = %d, want %d", len(opened), len(payload))
		}
	}
}
