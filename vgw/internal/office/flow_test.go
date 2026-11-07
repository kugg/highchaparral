package office

// Provider-free capability probe: can sipgo dispatch an INVITE received on
// the SAME client-initiated TLS connection used for a REGISTER, without a
// separate public office listener? This does not prove Eventphone does so.

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"example.com/ata/voip-gateway/internal/safesip"
	"github.com/emiago/diago"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

func fixtureLeaf(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("synthetic TLS key unavailable")
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	raw, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal("synthetic TLS leaf unavailable")
	}
	parsed, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal("synthetic TLS leaf invalid")
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{raw}, PrivateKey: key}, roots
}

func readSyntheticREGISTER(reader *bufio.Reader) (map[string]string, error) {
	result := make(map[string]string)
	for lineNo := 0; lineNo < 40; lineNo++ {
		line, err := reader.ReadString('\n')
		if err != nil || len(line) > 1024 {
			return nil, fmt.Errorf("synthetic REGISTER unavailable")
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if lineNo == 0 {
			if !strings.HasPrefix(line, "REGISTER ") {
				return nil, fmt.Errorf("unexpected synthetic SIP method")
			}
			continue
		}
		if line == "" {
			for _, required := range []string{"via", "to", "from", "call-id", "cseq"} {
				if result[required] == "" {
					return nil, fmt.Errorf("required synthetic SIP response header missing")
				}
			}
			return result, nil
		}
		key, value, found := strings.Cut(line, ":")
		if found {
			lower := strings.ToLower(strings.TrimSpace(key))
			if len(value) > 512 || strings.ContainsAny(value, "\r\n\x00") {
				return nil, fmt.Errorf("untrusted synthetic SIP header rejected")
			}
			result[lower] = strings.TrimSpace(value)
		}
	}
	return nil, fmt.Errorf("synthetic SIP header bound exceeded")
}

func TestClientInitiatedTLSCanReceiveINVITEOnTheSameFlow(t *testing.T) {
	leaf, roots := fixtureLeaf(t)
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{leaf}})
	if err != nil {
		t.Fatal("provider-free TLS listener unavailable")
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	policy, ok := newAdmission("1234", "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, true)
	if !ok {
		t.Fatal("synthetic office policy unavailable")
	}
	providerResult := make(chan bool, 1)
	providerDone := make(chan struct{})
	registeredReady := make(chan struct{})
	defer close(providerDone)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			providerResult <- false
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		header, err := readSyntheticREGISTER(bufio.NewReader(conn))
		if err != nil {
			providerResult <- false
			return
		}
		_, err = fmt.Fprintf(conn, "SIP/2.0 200 OK\r\nVia: %s\r\nFrom: %s\r\nTo: %s;tag=synthetic\r\nCall-ID: %s\r\nCSeq: %s\r\nContent-Length: 0\r\n\r\n",
			header["via"], header["from"], header["to"], header["call-id"], header["cseq"])
		if err != nil {
			providerResult <- false
			return
		}
		select {
		case <-registeredReady:
		case <-ctx.Done():
			providerResult <- false
			return
		}
		// NO second connection: deliver a new inbound INVITE on this exact
		// already-verified TLS transport after REGISTER succeeds.
		sdpBody := strings.ReplaceAll(syntheticSDP, "203.0.113.8", "127.0.0.1")
		wire := fmt.Sprintf("INVITE sip:1234@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/TLS localhost:%d;branch=z9hG4bKoffice-synthetic;rport\r\nFrom: <sip:provider@localhost>;tag=synthetic\r\nTo: <sip:1234@localhost>\r\nCall-ID: office-synthetic@localhost\r\nCSeq: 1 INVITE\r\nMax-Forwards: 70\r\nContact: <sips:provider@localhost;transport=tls>\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", port, len(sdpBody), sdpBody)
		parsed, parseErr := sip.NewParser().ParseSIP([]byte(wire))
		request, ok := parsed.(*sip.Request)
		if parseErr != nil || !ok || request.Recipient.User != "1234" ||
			!strings.EqualFold(request.Transport(), "tls") {
			providerResult <- false
			return
		}
		_, err = conn.Write([]byte(wire))
		providerResult <- err == nil
		select {
		case <-providerDone: // keep the existing TLS flow open until handler observes INVITE
		case <-ctx.Done():
		}
	}()
	ua, err := sipgo.NewUA(sipgo.WithUserAgenTLSConfig(&tls.Config{
		MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "localhost"}),
		sipgo.WithUserAgentTransportLayerOptions(sip.WithTransportLayerLogger(safesip.Logger)),
		sipgo.WithUserAgentTransactionLayerOptions(sip.WithTransactionLayerLogger(safesip.Logger)))
	if err != nil {
		t.Fatal("synthetic SIP UA unavailable")
	}
	defer ua.Close()
	server, err := sipgo.NewServer(ua, sipgo.WithServerLogger(safesip.Logger))
	if err != nil {
		t.Fatal("synthetic SIP transaction handler unavailable")
	}
	seen := make(chan bool, 1)
	dg := diago.NewDiago(ua, diago.WithTransport(diago.Transport{
		Transport: "tls", BindHost: "127.0.0.1", BindPort: 0}),
		diago.WithServer(server), diago.WithLogger(safesip.Logger),
		diago.WithServerRequestMiddleware(func(next sipgo.RequestHandler) sipgo.RequestHandler {
			return func(req *sip.Request, tx sip.ServerTransaction) {
				seen <- policy.Admit(req) == Admit
				_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusBusyHere, "Busy Here", nil))
			}
		}))
	uri := sip.Uri{Scheme: "sips", User: "synthetic", Host: "localhost", Port: port}
	uri.UriParams = sip.NewParams()
	uri.UriParams.Add("transport", "tls")
	registration, err := dg.RegisterTransaction(ctx, uri, diago.RegisterOptions{
		Username: "synthetic", Password: "unit-only", Expiry: 90 * time.Second})
	if err != nil || registration.Register(ctx) != nil {
		t.Fatal("synthetic TLS REGISTER did not complete")
	}
	policy.Registered() // Only the successful response permits inbound admission.
	close(registeredReady)
	select {
	case valid := <-seen:
		if !valid {
			t.Fatal("synthetic provider INVITE reached wrong destination or transport")
		}
	case <-ctx.Done():
		select {
		case wrote := <-providerResult:
			if !wrote {
				t.Fatal("synthetic provider could not write on registered TLS connection")
			}
		default:
		}
		t.Fatal("no inbound INVITE dispatched on client-initiated TLS flow")
	}
	select {
	case delivered := <-providerResult:
		if !delivered {
			t.Fatal("synthetic provider failed sending over existing TLS flow")
		}
	case <-ctx.Done():
		t.Fatal("synthetic provider delivery deadline exceeded")
	}
}
