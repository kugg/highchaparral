package asterisk

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type peerMaterial struct {
	certificate tls.Certificate
	parsed      *x509.Certificate
	key         *ecdsa.PrivateKey
}

func makePeer(t *testing.T, loopback, expired bool, issuer *peerMaterial) peerMaterial {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "synthetic ARI peer"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	if loopback {
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		template.DNSNames = []string{"wrong.invalid"}
	}
	if expired {
		template.NotAfter = time.Now().Add(-time.Minute)
	}
	parent, signer := template, key
	if issuer != nil {
		parent, signer = issuer.parsed, issuer.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return peerMaterial{tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, parsed, key}
}

func peerServer(t *testing.T, material peerMaterial, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{material.certificate}, MinVersion: tls.VersionTLS12}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

func peerClient(t *testing.T, server *httptest.Server, cert *x509.Certificate, target Target) *Client {
	t.Helper()
	client, err := New(Config{BaseURL: server.URL, PeerCertificate: cert, Username: "lab", Password: "only-for-tests", Timeout: time.Second, Target: target})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return client
}

func TestAuthenticatedARIRejectsPlaintextAndMissingIdentityBeforeCredentials(t *testing.T) {
	var requests atomic.Int32
	impostor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer impostor.Close()
	if _, err := New(Config{BaseURL: impostor.URL, Username: "lab", Password: "only-for-tests", Timeout: time.Second}); err == nil {
		t.Fatal("plaintext peer admitted")
	}
	if _, err := New(Config{BaseURL: strings.Replace(impostor.URL, "http:", "https:", 1), Username: "lab", Password: "only-for-tests", Timeout: time.Second}); err == nil {
		t.Fatal("missing identity admitted")
	}
	if requests.Load() != 0 {
		t.Fatal("credential request reached plaintext impostor")
	}
}

func TestAuthenticatedARIRejectsImpostorsOnHTTPAndWebSocket(t *testing.T) {
	trusted := makePeer(t, true, false, nil)
	for _, scenario := range []string{"untrusted", "wrong-host", "expired", "different-leaf-same-CA"} {
		t.Run(scenario, func(t *testing.T) {
			var observed atomic.Int32
			presented, pin := makePeer(t, true, false, nil), trusted.parsed
			switch scenario {
			case "wrong-host":
				presented = makePeer(t, false, false, nil)
				// Use a valid configured identity; bad presented identity cannot receive credentials.
			case "expired":
				presented = makePeer(t, true, true, nil)
				pin = presented.parsed
			case "different-leaf-same-CA":
				presented = makePeer(t, true, false, &trusted)
			}
			server := peerServer(t, presented, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" {
					observed.Add(1)
				}
				w.WriteHeader(http.StatusUnauthorized)
			}))
			client := peerClient(t, server, pin, BrowserIngress)
			if _, _, err := client.request(context.Background(), http.MethodGet, "/channels/synthetic", nil); err == nil {
				t.Fatal("impostor HTTP accepted")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if _, _, err := client.SubscribeBrowser(ctx); err == nil {
				t.Fatal("impostor WebSocket accepted")
			}
			if observed.Load() != 0 {
				t.Fatal("credential reached unauthenticated peer")
			}
		})
	}
	wrong := makePeer(t, false, false, nil)
	if _, err := New(Config{BaseURL: "https://127.0.0.1:8089", PeerCertificate: wrong.parsed, Username: "lab", Password: "only-for-tests", Timeout: time.Second}); err == nil {
		t.Fatal("wrong configured peer identity admitted")
	}
}

func TestAuthenticatedARIPreservesOwnedLifecycleAndBrowserSubscription(t *testing.T) {
	material := makePeer(t, true, false, nil)
	t.Run("owned lifecycle", func(t *testing.T) {
		m := startARI(t, 20000)
		m.server.Close()
		m.server = peerServer(t, material, http.HandlerFunc(m.handle))
		client := peerClient(t, m.server, material.parsed, LabEcho)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		session, err := client.Start(ctx, localID, ownedRTP(t))
		if err != nil {
			t.Fatal(err)
		}
		if err := session.Close(); err != nil {
			t.Fatal(err)
		}
		if err := session.Close(); err != nil {
			t.Fatal("cleanup not idempotent")
		}
		steps := m.snapshot()
		if len(steps) != 14 || !strings.HasPrefix(steps[len(steps)-1], "DELETE /ari/bridges/") {
			t.Fatal("owned lifecycle incomplete")
		}
	})
	t.Run("browser WSS", func(t *testing.T) {
		m := startARI(t, 20000)
		m.server.Close()
		m.wantApp = browserApp
		m.browserEvent = []byte(validBrowserEvent)
		m.server = peerServer(t, material, http.HandlerFunc(m.handle))
		client := peerClient(t, m.server, material.parsed, BrowserIngress)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		events, gone, err := client.SubscribeBrowser(ctx)
		if err != nil {
			t.Fatal(err)
		}
		select {
		case start := <-events:
			if start.ChannelID != "1693496751.43" {
				t.Fatal("wrong browser event")
			}
		case <-ctx.Done():
			t.Fatal("valid WSS event not delivered")
		}
		cancel()
		select {
		case <-gone:
		case <-time.After(time.Second):
			t.Fatal("WSS did not close")
		}
	})
}

func TestAuthenticatedARIPinRotationRequiresReprovisioning(t *testing.T) {
	first := makePeer(t, true, false, nil)
	second := makePeer(t, true, false, nil)
	var active atomic.Pointer[tls.Certificate]
	active.Store(&first.certificate)
	var observed atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); ok && u == "lab" && p == "only-for-tests" {
			observed.Add(1)
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*active.Load()}}, nil
	}}
	server.StartTLS()
	defer server.Close()
	client := peerClient(t, server, first.parsed, BrowserIngress)
	if _, _, err := client.request(context.Background(), http.MethodGet, "/channels/synthetic", nil); err != nil {
		t.Fatal(err)
	}
	if observed.Load() != 1 {
		t.Fatal("valid initial peer did not receive credentials")
	}
	server.CloseClientConnections()
	active.Store(&second.certificate)
	if _, _, err := client.request(context.Background(), http.MethodGet, "/channels/synthetic", nil); err == nil {
		t.Fatal("rotated unknown peer accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, _, err := client.SubscribeBrowser(ctx); err == nil {
		t.Fatal("rotated WSS peer accepted")
	}
	if observed.Load() != 1 {
		t.Fatal("outage replacement received credentials")
	}
	reprovisioned := peerClient(t, server, second.parsed, BrowserIngress)
	if _, _, err := reprovisioned.request(context.Background(), http.MethodGet, "/channels/synthetic", nil); err != nil {
		t.Fatal("provisioned new pin did not work")
	}
	if observed.Load() != 2 {
		t.Fatal("new peer not reached after reprovisioning")
	}
}
