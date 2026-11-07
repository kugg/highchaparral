package registration

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"example.com/ata/voip-gateway/internal/serviceconfig"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/icholy/digest"
)

func TestMain(m *testing.M) {
	// Set before ANY test UA/goroutine; sipgo's global debug flag is not
	// synchronized and cannot be toggled during active connections.
	sip.SIPDebug = true
	os.Exit(m.Run())
}

type mockRegistrar struct {
	port          int
	roots         *x509.CertPool
	certSHA       [sha256.Size]byte
	challenge     chan struct{}
	authorized    chan struct{}
	refresh       chan struct{}
	failures      chan time.Time
	dropped       chan struct{}
	unregistered  chan struct{}
	fail          atomic.Bool
	dropNext      atomic.Bool
	registrations atomic.Int32
}

func startMock(t *testing.T) *mockRegistrar {
	return startMockWithTLS(t, time.Now().Add(time.Hour), 0)
}

func startMockWithTLS(t *testing.T, notAfter time.Time, maxTLS uint16) *mockRegistrar {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
		IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	ua, err := sipgo.NewUA(sipgo.WithUserAgentTransportLayerOptions(
		sip.WithTransportLayerLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))))
	if err != nil {
		t.Fatal(err)
	}
	server, err := sipgo.NewServer(ua)
	if err != nil {
		t.Fatal(err)
	}
	m := &mockRegistrar{port: port, roots: roots, certSHA: sha256.Sum256(der), challenge: make(chan struct{}, 8),
		authorized: make(chan struct{}, 8), refresh: make(chan struct{}, 8),
		failures: make(chan time.Time, 8), dropped: make(chan struct{}, 1),
		unregistered: make(chan struct{}, 8)}
	challenge := digest.Challenge{Realm: "local-test", Nonce: "fixed-test-nonce", Algorithm: "MD5"}
	server.OnRegister(func(req *sip.Request, tx sip.ServerTransaction) {
		if m.dropNext.CompareAndSwap(true, false) {
			_ = tx.(*sip.ServerTx).Connection().Close()
			m.dropped <- struct{}{}
			return
		}
		if m.fail.Load() {
			m.failures <- time.Now()
			_ = tx.Respond(sip.NewResponseFromRequest(req, 503, "Unavailable", nil))
			return
		}
		h := req.GetHeader("Authorization")
		if h == nil {
			m.challenge <- struct{}{}
			res := sip.NewResponseFromRequest(req, 401, "Unauthorized", nil)
			res.AppendHeader(sip.NewHeader("WWW-Authenticate", challenge.String()))
			_ = tx.Respond(res)
			return
		}
		creds, err := digest.ParseCredentials(h.Value())
		if err != nil {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 403, "Forbidden", nil))
			return
		}
		expected, err := digest.Digest(&challenge, digest.Options{
			Method: "REGISTER", URI: creds.URI, Username: "synthetic", Password: "only-for-tests-long",
		})
		if err != nil || creds.Username != "synthetic" || subtle.ConstantTimeCompare([]byte(creds.Response), []byte(expected.Response)) != 1 {
			_ = tx.Respond(sip.NewResponseFromRequest(req, 403, "Forbidden", nil))
			return
		}
		if ex := req.GetHeader("Expires"); ex != nil && ex.Value() == "0" {
			m.unregistered <- struct{}{}
		} else if m.registrations.Add(1) == 1 {
			m.authorized <- struct{}{}
		} else {
			m.refresh <- struct{}{}
		}
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{}, 1)
	ctx = context.WithValue(ctx, sipgo.ListenReadyCtxKey, sipgo.ListenReadyFuncCtxValue(func(_, _ string) { ready <- struct{}{} }))
	go func() {
		_ = server.ListenAndServeTLS(ctx, "tls", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)),
			&tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: maxTLS,
				Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	}()
	select {
	case <-ready:
	case <-time.After(3 * time.Second):
		t.Fatal("registrar listener did not start")
	}
	t.Cleanup(func() { cancel(); ua.Close() })
	return m
}

func config(m *mockRegistrar) Config {
	return Config{Port: m.port, ServerName: "localhost", Roots: m.roots,
		Username: "synthetic", Password: "only-for-tests-long", Expiry: 10 * time.Second,
		Refresh: 80 * time.Millisecond, RetryMin: 30 * time.Millisecond,
		RetryMax: 150 * time.Millisecond, Timeout: time.Second}
}

func receive(t *testing.T, ch <-chan struct{}, name string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(4 * time.Second):
		t.Fatalf("missing %s", name)
	}
}

func TestRegisterChallengeRefreshAndShutdown(t *testing.T) {
	m := startMock(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var accepted atomic.Int32
	var refreshed atomic.Int32
	refreshObserved := make(chan struct{}, 1)
	c := config(m)
	c.OnFirstRegistered = func() error {
		accepted.Add(1)
		return nil
	}
	c.OnFirstRefreshed = func() error {
		refreshed.Add(1)
		refreshObserved <- struct{}{}
		return nil
	}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, c) }()
	receive(t, m.challenge, "401 challenge")
	receive(t, m.authorized, "authenticated REGISTER")
	receive(t, m.refresh, "refresh REGISTER")
	receive(t, refreshObserved, "accepted refresh response")
	if accepted.Load() != 1 || refreshed.Load() != 1 {
		t.Fatal("accepted REGISTER and later refresh must each be observed exactly once")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	receive(t, m.unregistered, "Expires: 0 unregister")
	t.Log("PASS: TLS verified; 401 -> authenticated REGISTER -> refresh -> unregister")
}

func TestRegistrationStopsWhenPrivateAcceptanceStatusCannotBeRecorded(t *testing.T) {
	m := startMock(t)
	c := config(m)
	var called atomic.Int32
	c.OnFirstRegistered = func() error {
		called.Add(1)
		return io.ErrClosedPipe
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := Run(ctx, c)
	if err == nil || err.Error() != "registration accepted but private status unavailable" || called.Load() != 1 {
		t.Fatal("lost owner-private acceptance signal must stop the process with a fixed error")
	}
	receive(t, m.authorized, "authenticated REGISTER before status failure")
}

func TestProviderNeutralTLSRegisterWithPinnedCertificate(t *testing.T) {
	m := startMock(t)
	cfg := serviceconfig.Config{
		UpstreamHost: "127.0.0.1", UpstreamPort: uint16(m.port),
		UpstreamTLSName: "localhost", UpstreamUsername: "synthetic",
		UpstreamPassword: "only-for-tests-long", CertSHA256: m.certSHA,
	}
	ctx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunUpstream(ctx, cfg, m.roots, "127.0.0.1") }()
	receive(t, m.challenge, "pinned TLS SIP 401 challenge")
	receive(t, m.authorized, "authenticated provider-neutral REGISTER")
	stop()
	if err := <-done; err != nil && err.Error() != "registration never established; no SIP retry after cancellation" {
		t.Fatal("synthetic remote registrar shutdown failed unexpectedly")
	}
	// Cancellation immediately after the server observes auth can race
	// the client receiving the 200 response. Unregister is best-effort;
	// never infer final provider state from an ambiguous response.
	wrong := cfg
	wrong.CertSHA256[0] ^= 0xff
	deadline, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if RunUpstream(deadline, wrong, m.roots, "127.0.0.1") == nil {
		t.Fatal("wrong DER leaf thumbprint accepted for SIP registration")
	}
	wrong = cfg
	wrong.UpstreamTLSName = "elsewhere.invalid"
	wrongNameCtx, cancelWrongName := context.WithTimeout(context.Background(), time.Second)
	defer cancelWrongName()
	if RunUpstream(wrongNameCtx, wrong, m.roots, "127.0.0.1") == nil {
		t.Fatal("wrong certificate hostname accepted for SIP registration")
	}
}

func TestRegistrationRecoversAfterFailure(t *testing.T) {
	m := startMock(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, config(m)) }()
	receive(t, m.authorized, "initial REGISTER")
	m.fail.Store(true)
	var failedAt time.Time
	select {
	case failedAt = <-m.failures:
	case <-time.After(4 * time.Second):
		t.Fatal("no registrar failure")
	}
	m.fail.Store(false)
	receive(t, m.refresh, "registration after retry")
	if time.Since(failedAt) < 30*time.Millisecond {
		t.Fatal("retry skipped the bounded backoff")
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	second, stopSecond := context.WithCancel(context.Background())
	secondDone := make(chan error, 1)
	go func() { secondDone <- Run(second, config(m)) }()
	receive(t, m.refresh, "registration after prior Run finished")
	stopSecond()
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
}

func TestReconnectAfterTransportDrop(t *testing.T) {
	m := startMock(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, config(m)) }()
	receive(t, m.authorized, "initial REGISTER")
	m.dropNext.Store(true)
	receive(t, m.dropped, "closed TLS connection")
	receive(t, m.refresh, "REGISTER on fresh TLS connection")
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestInvalidTLSAndCredential(t *testing.T) {
	m := startMock(t)
	for _, edit := range []func(*Config){
		func(c *Config) { c.ServerName = "wrong.invalid" },
		func(c *Config) { c.Roots = x509.NewCertPool() },
		func(c *Config) { c.Password = "incorrect" },
	} {
		c := config(m)
		edit(&c)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := Run(ctx, c)
		cancel()
		if err == nil || err.Error() != "registration rejected or TLS identity invalid" {
			t.Fatalf("failure did not fail closed: %v", err)
		}
	}
}

func TestExpiredCertificateAndOldTLS(t *testing.T) {
	for _, m := range []*mockRegistrar{
		startMockWithTLS(t, time.Now().Add(-time.Minute), 0),
		startMockWithTLS(t, time.Now().Add(time.Hour), tls.VersionTLS11),
	} {
		c := config(m)
		c.Timeout = 200 * time.Millisecond
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		err := Run(ctx, c)
		cancel()
		if err == nil || err == context.DeadlineExceeded {
			t.Fatalf("expired certificate or TLS 1.1 succeeded or stalled: %v", err)
		}
		select {
		case <-m.authorized:
			t.Fatal("accepted invalid TLS")
		default:
		}
	}
}

func TestPersistentFailureStopsAndBadTimingIsRejected(t *testing.T) {
	m := startMock(t)
	c := config(m)
	for _, edit := range []func(*Config){
		func(c *Config) { c.Timeout = 11 * time.Second },
		func(c *Config) { c.RetryMin = time.Nanosecond },
		func(c *Config) { c.RetryMax = 11 * time.Second },
		func(c *Config) { c.Refresh = c.Expiry },
		func(c *Config) { c.Username = "bad\r\nVia: injected" },
		func(c *Config) { c.Username = "other@host" },
		func(c *Config) { c.Password = strings.Repeat("x", 257) },
	} {
		bad := c
		edit(&bad)
		if Check(bad) == nil {
			t.Fatal("accepted unsafe timing settings")
		}
	}
	m.fail.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := Run(ctx, c); err == nil || err.Error() != "registration temporarily unavailable" {
		t.Fatalf("persistent failure did not stop: %v", err)
	}
	if len(m.failures) != maxConsecutiveFailures {
		t.Fatalf("attempt count = %d", len(m.failures))
	}
}

func TestPacketDebugDoesNotEmitCredential(t *testing.T) {
	// The registration package's tracer must remain safe even if an
	// embedding application inadvertently enables sipgo packet debugging.
	if !sip.SIPDebug {
		t.Fatal("debug mode disabled in test binary")
	}
	m := startMock(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, config(m)) }()
	receive(t, m.authorized, "debug-mode authenticated REGISTER")
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentRegistrationIsRejected(t *testing.T) {
	m := startMock(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, config(m)) }()
	receive(t, m.authorized, "first registration")
	if err := Run(context.Background(), config(m)); err == nil || err.Error() != "local registration already active" {
		t.Fatalf("concurrent registration not rejected: %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestUsernameCannotInjectSIPURI(t *testing.T) {
	for _, user := range []string{"a", strings.Repeat("a", 64), "user.name-123_ABC"} {
		if !validUser(user) {
			t.Fatal("safe SIP username rejected")
		}
	}
	for _, user := range []string{"", strings.Repeat("a", 65), "alice@bob", "user\rname",
		"user\nname", "usérñame", "user!name", "user%0d%0aheader:value"} {
		if validUser(user) {
			t.Fatal("unsafe SIP username accepted")
		}
	}
}
