package registration

import (
	"context"
	"testing"
	"time"

	"example.com/ata/voip-gateway/internal/serviceconfig"
)

func oneShotConfig(t *testing.T, m *mockRegistrar) Config {
	t.Helper()
	tlsPolicy, err := serviceconfig.TLSClient(serviceconfig.Config{
		UpstreamHost: "127.0.0.1", UpstreamPort: uint16(m.port),
		UpstreamTLSName: "localhost", CertSHA256: m.certSHA,
	}, m.roots)
	if err != nil {
		t.Fatal("synthetic certificate policy unavailable")
	}
	c := config(m)
	c.Host = "127.0.0.1"
	c.BindHost = "127.0.0.1"
	c.TLS = tlsPolicy
	c.Expiry = 90 * time.Second
	c.Refresh = 45 * time.Second
	c.RetryMin = 2 * time.Second
	c.RetryMax = 10 * time.Second
	return c
}

func TestRegisterOnceChallengeAcceptedAndUnregistered(t *testing.T) {
	m := startMock(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := RegisterOnce(ctx, oneShotConfig(t, m))
	if err != nil || !result.Registered || !result.Unregistered {
		t.Fatal("single authenticated TLS registration/unregister did not complete")
	}
	receive(t, m.challenge, "one 401/Digest challenge")
	receive(t, m.authorized, "one authenticated REGISTER")
	receive(t, m.unregistered, "one Expires 0 Unregister")
	if m.registrations.Load() != 1 || len(m.refresh) != 0 {
		t.Fatal("registration-only probe sent an application refresh")
	}
}

func TestRegisterOnceFailureDoesNotRetryOrSendUnregister(t *testing.T) {
	m := startMock(t)
	m.fail.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	result, err := RegisterOnce(ctx, oneShotConfig(t, m))
	if err == nil || result.Registered || result.Unregistered {
		t.Fatal("failed registration was reported accepted")
	}
	select {
	case <-m.failures:
	case <-ctx.Done():
		t.Fatal("one failed REGISTER response not observed")
	}
	if len(m.failures) != 0 || len(m.unregistered) != 0 || m.registrations.Load() != 0 {
		t.Fatal("one-use failure retried or sent an unexpected request")
	}
}
