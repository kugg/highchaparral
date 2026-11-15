package byok

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type testClock struct{ t time.Time }

func (c *testClock) now() time.Time { return c.t }
func (c *testClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newAdmittedStore(t *testing.T) (*Store, *SessionAdmitter, *testClock) {
	t.Helper()
	clock := &testClock{t: time.Now()}
	admitter, err := NewSessionAdmitter(bytes.Repeat([]byte("k"), 64))
	if err != nil {
		t.Fatal(err)
	}
	admitter.now = clock.now
	s, err := NewWithAdmission(admitter, "https://apu.invalid")
	if err != nil {
		t.Fatal(err)
	}
	s.now = clock.now
	return s, admitter, clock
}

func TestBYOKFailClosedWithoutTrustedAdmission(t *testing.T) {
	s, err := New("https://apu.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if out := reserve(s, syntheticRequest); out.Code != http.StatusServiceUnavailable || s.pending != nil {
		t.Fatal("header-only store admitted a reservation instead of failing closed")
	}
	if _, err := NewWithAdmission(nil, "https://apu.invalid"); err == nil {
		t.Fatal("admitting store constructed without an Admission")
	}
}

func TestBYOKReservationRefusesUnsignedForgedAndExpiredSessions(t *testing.T) {
	s, admitter, clock := newAdmittedStore(t)
	if out := reserve(s, syntheticRequest); out.Code != http.StatusUnauthorized || s.pending != nil {
		t.Fatal("unsigned reservation allocated the pending slot")
	}
	forged, err := admitter.Issue("synthetic", "sess-1", clock.now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(forged, ".")
	tampered := parts[0] + "." + parts[1] + "." + strings.Repeat("A", len(parts[2]))
	if out := authReserve(s, syntheticRequest, tampered); out.Code != http.StatusUnauthorized || s.pending != nil {
		t.Fatal("tampered session assertion allocated the pending slot")
	}
	valid, err := admitter.Issue("synthetic", "sess-2", clock.now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	clock.advance(2 * time.Minute)
	if out := authReserve(s, syntheticRequest, valid); out.Code != http.StatusUnauthorized || s.pending != nil {
		t.Fatal("expired session assertion allocated the pending slot")
	}
}

func TestBYOKClientSuppliedIdentityHeadersRejectedWithoutAdmission(t *testing.T) {
	s, _, _ := newAdmittedStore(t)
	req := httptest.NewRequest(http.MethodPost, "https://apu.invalid"+Path, strings.NewReader(syntheticRequest))
	req.Header.Set("Origin", "https://apu.invalid")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-VGW-Client", "softphone-v1")
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.Header.Set("X-Forwarded-Account", "victim")
	out := httptest.NewRecorder()
	s.ServeHTTP(out, req)
	if out.Code != http.StatusUnauthorized || s.pending != nil {
		t.Fatal("client-supplied identity headers obtained reservation authority")
	}
}

func TestBYOKUnauthenticatedCannotMonopolizeSlot(t *testing.T) {
	s, admitter, _ := newAdmittedStore(t)
	for i := 0; i < 10; i++ {
		nonce := strings.Repeat(string(rune('a'+i)), 32)
		if out := reserve(s, strings.ReplaceAll(syntheticRequest, syntheticNonce, nonce)); out.Code != http.StatusUnauthorized {
			t.Fatal("unauthenticated monopolization attempt was not refused")
		}
	}
	if s.pending != nil {
		t.Fatal("unauthenticated traffic allocated shared reservation state")
	}
	token, err := admitter.Issue("legit", "sess-1", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if out := authReserve(s, syntheticRequest, token); out.Code != http.StatusCreated {
		t.Fatal("legitimate caller blocked after unauthenticated flood")
	}
}

func TestBYOKPerPrincipalAttemptLimit(t *testing.T) {
	s, admitter, _ := newAdmittedStore(t)
	for i := 0; i < fairMaxPerUser; i++ {
		token, err := admitter.Issue("flooder", "sess-flood", time.Now().Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		body := strings.ReplaceAll(syntheticRequest, syntheticNonce, strings.Repeat(string(rune('a'+i)), 32))
		if out := authReserve(s, body, token); out.Code == http.StatusTooManyRequests {
			t.Fatal("attempt limit fired before the configured budget")
		}
	}
	token, err := admitter.Issue("flooder", "sess-flood", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if out := authReserve(s, strings.ReplaceAll(syntheticRequest, syntheticNonce, strings.Repeat("z", 32)), token); out.Code != http.StatusTooManyRequests {
		t.Fatal("per-principal attempt limit did not fire")
	}
	other, err := admitter.Issue("bystander", "sess-ok", time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if out := authReserve(s, strings.ReplaceAll(syntheticRequest, syntheticNonce, strings.Repeat("y", 32)), other); out.Code == http.StatusTooManyRequests {
		t.Fatal("attempt limit leaked across principals")
	}
}
