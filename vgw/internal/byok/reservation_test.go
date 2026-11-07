package byok

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const syntheticNonce = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const syntheticRequest = `{"identity":"synthetic","password":"test-only=password","destination":"1234","nonce":"` + syntheticNonce + `"}`

func reserve(s *Store, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "https://apu.invalid"+Path, strings.NewReader(body))
	req.Header.Set("Origin", "https://apu.invalid")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("X-VGW-Client", "softphone-v1")
	out := httptest.NewRecorder()
	s.ServeHTTP(out, req)
	return out
}

func TestBYOKReservationIsEphemeralOneCallAndNeverEchoesCredential(t *testing.T) {
	s, err := New("https://apu.invalid")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s.now = func() time.Time { return now }
	out := reserve(s, syntheticRequest)
	if out.Code != http.StatusCreated || out.Body.String() != `{"reserved":true}` ||
		strings.Contains(out.Body.String(), "test-only") || out.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("private BYOK reservation was not bounded or redacted")
	}
	if _, err := s.Consume(syntheticNonce, "9999"); err == nil ||
		strings.Contains(err.Error(), "test-only") || s.pending == nil {
		t.Fatal("mismatched ARI destination consumed a BYOK identity")
	}
	if _, err := s.Consume(strings.Repeat("b", 32), "1234"); err == nil || s.pending == nil {
		t.Fatal("unknown browser call token consumed BYOK identity")
	}
	private, err := s.Consume(syntheticNonce, "1234")
	if err != nil || private.Identity != "synthetic" || string(private.Password) != "test-only=password" ||
		private.Target != "1234" || strings.Contains(private.String(), "test-only") {
		t.Fatal("approved BYOK credentials were not delivered exactly once")
	}
	if _, err := json.Marshal(private); err == nil || strings.Contains(err.Error(), "test-only") ||
		strings.Contains(fmt.Sprintf("%+v", private), "test-only") {
		t.Fatal("BYOK credential could be serialized or reflected into logs")
	}
	if _, err := s.Consume(syntheticNonce, "1234"); err == nil {
		t.Fatal("BYOK token could be reused")
	}
	if reserve(s, strings.ReplaceAll(syntheticRequest, syntheticNonce, strings.Repeat("b", 32))).Code != http.StatusConflict {
		t.Fatal("second provider call admitted while first is active")
	}
	if s.Complete(syntheticNonce, false) == nil || s.active == "" {
		t.Fatal("ambiguous BYE freed the provider call slot")
	}
	private.Clear()
	if len(private.Password) != 0 {
		t.Fatal("call credential copy not cleared")
	}
	if err := s.Complete(syntheticNonce, true); err != nil || s.active != "" {
		t.Fatal("settled call did not free the provider slot")
	}
}

func TestBYOKTimeoutAndUntrustedInboundNeverReflectSecret(t *testing.T) {
	s, err := New("https://apu.invalid")
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now()
	s.now = func() time.Time { return clock }
	if reserve(s, syntheticRequest).Code != http.StatusCreated {
		t.Fatal("synthetic reservation failed")
	}
	expiredSecret := s.pending.password
	clock = clock.Add(46 * time.Second)
	if _, err := s.Consume(syntheticNonce, "1234"); err == nil || s.pending != nil {
		t.Fatal("expired BYOK reservation could still dial")
	}
	for _, b := range expiredSecret {
		if b != 0 {
			t.Fatal("expired credential was retained")
		}
	}
	for _, payload := range []string{
		strings.ReplaceAll(syntheticRequest, "test-only=password", "bad\\r\\nX-Log: forged"),
		strings.ReplaceAll(syntheticRequest, `"destination":"1234"`, `"destination":"sip:1234@other.invalid"`),
		strings.TrimSuffix(syntheticRequest, "}") + `,"extra":"unexpected"}`,
		strings.Repeat("X", 1025),
	} {
		out := reserve(s, payload)
		if out.Code != http.StatusBadRequest || strings.Contains(out.Body.String(), "test-only") ||
			strings.Contains(out.Body.String(), "forged") {
			t.Fatal("untrusted BYOK request was accepted/reflected")
		}
	}
	request := httptest.NewRequest(http.MethodPost, "https://apu.invalid"+Path, io.NopCloser(strings.NewReader(syntheticRequest)))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-VGW-Client", "softphone-v1")
	response := httptest.NewRecorder()
	s.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatal("cross-origin/browser-less BYOK request accepted")
	}
}

func TestBYOKOriginCannotDowngradeToPlaintextOrExternalPath(t *testing.T) {
	for _, origin := range []string{"http://apu.invalid", "https://apu.invalid/path", "https://user@apu.invalid", "https://apu.invalid/"} {
		if _, err := New(origin); err == nil {
			t.Fatal("unreviewed BYOK origin accepted")
		}
	}
	if _, err := New("https://apu.invalid", "https://apu.invalid"); err == nil {
		t.Fatal("duplicate BYOK site origin accepted")
	}
	s, err := New("https://apu.invalid", "https://apu-office.invalid")
	if err != nil {
		t.Fatal("two exact APU site origins refused")
	}
	request := httptest.NewRequest(http.MethodPost, "https://other.invalid"+Path, strings.NewReader(syntheticRequest))
	request.Header.Set("Origin", "https://apu.invalid")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-VGW-Client", "softphone-v1")
	out := httptest.NewRecorder()
	s.ServeHTTP(out, request)
	if out.Code != http.StatusForbidden {
		t.Fatal("mismatched Host/Origin accepted over loopback proxy")
	}
}
