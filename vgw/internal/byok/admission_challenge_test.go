package byok

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// JER-14 (this change): the original exploit sent well-formed POSTs using only
// client-controlled Origin/Host/X-VGW-Client headers and claimed the pending
// slot. After this repair those requests are refused unless a server-verified
// session assertion is presented; the flood no longer allocates pending state.

func reserveWithToken(s *Store, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "https://apu.invalid"+Path, strings.NewReader(body))
	req.Header.Set("Origin", "https://apu.invalid")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("X-VGW-Client", "softphone-v1")
	if token != "" {
		req.Header.Set(AdmissionHeader, token)
	}
	out := httptest.NewRecorder()
	s.ServeHTTP(out, req)
	return out
}

func TestBYOKAdmissionRejectsHeaderOnlyFloodBeforeState(t *testing.T) {
	s, _ := testAdmission(t, nil)
	for i := 0; i < 12; i++ {
		body := strings.ReplaceAll(syntheticRequest, syntheticNonce, strings.Repeat("f", 32))
		if out := reserve(s, body); out.Code != http.StatusUnauthorized {
			t.Fatalf("flood %d not refused without admission: %d", i, out.Code)
		}
	}
	s.mu.Lock()
	held := s.pending != nil || s.active != ""
	s.mu.Unlock()
	if held {
		t.Fatal("header-only flood allocated BYOK state")
	}
}

func TestBYOKAdmissionStoreWithoutVerifierFailsClosed(t *testing.T) {
	s, err := New("https://apu.invalid") // nil admission
	if err != nil {
		t.Fatal(err)
	}
	if out := reserve(s, syntheticRequest); out.Code != http.StatusServiceUnavailable {
		t.Fatalf("admission-less store did not fail closed: %d", out.Code)
	}
}

func TestBYOKAdmissionRefusalAndPositive(t *testing.T) {
	adm, err := NewHMACAdmission([]byte("test-only=session-secret-32-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now()
	adm.now = func() time.Time { return clock }
	s, err := NewWithAdmission(adm, "https://apu.invalid")
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return clock }

	if out := reserveWithToken(s, "", syntheticRequest); out.Code != http.StatusUnauthorized {
		t.Fatal("unsigned reservation accepted")
	}
	if out := reserveWithToken(s, "v1.eyJzdWIiOiJ1c2VyLTAxIiwiZXhwIjoyNTUyNTUyNTUyNX0.Zm9yZ2Vk", syntheticRequest); out.Code != http.StatusUnauthorized {
		t.Fatal("forged session accepted")
	}
	tok, err := adm.Issue("user-01", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(7 * time.Second)
	if out := reserveWithToken(s, tok, syntheticRequest); out.Code != http.StatusUnauthorized {
		t.Fatal("expired session accepted")
	}

	// Legitimate principal reserves; a second principal is refused only while
	// the single slot is pending (409).
	clock = time.Now().Add(-time.Minute)
	adm.now = func() time.Time { return clock }
	s.now = func() time.Time { return clock }
	tok1, err := adm.Issue("user-01", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if out := reserveWithToken(s, tok1, syntheticRequest); out.Code != http.StatusCreated {
		t.Fatal("legitimate reservation refused after admission")
	}
	tok2, err := adm.Issue("user-02", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if out := reserveWithToken(s, tok2, syntheticRequest); out.Code != http.StatusConflict {
		t.Fatal("second call admitted while slot is pending")
	}
}

func TestBYOKAdmissionPerPrincipalLimit(t *testing.T) {
	adm, err := NewHMACAdmission([]byte("test-only=session-secret-32-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	clock := time.Now()
	adm.now = func() time.Time { return clock }
	s, err := NewWithAdmission(adm, "https://apu.invalid")
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return clock }
	s.pending = &reservation{identity: "occupied", account: "user-00",
		password: []byte("x"), target: "1111", nonce: strings.Repeat("e", 32),
		expires: clock.Add(45 * time.Second)}
	// Occupied slot forces every admitted frame to hit the single-slot check.
	// Admission budget is consumed per attempt; after the budget is exhausted
	// the principal is rate-limited before state is touched.
	for i := 0; i < 3*maxAdmissionAttempts; i++ {
		tok, _ := adm.Issue("user-01", time.Minute)
		out := reserveWithToken(s, tok, syntheticRequest)
		if i < maxAdmissionAttempts {
			if out.Code != http.StatusConflict {
				t.Fatalf("attempt %d: expected 409 (slot occupied) got %d", i, out.Code)
			}
		} else if out.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected rate-limited 401 got %d", i, out.Code)
		}
	}
}
