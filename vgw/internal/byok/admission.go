// Package byok transit credentials exactly once for one browser-to-provider
// call. Admission verifies the requesting principal through a server-issued
// session assertion before the store allocates any pending state, because the
// intended same-origin proxy boundary must not be spoofable with client-set
// headers alone. See vgw/claims.json VGW-BYOK-ADMISSION-001.
package byok

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// maxAdmissionAttempts bounds how many reservation POSTs one principal may
// make inside the sliding window. A legitimately admitted caller keeps a
// single pending slot; a rejected flood cannot monopolize later legitimate
// attempts and cannot exhaust memory because attempts are only recorded once
// the logged-in principal has been verified.
const (
	maxAdmissionAttempts = 5
	admissionWindow      = 60 * time.Second
	admissionLifetime    = 60 * time.Second
	// AdmissionHeader carries the server-issued session assertion. It is
	// client-transparent; the receiver only trusts its verified MAC.
	AdmissionHeader   = "X-VGW-Session"
	AdmissionTokenMax = 512 // max serialized assertion bytes accepted
)

var admissionID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Admission verifies the caller's logged-in identity before any reservation
// state is touched. It is the server-side trust boundary the proxy must
// honor; the store fails closed when no admission verifier is installed.
type Admission interface {
	// Principal returns the verified account identity for the request, or an
	// error naming the refusal category. Implementations MUST be constant-time
	// for signature/mac comparisons and MUST expire assertions.
	Principal(r *http.Request) (string, error)
}

// HMACAdmission verifies signed, expiring session assertions issued by the
// trusted same-origin admission service (which also owns the deployed HTTP
// listener, so it can set an HttpOnly cookie or proxy a signed header).
//
// The assertion is `{"subject":<id>,"exp":<unix seconds>}` encoded as JSON,
// then base64url, then `v1.<b64>.<hmac-sha256(secret, b64)>`. Constant-time
// MAC comparison, strict expiry, canonical subject grammar and bounded sizes.
type HMACAdmission struct {
	mu     sync.Mutex
	secret []byte
	now    func() time.Time
	tried  map[string][]int64 // subject -> recent admission-window timestamps
}

// NewHMACAdmission requires a non-empty, sized secret and binds the clock.
func NewHMACAdmission(secret []byte) (*HMACAdmission, error) {
	if len(secret) < 16 || len(secret) > 256 {
		return nil, errors.New("BYOK admission secret size invalid")
	}
	return &HMACAdmission{secret: append([]byte(nil), secret...), now: time.Now, tried: make(map[string][]int64)}, nil
}

// Close clears the secret copy.
func (a *HMACAdmission) Close() {
	for i := range a.secret {
		a.secret[i] = 0
	}
	a.secret = nil
}

func sign(b []byte, secret []byte) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(b)
	return mac.Sum(nil)
}

// Issue creates a signed assertion for a known principle holder. It is used
// by the trusted admission/credential server, not by web clients.
func (a *HMACAdmission) Issue(subject string, ttl time.Duration) (string, error) {
	if !admissionID.MatchString(subject) {
		return "", errors.New("BYOK admission subject invalid")
	}
	if ttl < time.Second || ttl > admissionLifetime {
		return "", errors.New("BYOK admission ttl invalid")
	}
	payload := struct {
		Subject string `json:"subject"`
		Exp     int64  `json:"exp"`
	}{Subject: subject, Exp: a.now().Add(ttl).Unix()}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", errors.New("BYOK admission issue unavailable")
	}
	b64 := base64.RawURLEncoding.EncodeToString(raw)
	mac := sign([]byte(b64), a.secret)
	token := "v1." + b64 + "." + base64.RawURLEncoding.EncodeToString(mac)
	return token, nil
}

func (a *HMACAdmission) allowLocked(subject string) bool {
	now := a.now().Unix()
	cutoff := now - int64(admissionWindow.Seconds())
	kept := a.tried[subject][:0]
	for _, ts := range a.tried[subject] {
		if ts >= cutoff {
			kept = append(kept, ts)
		}
	}
	a.tried[subject] = kept
	if len(kept) >= maxAdmissionAttempts {
		return false
	}
	a.tried[subject] = append(a.tried[subject], now)
	if len(a.tried) > 4096 { // global bound: never grow without limit
		cleared := false
		for k, list := range a.tried {
			if len(list) == 0 && !cleared {
				delete(a.tried, k)
				cleared = true
			}
		}
	}
	return true
}

// Principal verifies the signed session assertion and the per-principal
// admission-window budget before returning the subject identity.
func (a *HMACAdmission) Principal(r *http.Request) (string, error) {
	header := r.Header.Get(AdmissionHeader)
	if header == "" || len(header) > 512 {
		return "", errors.New("BYOK admission missing")
	}
	parts := strings.Split(header, ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return "", errors.New("BYOK admission malformed")
	}
	b64, b64mac := parts[1], parts[2]
	if len(b64) == 0 || len(b64) > 400 || len(b64mac) != base64.RawURLEncoding.EncodedLen(sha256.Size) {
		return "", errors.New("BYOK admission size invalid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil || len(raw) == 0 || len(raw) > 512 {
		return "", errors.New("BYOK admission decode invalid")
	}
	expected := sign([]byte(b64), a.secret)
	got, err := base64.RawURLEncoding.DecodeString(b64mac)
	if err != nil || len(got) != sha256.Size {
		return "", errors.New("BYOK admission mac invalid")
	}
	if subtle.ConstantTimeCompare(got, expected) != 1 {
		return "", errors.New("BYOK admission refused")
	}
	var payload struct {
		Subject string `json:"subject"`
		Exp     int64  `json:"exp"`
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if dec.Decode(&payload) != nil || dec.Decode(new(any)) == nil ||
		admissionID.MatchString(payload.Subject) == false || payload.Exp <= 0 {
		return "", errors.New("BYOK admission claim invalid")
	}
	if a.now().Unix() >= payload.Exp {
		return "", errors.New("BYOK admission expired")
	}
	a.mu.Lock()
	ok := a.allowLocked(payload.Subject)
	a.mu.Unlock()
	if !ok {
		return "", errors.New("BYOK admission limited")
	}
	return payload.Subject, nil
}