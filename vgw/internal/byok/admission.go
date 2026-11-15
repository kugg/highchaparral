package byok

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Principal is a server-verified caller identity established at a trusted
// boundary (an authenticated HTTPS session or a trusted reverse-proxy
// assertion). It is never derived from client-controlled headers alone.
type Principal struct {
	Account string
	Session string
	Expires time.Time
}

func (p Principal) String() string { return "BYOK principal " + p.Account }

// Admission verifies a trusted session assertion on a reservation request
// before any shared pending-slot state is allocated.
type Admission interface {
	Admit(r *http.Request) (Principal, bool)
}

var sessionAccount = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// SessionAdmitter verifies HMAC-SHA256 session assertions issued by the
// trusted credential-entry/login boundary. The secret stays on the trusted
// side; callers cannot forge, extend or replay an assertion past expiry.
type SessionAdmitter struct {
	secret []byte
	now    func() time.Time
}

func NewSessionAdmitter(secret []byte) (*SessionAdmitter, error) {
	if len(secret) < 32 || len(secret) > 4096 {
		return nil, reject()
	}
	return &SessionAdmitter{secret: append([]byte(nil), secret...), now: time.Now}, nil
}

// Issue creates a session assertion for the trusted login boundary.
func (a *SessionAdmitter) Issue(account, session string, expires time.Time) (string, error) {
	if !sessionAccount.MatchString(account) || session == "" || len(session) > 128 ||
		!a.now().Before(expires) {
		return "", reject()
	}
	payload := account + "|" + session + "|" + strconv.FormatInt(expires.Unix(), 10)
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte(payload))
	return "v1." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (a *SessionAdmitter) Admit(r *http.Request) (Principal, bool) {
	parts := strings.Split(r.Header.Get("X-VGW-Session"), ".")
	if len(parts) != 3 || parts[0] != "v1" {
		return Principal{}, false
	}
	payload, err1 := base64.RawURLEncoding.DecodeString(parts[1])
	mac, err2 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil {
		return Principal{}, false
	}
	want := hmac.New(sha256.New, a.secret)
	want.Write(payload)
	if subtle.ConstantTimeCompare(want.Sum(nil), mac) != 1 {
		return Principal{}, false
	}
	fields := strings.Split(string(payload), "|")
	if len(fields) != 3 || !sessionAccount.MatchString(fields[0]) ||
		fields[1] == "" || len(fields[1]) > 128 {
		return Principal{}, false
	}
	exp, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return Principal{}, false
	}
	expires := time.Unix(exp, 0)
	if !a.now().Before(expires) {
		return Principal{}, false
	}
	return Principal{Account: fields[0], Session: fields[1], Expires: expires}, true
}
