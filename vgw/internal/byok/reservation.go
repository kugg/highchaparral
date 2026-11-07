// Package byok owns transient user-supplied SIP credentials for ONE
// browser-to-provider call. It neither persists secrets nor dials SIP.
package byok

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const Path = "/cgi-bin/vgw"

var (
	identity     = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	destination  = regexp.MustCompile(`^[0-9]{2,5}$`)
	noncePattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
)

func reject() error { return errors.New("BYOK reservation refused") }

func validPassword(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	for _, b := range []byte(value) {
		if b < '!' || b > '~' {
			return false
		}
	}
	return true
}

// Credentials are supplied once after verified ARI channel admission.
// The password is a private heap copy; never log, serialize or retain it.
type Credentials struct {
	Identity string
	Password []byte
	Target   string
}

func (Credentials) String() string   { return "provider BYOK credentials [redacted]" }
func (Credentials) GoString() string { return "byok.Credentials{redacted}" }
func (Credentials) LogValue() slog.Value {
	return slog.StringValue("provider BYOK credentials [redacted]")
}
func (Credentials) MarshalJSON() ([]byte, error) {
	return nil, errors.New("BYOK credential serialization refused")
}

func (c *Credentials) Clear() {
	for i := range c.Password {
		c.Password[i] = 0
	}
	c.Password = nil
}

type reservation struct {
	identity string
	password []byte
	target   string
	nonce    string
	expires  time.Time
}

type Store struct {
	mu      sync.Mutex
	origins map[string]string // exact HTTPS Origin -> matching request Host
	now     func() time.Time
	pending *reservation
	active  string
}

func (*Store) String() string { return "BYOK reservation store [redacted]" }

// New permits only an exact HTTPS origin. The loopback Go HTTP listener
// is published solely through a separately owned same-origin APU proxy.
func New(origins ...string) (*Store, error) {
	if len(origins) == 0 || len(origins) > 2 {
		return nil, reject()
	}
	allowed := make(map[string]string, len(origins))
	for _, origin := range origins {
		u, err := url.Parse(origin)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
			u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.String() != origin ||
			allowed[origin] != "" {
			return nil, reject()
		}
		allowed[origin] = u.Host
	}
	return &Store{origins: allowed, now: time.Now}, nil
}

func clear(raw []byte) {
	for i := range raw {
		raw[i] = 0
	}
}

func (s *Store) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	refuse := func(code int) { w.WriteHeader(code); _, _ = io.WriteString(w, `{"reserved":false}`) }
	if r.URL.Path != Path || r.Method != http.MethodPost ||
		s.origins[r.Header.Get("Origin")] == "" || r.Host != s.origins[r.Header.Get("Origin")] ||
		r.Header.Get("X-VGW-Client") != "softphone-v1" ||
		(strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json") ||
		(r.Header.Get("Sec-Fetch-Site") != "" && r.Header.Get("Sec-Fetch-Site") != "same-origin") {
		refuse(http.StatusForbidden)
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 1025))
	if err != nil || len(data) < 20 || len(data) > 1024 {
		clear(data)
		refuse(http.StatusBadRequest)
		return
	}
	var input struct {
		Identity    string `json:"identity"`
		Password    string `json:"password"`
		Destination string `json:"destination"`
		Nonce       string `json:"nonce"`
	}
	decode := json.NewDecoder(strings.NewReader(string(data)))
	decode.DisallowUnknownFields()
	if decode.Decode(&input) != nil || decode.Decode(new(any)) != io.EOF ||
		!identity.MatchString(input.Identity) || !validPassword(input.Password) ||
		!destination.MatchString(input.Destination) || !noncePattern.MatchString(input.Nonce) {
		clear(data)
		refuse(http.StatusBadRequest)
		return
	}
	clear(data)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending != nil && !s.now().Before(s.pending.expires) {
		clear(s.pending.password)
		s.pending = nil // never sent to the provider; no pending call was consumed
	}
	if s.pending != nil || s.active != "" {
		refuse(http.StatusConflict)
		return
	}
	s.pending = &reservation{identity: input.Identity, password: []byte(input.Password),
		target: input.Destination, nonce: input.Nonce, expires: s.now().Add(45 * time.Second)}
	w.WriteHeader(http.StatusCreated)
	_, _ = io.WriteString(w, `{"reserved":true}`)
}

// Consume is called only AFTER the owned ARI event/GET validates a browser
// leg and the short SIP nonce is read from that leg. No number is accepted
// from an untrusted SIP/ARI field without matching the private reservation.
func (s *Store) Consume(nonce, target string) (Credentials, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending != nil && !s.now().Before(s.pending.expires) {
		clear(s.pending.password)
		s.pending = nil
	}
	if s.pending == nil || s.active != "" ||
		!noncePattern.MatchString(nonce) || !destination.MatchString(target) ||
		subtle.ConstantTimeCompare([]byte(s.pending.nonce), []byte(nonce)) != 1 ||
		s.pending.target != target {
		return Credentials{}, reject()
	}
	copyOfSecret := append([]byte(nil), s.pending.password...)
	clear(s.pending.password)
	out := Credentials{Identity: s.pending.identity, Password: copyOfSecret, Target: target}
	s.pending = nil
	s.active = nonce
	return out, nil
}

// Complete unlocks the next call only after a definite local cleanup.
// Ambiguous BYE or delivery leaves active set for explicit reconciliation;
// there is never an automatic retry of the same nonce.
func (s *Store) Complete(nonce string, settled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !settled || s.active == "" || subtle.ConstantTimeCompare([]byte(s.active), []byte(nonce)) != 1 {
		return reject()
	}
	s.active = ""
	return nil
}
