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

// activeTTL bounds how long an unsettled (ambiguous) call may hold the slot
// before it auto-recovers. It MUST exceed the provider-leg context bound
// (2 minutes, see softphone coordinator) so the old leg is force-torn-down
// by its own deadline before the slot can be reused; a live call can never
// be double-spent. Without it an ambiguous teardown blocks BYOK forever.
const activeTTL = 5 * time.Minute

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
	account  string
	expires  time.Time
}

// Fairness bounds stop one admitted principal from monopolizing the shared
// slot (or burning validation work) by repeated reservation attempts.
const (
	fairWindow     = 60 * time.Second
	fairMaxPerUser = 5
	fairMaxTracked = 1024
)

type Store struct {
	mu            sync.Mutex
	origins       map[string]string // exact HTTPS Origin -> matching request Host
	now           func() time.Time
	pending       *reservation
	active        string
	activeExpires time.Time
	admission     Admission
	attempts      map[string][]time.Time
}

// expireActiveLocked clears a stale active slot so an ambiguous teardown
// cannot block BYOK indefinitely. Callers must hold s.mu.
func (s *Store) expireActiveLocked() {
	if s.active != "" && !s.now().Before(s.activeExpires) {
		s.active = ""
	}
}

func (*Store) String() string { return "BYOK reservation store [redacted]" }

func parseOrigins(origins []string) (map[string]string, error) {
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
	return allowed, nil
}

// New permits only an exact HTTPS origin. The loopback Go HTTP listener
// is published solely through a separately owned same-origin APU proxy.
// A store built without a trusted Admission fails closed: header-only
// requests are never enough to allocate the shared pending slot.
func New(origins ...string) (*Store, error) {
	allowed, err := parseOrigins(origins)
	if err != nil {
		return nil, err
	}
	return &Store{origins: allowed, now: time.Now}, nil
}

// NewWithAdmission builds the admitting store used by the BYOK service:
// every reservation must first present a server-verified principal.
func NewWithAdmission(admission Admission, origins ...string) (*Store, error) {
	if admission == nil {
		return nil, reject()
	}
	allowed, err := parseOrigins(origins)
	if err != nil {
		return nil, err
	}
	return &Store{origins: allowed, now: time.Now, admission: admission,
		attempts: make(map[string][]time.Time)}, nil
}

// fairnessLocked reports 0 when the attempt is allowed, 1 when the
// principal exceeded its windowed attempt budget, and 2 when the global
// tracked-principal bound is exhausted. Callers must hold s.mu.
func (s *Store) fairnessLocked(account string) int {
	if s.attempts == nil {
		s.attempts = make(map[string][]time.Time)
	}
	cutoff := s.now().Add(-fairWindow)
	list := s.attempts[account]
	trimmed := list[:0]
	for _, t := range list {
		if t.After(cutoff) {
			trimmed = append(trimmed, t)
		}
	}
	if len(trimmed) == 0 {
		delete(s.attempts, account)
	} else {
		s.attempts[account] = trimmed
	}
	if len(trimmed) >= fairMaxPerUser {
		return 1
	}
	if _, present := s.attempts[account]; !present && len(s.attempts) >= fairMaxTracked {
		return 2
	}
	s.attempts[account] = append(s.attempts[account], s.now())
	return 0
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
	// Trusted-boundary admission BEFORE any shared slot state is allocated.
	// Client-controlled headers above are supporting checks only; the sole
	// identity source is the verified session assertion. Without a trusted
	// Admission the store fails closed instead of trusting headers.
	if s.admission == nil {
		refuse(http.StatusServiceUnavailable)
		return
	}
	principal, admitted := s.admission.Admit(r)
	if !admitted {
		refuse(http.StatusUnauthorized)
		return
	}
	s.mu.Lock()
	switch s.fairnessLocked(principal.Account) {
	case 1:
		s.mu.Unlock()
		refuse(http.StatusTooManyRequests)
		return
	case 2:
		s.mu.Unlock()
		refuse(http.StatusServiceUnavailable)
		return
	}
	s.mu.Unlock()
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
	s.expireActiveLocked()
	if s.pending != nil || s.active != "" {
		refuse(http.StatusConflict)
		return
	}
	s.pending = &reservation{identity: input.Identity, password: []byte(input.Password),
		target: input.Destination, nonce: input.Nonce, account: principal.Account,
		expires: s.now().Add(45 * time.Second)}
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
	s.expireActiveLocked()
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
	s.activeExpires = s.now().Add(activeTTL)
	return out, nil
}

// Complete unlocks the next call only after a definite local cleanup.
// Ambiguous BYE or delivery leaves active set for explicit reconciliation;
// there is never an automatic retry of the same nonce.
func (s *Store) Complete(nonce string, settled bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireActiveLocked()
	if !settled || s.active == "" || subtle.ConstantTimeCompare([]byte(s.active), []byte(nonce)) != 1 {
		return reject()
	}
	s.active = ""
	return nil
}
