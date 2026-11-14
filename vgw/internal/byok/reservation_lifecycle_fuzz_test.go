package byok

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func doReserve(s *Store, nonce, target string, valid bool) string {
	body := fmt.Sprintf(`{"identity":"user-1","password":"pw-1234","destination":%q,"nonce":%q}`, target, nonce)
	if !valid {
		body = `{"identity":"bad identity!!","password":"","destination":"x","nonce":"zz"}`
	}
	req := httptest.NewRequest(http.MethodPost, Path, strings.NewReader(body))
	req.Host = "vgw.invalid"
	req.Header.Set("Origin", "https://vgw.invalid")
	req.Header.Set("X-VGW-Client", "softphone-v1")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return fmt.Sprintf("%d", rec.Code)
}

func hexNonce(a, b byte) string {
	raw := []byte{a, b, a ^ 0x5a, b ^ 0x33, a + 1, b + 2, a ^ 0x0f, b ^ 0xaa,
		a + 3, b + 4, a ^ 0x99, b ^ 0x11, a + 5, b + 6, a ^ 0x77, b ^ 0x22}
	return hex.EncodeToString(raw)
}

func targetFrom(b byte) string {
	return fmt.Sprintf("%d", 10+int(b)%99000)
}

// runSequence drives one bounded lifecycle and asserts the security
// invariants inline, returning a coarse outcome trace for determinism.
func runSequence(t *testing.T, s *Store, data []byte) []string {
	var out []string
	clock := time.Unix(1700000000, 0)
	s.now = func() time.Time { return clock }
	var reservedNonce, reservedTarget, activeNonce string
	pos := 1
	take := func() byte {
		if pos < len(data) {
			b := data[pos]
			pos++
			return b
		}
		return 0
	}
	ops := int(data[0]) % 8
	for i := 0; i < ops; i++ {
		switch take() % 7 {
		case 0:
			nonce, target := hexNonce(take(), take()), targetFrom(take())
			code := doReserve(s, nonce, target, true)
			if code == "201" {
				reservedNonce, reservedTarget = nonce, target
				if s.pending == nil || s.active != "" {
					t.Fatal("reserve succeeded with a live owner already present")
				}
			} else if code == "409" {
				if s.pending == nil && s.active == "" {
					t.Fatal("reserve conflicted while the slot was free")
				}
			}
			out = append(out, "reserve:"+code)
		case 1:
			out = append(out, "reserveBad:"+doReserve(s, "bad", "x", false))
		case 2:
			creds, err := s.Consume(reservedNonce, reservedTarget)
			if err == nil {
				if creds.Target != reservedTarget || s.active != reservedNonce || s.pending != nil || len(creds.Password) == 0 {
					t.Fatal("consume returned credentials without binding the reserved owner")
				}
				activeNonce = reservedNonce
				out = append(out, "consumeMatch:ok")
			} else {
				out = append(out, "consumeMatch:refused")
			}
		case 3:
			before := s.active
			if _, err := s.Consume(strings.Repeat("f", 32), reservedTarget); err == nil || s.active != before {
				t.Fatal("a mismatched owner mutated the reservation")
			}
			out = append(out, "consumeMismatch:refused")
		case 4:
			before := s.active
			err := s.Complete(activeNonce, true)
			if err == nil && s.active != "" {
				t.Fatal("settled complete did not release the active slot")
			}
			if err != nil && before != "" && before == activeNonce && clock.Before(s.activeExpires) {
				t.Fatal("settled complete refused the live active nonce")
			}
			if err == nil {
				activeNonce = ""
			}
			out = append(out, fmt.Sprintf("completeSettled:%v", err == nil))
		case 5:
			before := s.active
			if err := s.Complete(activeNonce, false); err == nil || s.active != before {
				t.Fatal("an unsettled complete released durable state")
			}
			out = append(out, "completeUnsettled:refused")
		case 6:
			clock = clock.Add(time.Duration(1+take()%25) * time.Second)
			out = append(out, "advance")
		}
		if s.pending != nil && s.active != "" {
			t.Fatal("two simultaneous live owners")
		}
	}
	return out
}

// FuzzReservationLifecycle interprets fuzz bytes as a bounded sequence of
// reserve / consume / complete / clock operations and asserts that at most
// one owner controls the slot, mismatched owners cannot mutate a
// reservation, unsettled calls never free durable state early, and the
// state machine neither panics nor diverges across a replay.
func FuzzReservationLifecycle(f *testing.F) {
	f.Add([]byte{0})
	f.Add([]byte{2, 0, 1, 2, 3, 4, 5, 6})
	f.Add([]byte{4, 0, 3, 2, 4, 1, 5, 0})
	f.Add([]byte{7, 1, 1, 3, 5, 3, 5, 6})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < 1 || len(data) > 64 {
			t.Skip()
		}
		s1, err := New("https://vgw.invalid")
		if err != nil {
			t.Fatal(err)
		}
		s2, err := New("https://vgw.invalid")
		if err != nil {
			t.Fatal(err)
		}
		trace1 := runSequence(t, s1, data)
		trace2 := runSequence(t, s2, data)
		if strings.Join(trace1, "|") != strings.Join(trace2, "|") {
			t.Fatal("lifecycle diverged across an identical replay")
		}
	})
}
