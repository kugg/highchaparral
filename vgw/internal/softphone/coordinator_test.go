package softphone

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"example.com/ata/voip-gateway/internal/asterisk"
	"example.com/ata/voip-gateway/internal/byok"
)

const nonce = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type reader func(context.Context, asterisk.BrowserStart) (asterisk.BrowserDial, error)

func (f reader) ReadBrowserDial(ctx context.Context, start asterisk.BrowserStart) (asterisk.BrowserDial, error) {
	return f(ctx, start)
}

func reserved(t *testing.T) *byok.Store {
	t.Helper()
	s, err := byok.New("https://apu.invalid")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://apu.invalid"+byok.Path,
		strings.NewReader(`{"identity":"synthetic","password":"test-only=password","destination":"1234","nonce":"`+nonce+`"}`))
	req.Header.Set("Origin", "https://apu.invalid")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-VGW-Client", "softphone-v1")
	out := httptest.NewRecorder()
	s.ServeHTTP(out, req)
	if out.Code != http.StatusCreated {
		t.Fatal("synthetic BYOK setup failed")
	}
	return s
}

func journal(t *testing.T) *byok.Journal {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	j, err := byok.OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = j.Close() })
	return j
}

func TestBrowserCallConsumesOneBYOKCredentialAfterReadbackAndDefiniteCleanup(t *testing.T) {
	s := reserved(t)
	start := asterisk.BrowserStart{ChannelID: "1693496751.43"}
	var called, checked bool
	c := Coordinator{Store: s, Journal: journal(t),
		Reader: reader(func(_ context.Context, actual asterisk.BrowserStart) (asterisk.BrowserDial, error) {
			checked = actual == start
			return asterisk.BrowserDial{ChannelID: start.ChannelID, Nonce: nonce, Destination: "1234"}, nil
		}),
		Call: func(_ context.Context, creds byok.Credentials, dial asterisk.BrowserDial) (bool, error) {
			called = checked && creds.Identity == "synthetic" &&
				string(creds.Password) == "test-only=password" &&
				dial.Destination == "1234" && dial.ChannelID == start.ChannelID
			return true, nil
		},
	}
	if err := c.Handle(context.Background(), start, make(chan error)); err != nil || !called {
		t.Fatal("owned browser call failed to consume the exact BYOK reservation once")
	}
	if err := c.Handle(context.Background(), start, make(chan error)); err == nil {
		t.Fatal("same event/nonce could call provider twice")
	}
}

func TestBrowserCallRefusesStaleSocketOrChangedDialBeforeProvider(t *testing.T) {
	for _, condition := range []string{"disconnected", "changed-channel", "changed-target"} {
		s := reserved(t)
		start := asterisk.BrowserStart{ChannelID: "1693496751.43"}
		gone := make(chan error)
		if condition == "disconnected" {
			close(gone)
		}
		var called bool
		c := Coordinator{Store: s, Journal: journal(t),
			Reader: reader(func(_ context.Context, _ asterisk.BrowserStart) (asterisk.BrowserDial, error) {
				id, target := start.ChannelID, "1234"
				if condition == "changed-channel" {
					id = "foreign"
				}
				if condition == "changed-target" {
					target = "9876"
				}
				return asterisk.BrowserDial{ChannelID: id, Nonce: nonce, Destination: target}, nil
			}),
			Call: func(context.Context, byok.Credentials, asterisk.BrowserDial) (bool, error) {
				called = true
				return true, nil
			},
		}
		if err := c.Handle(context.Background(), start, gone); err == nil || called {
			t.Fatalf("untrusted browser state %s reached provider", condition)
		}
	}
}

func TestAmbiguousProviderHangupKeepsBYOKCallSlotBlocked(t *testing.T) {
	s := reserved(t)
	start := asterisk.BrowserStart{ChannelID: "1693496751.43"}
	c := Coordinator{Store: s, Journal: journal(t),
		Reader: reader(func(_ context.Context, _ asterisk.BrowserStart) (asterisk.BrowserDial, error) {
			return asterisk.BrowserDial{ChannelID: start.ChannelID, Nonce: nonce, Destination: "1234"}, nil
		}),
		Call: func(context.Context, byok.Credentials, asterisk.BrowserDial) (bool, error) {
			return false, nil
		},
	}
	if err := c.Handle(context.Background(), start, make(chan error)); err == nil {
		t.Fatal("ambiguous provider delivery was accepted")
	}
	req := httptest.NewRequest(http.MethodPost, "https://apu.invalid"+byok.Path,
		strings.NewReader(`{"identity":"synthetic","password":"test-only=password","destination":"1234","nonce":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`))
	req.Header.Set("Origin", "https://apu.invalid")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-VGW-Client", "softphone-v1")
	out := httptest.NewRecorder()
	s.ServeHTTP(out, req)
	if out.Code != http.StatusConflict {
		t.Fatal("new outbound reservation admitted after ambiguous BYE")
	}
}
