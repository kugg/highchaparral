// Package softphone joins the browser ARI admission to a single transient
// BYOK reservation. It cannot construct or retry a provider INVITE itself.
package softphone

import (
	"context"
	"errors"
	"time"

	"example.com/ata/voip-gateway/internal/asterisk"
	"example.com/ata/voip-gateway/internal/byok"
)

type Reader interface {
	ReadBrowserDial(context.Context, asterisk.BrowserStart) (asterisk.BrowserDial, error)
}

type Journal interface {
	Begin(string) error
	End(string) error
}

// Provider must place exactly one bounded SIP/TLS call with an independent
// media leg, and report settled=true ONLY after definite local cleanup.
// An ambiguous BYE/ACK/ARI orphan keeps the BYOK Store blocked.
type Provider func(context.Context, byok.Credentials, asterisk.BrowserDial) (settled bool, err error)

type Coordinator struct {
	Store      *byok.Store
	Reader     Reader
	Call       Provider
	Journal    Journal
	Milestones *byok.Milestones // fixed-category, durable, no caller data
}

func refused() error { return errors.New("softphone call admission refused or ambiguous") }

// Handle starts with an ARI event, not browser-provided URI/SDP. The Store
// owns one active slot. No Eventphone credential comes from Asterisk. The
// browser Stasis socket must still be live both before and after readback;
// disconnect cancels the provider context, never triggers redial.
func (c *Coordinator) Handle(ctx context.Context, start asterisk.BrowserStart, gone <-chan error) error {
	if c == nil || c.Store == nil || c.Reader == nil || c.Call == nil || c.Journal == nil || gone == nil {
		return refused()
	}
	select {
	case <-gone:
		return refused()
	default:
	}
	readCtx, stopRead := context.WithTimeout(ctx, 3*time.Second)
	dial, err := c.Reader.ReadBrowserDial(readCtx, start)
	stopRead()
	if err != nil || dial.ChannelID != start.ChannelID ||
		(start.Nonce != "" && dial.Nonce != start.Nonce) {
		return refused()
	}
	select {
	case <-gone:
		return refused()
	default:
	}
	creds, err := c.Store.Consume(dial.Nonce, dial.Destination)
	if err != nil {
		return refused()
	}
	defer creds.Clear()
	if c.Journal.Begin(dial.Nonce) != nil {
		return refused() // no provider network; active slot remains blocked
	}
	if c.Milestones != nil && c.Milestones.Mark(byok.AdmissionReady) != nil {
		return refused() // durable intent exists; no provider operation began
	}
	callCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	finished := make(chan struct{})
	go func() {
		select {
		case <-gone:
			cancel()
		case <-finished:
		}
	}()
	settled, err := c.Call(callCtx, creds, dial)
	close(finished)
	if err != nil || !settled || callCtx.Err() != nil {
		if c.Milestones != nil {
			_ = c.Milestones.Mark(byok.CallAmbiguous)
		}
		return refused()
	}
	if c.Journal.End(dial.Nonce) != nil || c.Store.Complete(dial.Nonce, true) != nil {
		if c.Milestones != nil {
			_ = c.Milestones.Mark(byok.CallAmbiguous)
		}
		return refused()
	}
	if c.Milestones != nil && c.Milestones.Mark(byok.CallSettled) != nil {
		return refused()
	}
	return nil
}
