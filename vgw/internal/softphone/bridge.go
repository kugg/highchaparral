package softphone

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"sync/atomic"
	"time"

	"example.com/ata/voip-gateway/internal/asterisk"
	"example.com/ata/voip-gateway/internal/byok"
	"example.com/ata/voip-gateway/internal/calls"
	"example.com/ata/voip-gateway/internal/provider"
)

// Bridge owns one local ARI bridge, a separate UDP socket and one provider
// leg. It cannot originate to another office endpoint or forward browser
// SIP/SDP/RTP headers to Eventphone. The short-lived BYOK reservation must
// already have been consumed by Coordinator.Handle.
type Bridge struct {
	ARI             *asterisk.Client
	ProviderProfile provider.Profile
	Milestones      *byok.Milestones // fixed-category one-use call progress
	// Connector defaults to provider.Call; synthetic tests replace ONLY it.
	Connector func(context.Context, provider.Profile, byok.Credentials, string,
		<-chan calls.AudioFrame, chan<- calls.AudioFrame) (bool, error)
}

func (b *Bridge) Call(ctx context.Context, credentials byok.Credentials,
	dial asterisk.BrowserDial) (settled bool, err error) {
	if b == nil || b.ARI == nil || dial.ChannelID == "" || dial.Nonce == "" ||
		credentials.Target != dial.Destination {
		return false, errors.New("owned BYOK media bridge unavailable")
	}
	mark := func(step byok.Milestone) error {
		if b.Milestones != nil {
			return b.Milestones.Mark(step)
		}
		return nil // isolated synthetic tests do not persist production milestones
	}
	if mark(byok.BridgeStart) != nil {
		return false, errors.New("owned browser bridge progress unavailable")
	}
	var seed [16]byte
	if _, e := rand.Read(seed[:]); e != nil {
		return false, errors.New("owned media ID unavailable")
	}
	id := hex.EncodeToString(seed[:])
	media, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		return false, errors.New("owned browser media socket unavailable")
	}
	defer media.Close()
	start := asterisk.BrowserStart{ChannelID: dial.ChannelID, Nonce: dial.Nonce}
	session, e := b.ARI.AttachBrowser(ctx, start, media)
	if e != nil {
		_ = mark(byok.BridgeRefused)
		return false, errors.New("owned browser bridge attachment unavailable")
	}
	defer func() {
		if session.Close() != nil {
			settled = false
			err = errors.New("owned browser bridge cleanup ambiguous")
			_ = mark(byok.BridgeCloseFailed)
		} else if mark(byok.BridgeClosed) != nil {
			settled = false
			err = errors.New("owned browser bridge progress unavailable")
		}
	}()
	if mark(byok.BridgeAttached) != nil {
		return false, errors.New("owned browser bridge progress unavailable")
	}
	fromARI := make(chan calls.AudioFrame, 4)
	toARI := make(chan calls.AudioFrame, 4)
	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopRelay, e := session.StartBrowserRelay(relayCtx, id, media,
		asterisk.Frames{FromSIP: toARI, ToSIP: fromARI})
	if e != nil {
		return false, errors.New("owned browser media relay unavailable")
	}
	defer func() {
		cancel()
		if stopRelay() != nil {
			settled = false
			err = errors.New("owned browser media cleanup ambiguous")
		}
	}()
	// The browser may hang up at any time. One bounded read-only ARI check
	// per second cancels provider media on missing/changed browser channel.
	callCtx, stopCall := context.WithCancel(ctx)
	defer stopCall()
	finished := make(chan struct{})
	monitorDone := make(chan struct{})
	var callerGone, readbackUnknown atomic.Bool
	go func() {
		defer close(monitorDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-finished:
				return
			case <-callCtx.Done():
				return
			case <-ticker.C:
				check, cancelCheck := context.WithTimeout(callCtx, 750*time.Millisecond)
				class, checkErr := b.ARI.BrowserChannelClass(check, start)
				cancelCheck()
				if checkErr != nil {
					readbackUnknown.Store(true)
					stopCall()
					return
				}
				if class == "gone" {
					callerGone.Store(true)
					stopCall() // never initiate another SIP operation
					return
				}
			}
		}
	}()
	profile := b.ProviderProfile
	profile.OnMilestone = mark
	profile.OnAnswer = func(active context.Context) error {
		return b.ARI.AnswerBrowser(active, start) // exactly one answer after verified provider SDP
	}
	connector := b.Connector
	if connector == nil {
		connector = provider.Call
	}
	if mark(byok.ProviderStart) != nil {
		return false, errors.New("owned provider progress unavailable")
	}
	settled, err = connector(callCtx, profile, credentials, id, fromARI, toARI)
	close(finished)
	select {
	case <-monitorDone:
	case <-time.After(time.Second):
		return false, errors.New("browser channel monitor cleanup ambiguous")
	}
	if readbackUnknown.Load() || (callCtx.Err() != nil && !callerGone.Load()) {
		return false, errors.New("browser call ended or ARI subscription lost")
	}
	return settled, err
}
