// Package provider owns one outbound BYOK SIP/TLS and PCMA media leg.
// It cannot accept inbound SIP, choose a browser destination or redial.
package provider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"regexp"
	"time"

	"example.com/ata/voip-gateway/internal/byok"
	"example.com/ata/voip-gateway/internal/calls"
	"example.com/ata/voip-gateway/internal/safesip"
	"github.com/emiago/diago"
	"github.com/emiago/diago/media"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

type Profile struct {
	Host     string
	TLSName  string
	Port     int
	BindIPv4 string
	Roots    *x509.CertPool
	// OnAnswer admits the browser only after provider SDP/PCMA is verified.
	// It must make at most one owned ARI answer request, never redial SIP.
	OnAnswer func(context.Context) error
	// Fixed-category, fsynced progress; never passes upstream data or secrets.
	OnMilestone func(byok.Milestone) error
	// Only same-package synthetic tests can permit localhost SDP/TLS.
	allowLoopback bool
}

func refuse() error { return errors.New("provider BYOK call unavailable or ambiguous") }

// inviteFailureMilestone extracts ONLY an allowlisted numeric response from
// typed sipgo errors. Never call err.Error(): a SIP Reason can contain
// upstream-controlled text, CRLF, account or display-name data.
func inviteFailureMilestone(err error) byok.Milestone {
	var pointer *sipgo.ErrDialogResponse
	var value sipgo.ErrDialogResponse
	var code int
	if errors.As(err, &pointer) && pointer != nil && pointer.Res != nil {
		code = int(pointer.Res.StatusCode)
	} else if errors.As(err, &value) && value.Res != nil {
		code = int(value.Res.StatusCode)
	}
	switch code {
	case 403:
		return byok.InviteStatus403
	case 404:
		return byok.InviteStatus404
	case 480:
		return byok.InviteStatus480
	case 486:
		return byok.InviteStatus486
	case 488:
		return byok.InviteStatus488
	case 500:
		return byok.InviteStatus500
	case 503:
		return byok.InviteStatus503
	}
	if code >= 300 && code <= 699 {
		return byok.InviteOtherStatus
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return byok.InviteTimeout
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return byok.InviteTimeout
	}
	return byok.InviteOtherError
}

// Call makes at most one REGISTER and one authenticated INVITE. It routes
// only owned 160-byte PCMA frames, never SIP/SDP/RTP headers, to/from ARI.
// settled is true only when BYE, unregister and local media cleanup succeed;
// the separate ARI bridge cleanup must ALSO succeed before releasing the
// BYOK Store. No error contains an upstream header, credential or number.
func Call(ctx context.Context, p Profile, c byok.Credentials, callID string,
	fromARI <-chan calls.AudioFrame, toARI chan<- calls.AudioFrame) (settled bool, err error) {
	if p.Roots == nil || p.Port < 1 || p.Port > 65535 || p.Host == "" || p.TLSName == "" ||
		net.ParseIP(p.BindIPv4).To4() == nil || fromARI == nil || toARI == nil ||
		!regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(callID) ||
		!regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`).MatchString(c.Identity) ||
		!regexp.MustCompile(`^[0-9]{2,5}$`).MatchString(c.Target) || len(c.Password) == 0 || len(c.Password) > 256 ||
		(!p.allowLoopback && (p.Host != "hg.eventphone.de" || p.TLSName != p.Host ||
			net.ParseIP(p.BindIPv4).IsLoopback())) {
		return false, refuse()
	}
	for _, b := range c.Password {
		if b < '!' || b > '~' {
			return false, refuse()
		}
	}
	mark := func(step byok.Milestone) bool {
		return p.OnMilestone == nil || p.OnMilestone(step) == nil
	}
	if !mark(byok.RegisterStart) {
		return false, refuse() // no provider transaction started
	}
	ua, e := sipgo.NewUA(sipgo.WithUserAgenTLSConfig(&tls.Config{
		MinVersion: tls.VersionTLS12, RootCAs: p.Roots, ServerName: p.TLSName,
	}), sipgo.WithUserAgentTransportLayerOptions(sip.WithTransportLayerLogger(safesip.Logger)),
		sipgo.WithUserAgentTransactionLayerOptions(sip.WithTransactionLayerLogger(safesip.Logger),
			sip.WithTransactionLayerUnhandledResponseHandler(func(*sip.Response) {})))
	if e != nil {
		return false, refuse()
	}
	defer ua.Close()
	dg := diago.NewDiago(ua, diago.WithTransport(diago.Transport{
		Transport: "tls", BindHost: p.BindIPv4, BindPort: 0,
	}), diago.WithMediaConfig(diago.MediaConfig{Codecs: []media.Codec{media.CodecAudioAlaw}}),
		diago.WithLogger(safesip.Logger))
	uri := sip.Uri{Scheme: "sips", User: c.Identity, Host: p.Host, Port: p.Port}
	uri.UriParams = sip.NewParams()
	uri.UriParams.Add("transport", "tls")
	password := string(c.Password) // pinned SIP library requires an immutable string
	register, e := dg.RegisterTransaction(ctx, uri, diago.RegisterOptions{
		Username: c.Identity, Password: password, Expiry: 90 * time.Second,
	})
	if e != nil {
		_ = mark(byok.RegisterRefused)
		return false, refuse()
	}
	regCtx, cancelReg := context.WithTimeout(ctx, 8*time.Second)
	e = register.Register(regCtx)
	cancelReg()
	if e != nil {
		_ = mark(byok.RegisterRefused)
		return false, refuse()
	}
	registered := true
	byeOK, unregisterOK, mediaOK := false, false, false
	milestonesOK := true
	defer func() {
		if registered {
			if !mark(byok.UnregisterStart) {
				milestonesOK = false
			}
			stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			unregisterOK = register.Unregister(stop) == nil
			cancel()
			if unregisterOK {
				if !mark(byok.UnregisterOK) {
					milestonesOK = false
				}
			} else {
				_ = mark(byok.UnregisterRefused)
			}
		}
		settled = err == nil && byeOK && unregisterOK && mediaOK && milestonesOK
		if !settled {
			err = refuse()
		}
	}()
	if !mark(byok.RegisterOK) {
		return false, refuse()
	}
	to := sip.Uri{Scheme: "sip", User: c.Target, Host: p.Host, Port: p.Port}
	to.UriParams = sip.NewParams()
	to.UriParams.Add("transport", "tls")
	inviteCtx, cancelInvite := context.WithTimeout(ctx, 12*time.Second)
	if !mark(byok.InviteStart) {
		cancelInvite()
		return false, refuse()
	}
	call, e := dg.Invite(inviteCtx, to, diago.InviteOptions{
		Transport: "tls", Username: c.Identity, Password: password,
	})
	cancelInvite()
	if e != nil {
		_ = mark(inviteFailureMilestone(e))
		_ = mark(byok.InviteRefused)
		return false, refuse()
	}
	defer func() {
		if !mark(byok.ByeStart) {
			milestonesOK = false
		}
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		byeOK = call.Hangup(stop) == nil
		cancel()
		if call.Close() != nil {
			byeOK = false
		}
		if byeOK {
			if !mark(byok.ByeOK) {
				milestonesOK = false
			}
		} else {
			_ = mark(byok.ByeRefused)
		}
	}()
	if !mark(byok.InviteAnswered) {
		return false, refuse()
	}
	session := call.MediaSession()
	if session == nil || session.Raddr.IP.To4() == nil || session.Raddr.Port < 1 ||
		(!p.allowLoopback && (session.Raddr.IP.IsPrivate() || session.Raddr.IP.IsLoopback() ||
			session.Raddr.IP.IsMulticast() || session.Raddr.IP.IsUnspecified())) {
		return false, refuse()
	}
	codecs := session.CommonCodecs()
	if len(codecs) != 1 || codecs[0].PayloadType != 8 {
		return false, refuse()
	}
	reader, e := call.AudioReader()
	if e != nil {
		return false, refuse()
	}
	writer, e := call.AudioWriter()
	if e != nil {
		return false, refuse()
	}
	if p.OnAnswer != nil && p.OnAnswer(ctx) != nil {
		_ = mark(byok.BrowserRefused)
		return false, refuse()
	}
	if !mark(byok.BrowserAnswered) {
		return false, refuse()
	}
	readDone := make(chan error, 1)
	go func() {
		var buf [2048]byte
		for ctx.Err() == nil {
			n, readErr := reader.Read(buf[:])
			if readErr != nil {
				readDone <- refuse()
				return
			}
			from, ok := session.ReadRTPFromAddr.(*net.UDPAddr)
			if !ok || !from.IP.Equal(session.Raddr.IP) || from.Port != session.Raddr.Port ||
				n != 160 || call.RTPPacketReader.PacketHeader.PayloadType != 8 {
				continue
			}
			var frame calls.AudioFrame
			frame.ID = callID
			copy(frame.Payload[:], buf[:n])
			select {
			case toARI <- frame:
			case <-ctx.Done():
				return
			default: // never block provider RTP on a slow browser
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			mediaOK = true // caller may hang up after fully owned cleanup
			return false, nil
		case <-call.Context().Done():
			return false, refuse() // remote BYE state requires separate confirmation
		case <-readDone:
			return false, refuse()
		case frame, ok := <-fromARI:
			if !ok {
				mediaOK = true
				return false, nil
			}
			if frame.ID != callID {
				continue
			}
			if n, writeErr := writer.Write(frame.Payload[:]); writeErr != nil || n != len(frame.Payload) {
				return false, refuse()
			}
		}
	}
}
