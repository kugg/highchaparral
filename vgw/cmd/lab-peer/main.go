// Command lab-peer completes ONE synthetic SIP dialog against local-ari-lab.
// It cannot register, redial, call Eventphone or emit an audio payload.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"time"

	"example.com/ata/voip-gateway/internal/safesip"
	"github.com/emiago/diago"
	"github.com/emiago/diago/media"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

func main() {
	port := flag.Int("sip-port", 5080, "local-only SIP listener port")
	linger := flag.Duration("linger", 2*time.Second, "time for local ARI bridge setup before BYE")
	flag.Parse()
	if *port < 1 || *port > 65535 || *linger < 100*time.Millisecond || *linger > 5*time.Second {
		slog.Error("invalid local lab peer configuration")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	ua, err := sipgo.NewUA(sipgo.WithUserAgentTransportLayerOptions(
		sip.WithTransportLayerLogger(safesip.Logger)))
	if err != nil {
		slog.Error("local SIP user agent unavailable")
		os.Exit(1)
	}
	defer ua.Close()
	client := diago.NewDiago(ua,
		diago.WithTransport(diago.Transport{Transport: "udp", BindHost: "127.0.0.1", BindPort: 0}),
		diago.WithMediaConfig(diago.MediaConfig{Codecs: []media.Codec{media.CodecAudioAlaw}}),
		diago.WithLogger(safesip.Logger))
	dialog, err := client.Invite(ctx, sip.Uri{User: "desk", Host: "127.0.0.1", Port: *port}, diago.InviteOptions{})
	if err != nil {
		slog.Error("local SIP INVITE failed")
		os.Exit(1)
	}
	defer dialog.Close()
	select {
	case <-ctx.Done():
		slog.Error("local SIP dialog timed out")
		os.Exit(1)
	case <-time.After(*linger):
	}
	if err := dialog.Hangup(ctx); err != nil {
		slog.Error("local SIP BYE failed")
		os.Exit(1)
	}
	slog.Info("local synthetic SIP INVITE/ACK/BYE completed; no audio assertion")
}
