// Command lab-media-peer places ONE synthetic loopback SIP call and verifies
// a PCMA frame through a separate gateway and Asterisk RTP leg. No provider,
// credentials, phone number, speech, replay, or raw media logging.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
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

func oneCall(ctx context.Context, port int) (result error) {
	ua, err := sipgo.NewUA(sipgo.WithUserAgentTransportLayerOptions(
		sip.WithTransportLayerLogger(safesip.Logger)))
	if err != nil {
		return errors.New("synthetic SIP user agent unavailable")
	}
	defer ua.Close()
	client := diago.NewDiago(ua,
		diago.WithTransport(diago.Transport{Transport: "udp", BindHost: "127.0.0.1", BindPort: 0}),
		diago.WithMediaConfig(diago.MediaConfig{Codecs: []media.Codec{media.CodecAudioAlaw}}),
		diago.WithLogger(safesip.Logger))
	if err := client.ServeBackground(ctx, func(*diago.DialogServerSession) {}); err != nil {
		return errors.New("synthetic SIP media listener unavailable")
	}
	call, err := client.Invite(ctx, sip.Uri{User: "desk", Host: "127.0.0.1", Port: port}, diago.InviteOptions{})
	if err != nil {
		return errors.New("synthetic SIP call unavailable")
	}
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := call.Hangup(stop); err != nil {
			result = errors.New("synthetic SIP BYE cleanup incomplete")
		}
		_ = call.Close()
	}()
	reader, err := call.AudioReader()
	if err != nil {
		return errors.New("synthetic SIP audio reader unavailable")
	}
	writer, err := call.AudioWriter()
	if err != nil {
		return errors.New("synthetic SIP audio writer unavailable")
	}
	var frame [160]byte
	if _, err := rand.Read(frame[:]); err != nil {
		return errors.New("synthetic media random source unavailable")
	}
	received := make(chan bool, 1)
	go func() {
		var buf [2048]byte
		for ctx.Err() == nil {
			n, err := reader.Read(buf[:])
			if err != nil {
				return
			}
			if n == len(frame) && bytes.Equal(buf[:n], frame[:]) {
				received <- true
				return
			}
		}
	}()
	// ARI create→bridge→dial may take a moment after the SIP ACK. Sending
	// begins only after a fixed, bounded settling interval; at most 75 frames.
	select {
	case <-time.After(300 * time.Millisecond):
	case <-ctx.Done():
		return errors.New("synthetic SIP media deadline exceeded")
	}
	for i := 0; i < 75; i++ {
		if n, err := writer.Write(frame[:]); err != nil || n != len(frame) {
			return errors.New("synthetic SIP PCMA send failed")
		}
		select {
		case <-received:
			return nil
		case <-ctx.Done():
			return errors.New("synthetic SIP media deadline exceeded")
		default:
		}
	}
	select {
	case <-received:
		return nil
	case <-time.After(500 * time.Millisecond):
		return errors.New("synthetic SIP PCMA not returned")
	case <-ctx.Done():
		return errors.New("synthetic SIP media deadline exceeded")
	}
}

func main() {
	port := flag.Int("sip-port", 5080, "isolated guest-only SIP UDP loopback port")
	flag.Parse()
	if *port < 1 || *port > 65535 {
		slog.Error("invalid isolated synthetic SIP port")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := oneCall(ctx, *port); err != nil {
		switch err.Error() {
		case "synthetic SIP PCMA not returned":
			slog.Error("guest SIP/Asterisk audio refused", "category", "no-audio")
		case "synthetic SIP BYE cleanup incomplete":
			slog.Error("guest SIP/Asterisk audio refused", "category", "bye-cleanup")
		default:
			slog.Error("guest SIP/Asterisk audio refused", "category", "other")
		}
		os.Exit(1)
	}
	slog.Info("guest synthetic SIP-to-real-Asterisk PCMA round-trip PASS; no provider or hardware tested")
}
