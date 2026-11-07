// Command local-ari-lab is an isolated SIP-to-ARI control experiment.
// It never dials an office phone or connects to a remote PBX.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"example.com/ata/voip-gateway/internal/asterisk"
	"example.com/ata/voip-gateway/internal/calls"
)

func main() {
	sipPort := flag.Int("sip-port", 5080, "local IPv4-loopback UDP SIP port")
	ariPort := flag.Int("ari-port", 8088, "local IPv4-loopback Asterisk ARI HTTP port")
	ackTimeout := flag.Duration("ack-timeout", 5*time.Second, "bounded ACK deadline")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	media, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		slog.Error("local RTP socket unavailable")
		os.Exit(1)
	}
	defer media.Close()
	ariUser, ariPass, err := readARIConfig()
	if err != nil {
		slog.Error("guest-only ARI credential ownership refused")
		os.Exit(1)
	}
	ari, err := asterisk.New(asterisk.Config{
		BaseURL:  fmt.Sprintf("http://127.0.0.1:%d", *ariPort),
		Username: ariUser,
		Password: ariPass,
		Timeout:  2 * time.Second,
	})
	if err != nil {
		slog.Error("invalid local ARI configuration")
		os.Exit(1)
	}
	defer ari.Close()
	subscription, err := ari.Subscribe(ctx)
	if err != nil {
		slog.Error("local ARI Stasis application unavailable", "category", asterisk.ErrorCategory(err))
		os.Exit(1)
	}
	s, err := calls.New(calls.Config{
		Port: *sipPort, DialedUser: "desk", Destination: calls.Desk,
		OfferTimeout: 3 * time.Second, ACKTimeout: *ackTimeout, MaxCall: 30 * time.Second,
		MediaEnabled: true,
	})
	if err != nil {
		slog.Error("invalid local SIP configuration")
		os.Exit(1)
	}
	defer s.Close()
	controller := make(chan error, 1)
	listener := make(chan error, 1)
	controllerDone := false
	waitForCleanup := func() bool {
		if controllerDone {
			return true
		}
		select {
		case <-controller: // Run closes only its owned ARI channels.
			controllerDone = true
			return true
		case <-time.After(6 * time.Second):
			slog.Error("local ARI owned cleanup timed out")
			return false
		}
	}
	go func() {
		controller <- asterisk.RunWithMedia(ctx, s.Events(), ari, media,
			asterisk.Frames{FromSIP: s.MediaToGateway(), ToSIP: s.MediaFromGateway()})
	}()
	go func() { listener <- s.Serve(ctx) }()
	select {
	case err = <-subscription:
		if ctx.Err() == nil {
			slog.Error("local ARI Stasis subscription lost; process failing closed",
				"category", asterisk.ErrorCategory(err))
			stop()
			waitForCleanup()
			os.Exit(1)
		}
	case err = <-controller:
		controllerDone = true
		if err != nil || ctx.Err() == nil {
			slog.Error("local ARI control stopped; process failing closed",
				"category", asterisk.ErrorCategory(err))
			stop()
			os.Exit(1)
		}
	case err = <-listener:
		if err != nil && !errors.Is(err, context.Canceled) {
			slog.Error("local SIP listener stopped; process failing closed")
			stop()
			waitForCleanup()
			os.Exit(1)
		}
	case <-ctx.Done():
	}
	stop()
	if !waitForCleanup() {
		os.Exit(1)
	}
}
