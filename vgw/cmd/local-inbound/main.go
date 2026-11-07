// Command local-inbound runs the M2 local test listener without provider
// registration, outbound dialling, or Asterisk connectivity.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"example.com/ata/voip-gateway/internal/calls"
)

func main() {
	port := flag.Int("port", 5080, "IPv4-loopback UDP SIP listening port")
	ackTimeout := flag.Duration("ack-timeout", 5*time.Second, "fail-closed deadline for missing ACK (25ms–10s)")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	conf := calls.Config{Port: *port, DialedUser: "desk", Destination: calls.Desk,
		OfferTimeout: 3 * time.Second, ACKTimeout: *ackTimeout, MaxCall: 30 * time.Second}
	s, err := calls.New(conf)
	if err != nil {
		slog.Error("invalid local call policy")
		os.Exit(1)
	}
	defer s.Close()
	go func() {
		for {
			select {
			case e := <-s.Events():
				// Locally generated ID and fixed enum only; no SIP data.
				slog.Info("local call event", "id", e.ID, "kind", int(e.Kind))
			case <-ctx.Done():
				return
			}
		}
	}()
	if err := s.Serve(ctx); err != nil && !errors.Is(err, context.Canceled) {
		if errors.Is(err, calls.ErrACKTimeout) {
			// os.Exit deliberately bypasses deferred cleanup: the library
			// cannot unwind its ACK wait. The OS reclaims all sockets.
			slog.Error("local ACK deadline; stopping process")
		} else {
			slog.Error("local inbound service stopped")
		}
		os.Exit(1)
	}
}
