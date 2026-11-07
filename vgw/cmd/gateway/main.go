package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"

	"example.com/ata/voip-gateway/internal/loopback"
)

func main() {
	port := flag.Int("port", 5070, "loopback-only UDP SIP listening port")
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := loopback.Run(ctx, *port); err != nil && !errors.Is(err, context.Canceled) {
		slog.Error("local SIP service stopped")
		os.Exit(1)
	}
}
