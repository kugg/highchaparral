// Command ari-probe performs ONE fixed loopback ARI bridge/external-media test.
// It does not register, dial a phone, send audio, or contact Eventphone.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"example.com/ata/voip-gateway/internal/asterisk"
	"example.com/ata/voip-gateway/internal/serviceconfig"
)

func main() {
	peerPath := flag.String("ari-peer-cert", "", "absolute owner-controlled public leaf certificate path")
	ariPort := flag.Int("ari-port", 8089, "local IPv4-loopback ARI HTTPS port")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	peer, err := serviceconfig.ReadLabARIPeerCertificate(*peerPath)
	if err != nil {
		slog.Error("local ARI peer provisioning unavailable")
		os.Exit(1)
	}
	client, err := asterisk.New(asterisk.Config{
		BaseURL: fmt.Sprintf("https://127.0.0.1:%d", *ariPort), PeerCertificate: peer, Username: os.Getenv("GATEWAY_LAB_ARI_USER"),
		Password: os.Getenv("GATEWAY_LAB_ARI_PASSWORD"), Timeout: 2 * time.Second,
	})
	if err != nil {
		slog.Error("local ARI probe configuration unavailable")
		os.Exit(1)
	}
	defer client.Close()
	subscription, err := client.Subscribe(ctx)
	if err != nil {
		slog.Error("local ARI Stasis subscription refused", "category", asterisk.ErrorCategory(err))
		os.Exit(1)
	}
	select {
	case err := <-subscription:
		slog.Error("local ARI Stasis subscription lost", "category", asterisk.ErrorCategory(err))
		os.Exit(1)
	default:
	}
	media, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		slog.Error("local probe media socket unavailable")
		os.Exit(1)
	}
	defer media.Close()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		slog.Error("local probe ID unavailable")
		os.Exit(1)
	}
	session, err := client.Start(ctx, hex.EncodeToString(id[:]), media)
	if err != nil {
		slog.Error("local ARI probe rejected", "category", asterisk.ErrorCategory(err))
		os.Exit(1)
	}
	if err := session.Close(); err != nil {
		slog.Error("local ARI probe cleanup incomplete", "category", asterisk.ErrorCategory(err))
		os.Exit(1)
	}
	select {
	case err := <-subscription:
		if err != nil {
			slog.Error("local ARI Stasis subscription lost", "category", asterisk.ErrorCategory(err))
			os.Exit(1)
		}
	default:
	}
	slog.Info("local ARI bridge/external-media/Local-Echo probe passed; no audio assertion")
}
