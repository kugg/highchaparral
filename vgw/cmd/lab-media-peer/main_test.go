package main

import (
	"context"
	"net"
	"testing"
	"time"

	"example.com/ata/voip-gateway/internal/loopback"
)

func TestOneSyntheticPeerCallAgainstLocalEcho(t *testing.T) {
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	_ = probe.Close()
	server, ua, err := loopback.New(port)
	if err != nil {
		t.Fatal(err)
	}
	defer ua.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.ServeBackground(ctx, loopback.Handle); err != nil {
		t.Fatal(err)
	}
	if err := oneCall(ctx, port); err != nil {
		t.Fatal("mock-only synthetic media peer failed to complete exactly one echo call")
	}
}
