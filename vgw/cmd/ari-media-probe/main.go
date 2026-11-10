// Command ari-media-probe sends ONE bounded synthetic PCMA stream to a fixed
// Local/Echo target in the isolated, loopback-only Asterisk lab. It does not
// dial a provider, connect SIP media, or log payload bytes.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"time"

	"example.com/ata/voip-gateway/internal/asterisk"
	"example.com/ata/voip-gateway/internal/serviceconfig"
	"github.com/pion/rtp"
)

const (
	frameBytes = 160 // 20 ms at 8 kHz, G.711 A-law
	maxFrames  = 75  // at most 1.5 seconds of synthetic packets
)

type mediaDiagnostic struct {
	category string
	members  string
}

func (e *mediaDiagnostic) Error() string { return "synthetic RTP " + e.category }

type targetDiagnostic struct {
	cause  error
	status string
}

func (e *targetDiagnostic) Error() string { return e.cause.Error() }

func acceptableReply(raw []byte, from *net.UDPAddr, port int, want []byte) bool {
	if from == nil || !from.IP.Equal(net.IPv4(127, 0, 0, 1)) || from.Port != port ||
		len(raw) < 12+frameBytes || len(raw) > 512 {
		return false
	}
	var packet rtp.Packet
	return packet.Unmarshal(raw) == nil && packet.Version == 2 &&
		packet.PayloadType == 8 && len(packet.Payload) == frameBytes &&
		bytes.Equal(packet.Payload, want)
}

type replyObservations struct {
	fromOtherIP   atomic.Uint32
	fromOtherPort atomic.Uint32
	badFormat     atomic.Uint32
	otherPayload  atomic.Uint32
}

func (o *replyObservations) category() string {
	switch {
	case o.otherPayload.Load() != 0:
		return "payload-mismatch"
	case o.badFormat.Load() != 0:
		return "format-mismatch"
	case o.fromOtherPort.Load() != 0:
		return "port-mismatch"
	case o.fromOtherIP.Load() != 0:
		return "source-mismatch"
	default:
		return "no-packets"
	}
}

func observe(ctx context.Context, socket *net.UDPConn, port int, payload []byte, stats *replyObservations) <-chan struct{} {
	found := make(chan struct{}, 1)
	go func() {
		var buf [513]byte
		for ctx.Err() == nil {
			_ = socket.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, from, err := socket.ReadFromUDP(buf[:])
			if err != nil {
				if ctx.Err() != nil || !errors.Is(err, os.ErrDeadlineExceeded) {
					return
				}
				continue
			}
			if acceptableReply(buf[:n], from, port, payload) {
				found <- struct{}{}
				return
			}
			switch {
			case from == nil || !from.IP.Equal(net.IPv4(127, 0, 0, 1)):
				stats.fromOtherIP.Add(1)
			case from.Port != port:
				stats.fromOtherPort.Add(1)
			case n < 12+frameBytes || n > 512:
				stats.badFormat.Add(1)
			default:
				var packet rtp.Packet
				if packet.Unmarshal(buf[:n]) != nil || packet.Version != 2 ||
					packet.PayloadType != 8 || len(packet.Payload) != frameBytes {
					stats.badFormat.Add(1)
				} else {
					stats.otherPayload.Add(1)
				}
			}
		}
	}()
	return found
}

// Observe membership without media injection. Only Asterisk-owned ARI
// resource IDs are queried; no channel names, response bodies or IDs log.
func checkBridgeDuringWindow(ctx context.Context, read func(context.Context) (string, error)) error {
	everBoth := false
	for i := 0; i < 10; i++ {
		membership, err := read(ctx)
		if err != nil {
			return errors.New("ARI bridge membership read failed")
		}
		if membership == "both" {
			everBoth = true
		}
		if i == 9 {
			if membership == "both" {
				return nil
			}
			if everBoth {
				return errors.New("ARI target departed bridge")
			}
			return errors.New("ARI target never joined bridge")
		}
		select {
		case <-ctx.Done():
			return errors.New("ARI bridge membership read failed")
		case <-time.After(100 * time.Millisecond):
		}
	}
	return errors.New("ARI bridge membership read failed")
}

func run(ctx context.Context, controlOnly bool, peerPath string, ariPort int) (result error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ariPeer, err := serviceconfig.ReadLabARIPeerCertificate(peerPath)
	if err != nil {
		return errors.New("ARI peer provisioning unavailable")
	}
	client, err := asterisk.New(asterisk.Config{
		BaseURL: fmt.Sprintf("https://127.0.0.1:%d", ariPort), PeerCertificate: ariPeer, Username: os.Getenv("GATEWAY_LAB_ARI_USER"),
		Password: os.Getenv("GATEWAY_LAB_ARI_PASSWORD"), Timeout: 2 * time.Second,
	})
	if err != nil {
		return errors.New("media configuration unavailable")
	}
	defer client.Close()
	gone, err := client.Subscribe(ctx)
	if err != nil {
		return err
	}
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return errors.New("media socket unavailable")
	}
	defer socket.Close()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return errors.New("media random source unavailable")
	}
	session, err := client.Start(ctx, hex.EncodeToString(id[:]), socket)
	if err != nil {
		return err
	}
	defer func() {
		if session.Close() != nil {
			result = errors.New("ARI owned resource cleanup incomplete")
		}
	}()
	if controlOnly {
		if err := checkBridgeDuringWindow(ctx, session.BridgeMemberClass); err != nil {
			status, readErr := session.TargetStatusClass(ctx)
			if readErr != nil {
				status = "unavailable"
			}
			return &targetDiagnostic{cause: err, status: status}
		}
		return nil
	}
	// A random synthetic, non-speech PCMA frame ensures an unrelated RTP
	// packet cannot masquerade as a round-trip. It exists only in memory.
	var payload [frameBytes]byte
	var seed [10]byte
	if _, err := rand.Read(payload[:]); err != nil {
		return errors.New("media random source unavailable")
	}
	if _, err := rand.Read(seed[:]); err != nil {
		return errors.New("media random source unavailable")
	}
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: session.LocalPort}
	stats := &replyObservations{}
	found := observe(ctx, socket, session.LocalPort, payload[:], stats)
	clock := time.NewTicker(20 * time.Millisecond)
	defer clock.Stop()
	for i := 0; i < maxFrames; i++ {
		packet := rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 8,
			SequenceNumber: binary.BigEndian.Uint16(seed[:2]) + uint16(i),
			Timestamp:      binary.BigEndian.Uint32(seed[2:6]) + uint32(frameBytes*i),
			SSRC:           binary.BigEndian.Uint32(seed[6:])}, Payload: payload[:]}
		wire, err := packet.Marshal()
		if err != nil || len(wire) != 12+frameBytes {
			return errors.New("synthetic RTP frame unavailable")
		}
		if _, err := socket.WriteToUDP(wire, peer); err != nil {
			return errors.New("synthetic RTP send unavailable")
		}
		select {
		case <-found:
			return nil
		case err := <-gone:
			if err != nil {
				return err
			}
			return errors.New("ARI Stasis subscription lost")
		case <-ctx.Done():
			return errors.New("synthetic RTP deadline exceeded")
		case <-clock.C:
		}
	}
	select {
	case <-found:
		return nil
	case <-time.After(250 * time.Millisecond):
		members, err := session.BridgeMemberClass(ctx)
		if err != nil {
			members = "unavailable"
		}
		return &mediaDiagnostic{category: stats.category(), members: members}
	case <-ctx.Done():
		return errors.New("synthetic RTP deadline exceeded")
	}
}

func main() {
	peerPath := flag.String("ari-peer-cert", "", "absolute owner-controlled public leaf certificate path")
	ariPort := flag.Int("ari-port", 8089, "local IPv4-loopback ARI HTTPS port")
	controlOnly := flag.Bool("control-only", false, "guest-only ARI bridge lifetime diagnostic; sends no RTP")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := run(ctx, *controlOnly, *peerPath, *ariPort); err != nil {
		category := asterisk.ErrorCategory(err)
		if category == "other" {
			switch err.Error() {
			case "ARI target never joined bridge":
				category = "target-never-joined"
			case "ARI target departed bridge":
				category = "target-departed"
			case "ARI bridge membership read failed":
				category = "bridge-read"
			case "synthetic RTP no-packets", "synthetic RTP source-mismatch",
				"synthetic RTP port-mismatch", "synthetic RTP format-mismatch",
				"synthetic RTP payload-mismatch":
				category = err.Error()[len("synthetic RTP "):]
			case "synthetic RTP deadline exceeded":
				category = "timeout"
			default:
				category = "media-local"
			}
		}
		members := "unavailable"
		var diagnostic *mediaDiagnostic
		if errors.As(err, &diagnostic) {
			switch diagnostic.members {
			case "both", "media-only", "target-only", "none":
				members = diagnostic.members
			}
		}
		status := "unavailable"
		var target *targetDiagnostic
		if errors.As(err, &target) {
			switch target.status {
			case "up-stasis", "up-other", "down-stasis", "down-other":
				status = target.status
			}
		}
		slog.Error("guest-only local ARI diagnostic refused", "category", category,
			"membership", members, "target_status", status)
		os.Exit(1)
	}
	if *controlOnly {
		slog.Info("guest-only ARI target retained in bridge; no RTP sent")
		return
	}
	slog.Info("guest-only Local/Echo synthetic RTP round-trip PASS; SIP media NOT tested")
}
