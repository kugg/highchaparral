package asterisk

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"

	"example.com/ata/voip-gateway/internal/calls"
	"github.com/pion/rtp"
)

// Frames is the only media crossing the M2/M4 boundary: locally owned PCMA
// payloads with an opaque local call ID, never SIP objects or external RTP
// headers. Each lane has four frames of capacity in the call service.
type Frames struct {
	FromSIP <-chan calls.AudioFrame
	ToSIP   chan<- calls.AudioFrame
}

// StartBrowserRelay connects ONLY the owned PCMA payload lanes of a
// previously verified browser bridge. The caller supplies a fresh local
// 32-hex call ID shared with the provider leg and MUST stop this relay
// before deleting the bridge. No SIP/SDP/RTP header crosses the boundary.
func (s *Session) StartBrowserRelay(ctx context.Context, id string, socket *net.UDPConn,
	lanes Frames) (func() error, error) {
	if s == nil || s.client == nil || s.client.app != browserApp || s.targetAttempted || s.LocalPort == 0 {
		return nil, errors.New("owned browser media bridge unavailable")
	}
	offered, err := ownedMediaPort(socket)
	if err != nil || offered != s.offeredPort {
		return nil, errors.New("owned browser media socket changed")
	}
	worker, err := startRelay(ctx, id, socket, s.LocalPort, lanes)
	if err != nil {
		return nil, errors.New("owned browser media relay unavailable")
	}
	return worker.stop, nil
}

type relay struct {
	cancel   context.CancelFunc
	stopRead func()
	finished chan struct{}
	errs     chan error
}

type mediaSource struct {
	locked   bool
	ssrc     uint32
	sequence uint16
}

// decodeOwnedPCMA treats UDP and RTP as untrusted. The only output is an
// owned payload, never the sender's header, timing or packet buffer.
func (s *mediaSource) decodeOwnedPCMA(raw []byte, from *net.UDPAddr, port int) ([160]byte, bool) {
	var payload [160]byte
	if from == nil || !from.IP.Equal(net.IPv4(127, 0, 0, 1)) ||
		from.Port != port || len(raw) < 172 || len(raw) > 512 {
		return payload, false
	}
	var packet rtp.Packet
	if packet.Unmarshal(raw) != nil || packet.Version != 2 ||
		packet.PayloadType != 8 || len(packet.Payload) != len(payload) {
		return payload, false
	}
	if s.locked {
		delta := uint16(packet.SequenceNumber - s.sequence)
		if packet.SSRC != s.ssrc || delta == 0 || delta > 50 {
			return payload, false
		}
	}
	s.locked, s.ssrc, s.sequence = true, packet.SSRC, packet.SequenceNumber
	copy(payload[:], packet.Payload)
	return payload, true
}

func (r *relay) stop() error {
	if r == nil {
		return nil
	}
	r.cancel()
	r.stopRead()
	select {
	case <-r.finished:
	case <-time.After(500 * time.Millisecond):
		return errors.New("ARI media relay teardown incomplete")
	}
	select {
	case err := <-r.errs:
		return err
	default:
		return nil
	}
}

func startRelay(parent context.Context, id string, socket *net.UDPConn, port int, lanes Frames) (*relay, error) {
	if !localCallID(id) || port < 1 || port > 65535 || socket == nil ||
		lanes.FromSIP == nil || lanes.ToSIP == nil {
		return nil, errors.New("ARI media relay unavailable")
	}
	if _, err := ownedMediaPort(socket); err != nil {
		return nil, errors.New("ARI media relay unavailable")
	}
	var seed [10]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, errors.New("ARI media relay unavailable")
	}
	ctx, cancel := context.WithCancel(parent)
	r := &relay{cancel: cancel, errs: make(chan error, 2), finished: make(chan struct{}),
		stopRead: func() { _ = socket.SetReadDeadline(time.Now()) }}
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		seq := binary.BigEndian.Uint16(seed[:2])
		timestamp := binary.BigEndian.Uint32(seed[2:6])
		ssrc := binary.BigEndian.Uint32(seed[6:])
		for {
			select {
			case <-ctx.Done():
				return
			case frame, ok := <-lanes.FromSIP:
				if !ok || ctx.Err() != nil {
					return
				}
				if frame.ID != id { // no late frames from a prior dialog
					continue
				}
				pkt := rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 8,
					SequenceNumber: seq, Timestamp: timestamp, SSRC: ssrc}, Payload: frame.Payload[:]}
				wire, err := pkt.Marshal()
				if err != nil || len(wire) != 172 {
					r.errs <- errors.New("ARI media relay failed")
					return
				}
				_ = socket.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
				if n, err := socket.WriteToUDP(wire, peer); err != nil || n != len(wire) {
					if ctx.Err() == nil {
						r.errs <- errors.New("ARI media relay failed")
					}
					return
				}
				seq++
				timestamp += 160
			}
		}
	}()
	go func() {
		defer wg.Done()
		var buf [513]byte
		var source mediaSource
		for ctx.Err() == nil {
			_ = socket.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, from, err := socket.ReadFromUDP(buf[:])
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				if e, ok := err.(net.Error); ok && e.Timeout() {
					continue
				}
				r.errs <- errors.New("ARI media relay failed")
				return
			}
			payload, ok := source.decodeOwnedPCMA(buf[:n], from, port)
			if !ok {
				continue
			}
			frame := calls.AudioFrame{ID: id, Payload: payload}
			select {
			case <-ctx.Done():
				return
			case lanes.ToSIP <- frame:
			default: // bounded queue; discard late media instead of blocking UDP
			}
		}
	}()
	go func() { wg.Wait(); close(r.finished) }()
	return r, nil
}
