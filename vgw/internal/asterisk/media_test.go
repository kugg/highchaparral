package asterisk

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"example.com/ata/voip-gateway/internal/calls"
	"example.com/ata/voip-gateway/internal/safesip"
	"github.com/emiago/diago"
	"github.com/emiago/diago/media"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/pion/rtp"
)

func packetForTest(t *testing.T, payload []byte, typ uint8, seq uint16) []byte {
	t.Helper()
	p := rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: typ,
		SequenceNumber: seq, Timestamp: uint32(seq) * 160, SSRC: 0x598231ab}, Payload: payload}
	raw, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func FuzzOwnedPCMAReturnPacket(f *testing.F) {
	seed := rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 8,
		SequenceNumber: 42, Timestamp: 6720, SSRC: 0x7191abcd},
		Payload: bytes.Repeat([]byte{0x5a}, 160)}
	valid, err := seed.Marshal()
	if err != nil {
		f.Fatal(err)
	}
	for _, b := range [][]byte{valid, valid[:11], valid[:171],
		{0x80, 101, 0, 1}, bytes.Repeat([]byte{'Z'}, 513)} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18000}
		var source mediaSource
		frame, accepted := source.decodeOwnedPCMA(raw, from, from.Port)
		if _, ok := (&mediaSource{}).decodeOwnedPCMA(raw, from, from.Port+1); ok {
			t.Fatal("untrusted RTP source port accepted")
		}
		if accepted {
			if len(raw) < 172 || len(raw) > 512 {
				t.Fatal("RTP outside bounded wire size accepted")
			}
			var parsed rtp.Packet
			if parsed.Unmarshal(raw) != nil || !bytes.Equal(frame[:], parsed.Payload) {
				t.Fatal("accepted RTP payload differs from owned frame")
			}
			if _, ok := source.decodeOwnedPCMA(raw, from, from.Port); ok {
				t.Fatal("replayed RTP packet accepted")
			}
		}
	})
}

func startMockEcho(t *testing.T, ctx context.Context, socket *net.UDPConn, payload []byte) <-chan struct{} {
	t.Helper()
	reply := packetForTest(t, payload, 8, 7)
	observed := make(chan struct{}, 1)
	go func() {
		var buf [513]byte
		for ctx.Err() == nil {
			_ = socket.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			n, from, err := socket.ReadFromUDP(buf[:])
			if err != nil {
				continue
			}
			var pkt rtp.Packet
			if pkt.Unmarshal(buf[:n]) != nil || pkt.PayloadType != 8 ||
				!bytes.Equal(pkt.Payload, payload) {
				continue
			}
			_, _ = socket.WriteToUDP(reply, from)
			observed <- struct{}{}
			return
		}
	}()
	return observed
}

func TestSeparateMediaRelayRejectsUnownedAndMalformedRTP(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gateway := ownedRTP(t)
	asterisk := ownedRTP(t)
	other := ownedRTP(t)
	toGateway := make(chan calls.AudioFrame, 4)
	toSIP := make(chan calls.AudioFrame, 4)
	r, err := startRelay(ctx, localID, gateway, asterisk.LocalAddr().(*net.UDPAddr).Port,
		Frames{FromSIP: toGateway, ToSIP: toSIP})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := r.stop(); err != nil {
			t.Error(err)
		}
	}()
	var frame calls.AudioFrame
	frame.ID = localID
	for i := range frame.Payload {
		frame.Payload[i] = byte((i*57 + 13) & 0xff)
	}
	remote := gateway.LocalAddr().(*net.UDPAddr)
	wrongPort := packetForTest(t, frame.Payload[:], 8, 1)
	_, _ = other.WriteToUDP(wrongPort, remote)
	_, _ = asterisk.WriteToUDP(packetForTest(t, frame.Payload[:], 101, 2), remote)
	_, _ = asterisk.WriteToUDP([]byte{0x80, 8, 0}, remote)
	select {
	case <-toSIP:
		t.Fatal("foreign source, DTMF or short RTP crossed into SIP")
	case <-time.After(100 * time.Millisecond):
	}
	_, err = asterisk.WriteToUDP(packetForTest(t, frame.Payload[:], 8, 3), remote)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-toSIP:
		if got != frame {
			t.Fatal("locally owned frame did not preserve PCMA payload")
		}
	case <-time.After(time.Second):
		t.Fatal("valid RTP from owned Asterisk port did not enter SIP frame lane")
	}
	_, _ = asterisk.WriteToUDP(packetForTest(t, frame.Payload[:], 8, 3), remote)  // replay
	_, _ = asterisk.WriteToUDP(packetForTest(t, frame.Payload[:], 8, 60), remote) // >50 jump
	select {
	case <-toSIP:
		t.Fatal("replayed or implausibly reordered RTP admitted")
	case <-time.After(100 * time.Millisecond):
	}
	stale := frame
	stale.ID = "abcdef0123456789abcdef0123456789"
	toGateway <- stale
	toGateway <- frame
	_ = asterisk.SetReadDeadline(time.Now().Add(time.Second))
	var wire [513]byte
	n, _, err := asterisk.ReadFromUDP(wire[:])
	if err != nil {
		t.Fatal("owned local Asterisk port did not receive freshly packetized PCMA")
	}
	var pkt rtp.Packet
	if pkt.Unmarshal(wire[:n]) != nil || pkt.Version != 2 || pkt.PayloadType != 8 ||
		!bytes.Equal(pkt.Payload, frame.Payload[:]) || pkt.SSRC == 0x598231ab {
		t.Fatal("outgoing RTP reused untrusted header or changed frame payload")
	}
	select {
	case <-toSIP:
		t.Fatal("outbound media was falsely counted as an echoed reply")
	case <-time.After(80 * time.Millisecond):
	}
	_ = asterisk.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := asterisk.ReadFromUDP(wire[:]); err == nil {
		t.Fatal("old call frame escaped the fixed media boundary")
	}
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	toGateway <- frame
	_ = asterisk.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if _, _, err := asterisk.ReadFromUDP(wire[:]); err == nil {
		t.Fatal("media escaped after owned relay teardown")
	}
}

func TestMockMediaARIHangupCleanupFailureIsNotHiddenOrReplayed(t *testing.T) {
	m := startARI(t, 20000)
	m.failDeletes = true
	c := m.client(t)
	events := make(chan calls.Event, 4)
	for _, kind := range []calls.Kind{calls.Incoming, calls.Ringing, calls.Answered, calls.Ended} {
		events <- calls.Event{ID: localID, Destination: calls.Desk, Kind: kind}
	}
	close(events)
	err := RunWithMedia(context.Background(), events, c, ownedRTP(t), Frames{
		FromSIP: make(chan calls.AudioFrame), ToSIP: make(chan calls.AudioFrame),
	})
	if ErrorCategory(err) != "owned-cleanup" {
		t.Fatal("ARI media session reported success despite failed owned DELETE")
	}
	var origination, deletes int
	for _, step := range m.snapshot() {
		if step == "POST /ari/channels/create" {
			origination++
		}
		if len(step) >= len("DELETE ") && step[:len("DELETE ")] == "DELETE " {
			deletes++
		}
	}
	if origination != 1 || deletes != 3 {
		t.Fatal("ambiguous ARI media teardown was replayed or abandoned")
	}
}

func TestMockMediaControllerCancelCleansActiveBridge(t *testing.T) {
	asterisk := ownedRTP(t)
	m := startARI(t, asterisk.LocalAddr().(*net.UDPAddr).Port)
	c := m.client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	events := make(chan calls.Event, 3)
	for _, kind := range []calls.Kind{calls.Incoming, calls.Ringing, calls.Answered} {
		events <- calls.Event{ID: localID, Destination: calls.Desk, Kind: kind}
	}
	socket := ownedRTP(t)
	fromSIP := make(chan calls.AudioFrame, 1)
	done := make(chan error, 1)
	go func() {
		done <- RunWithMedia(ctx, events, c, socket, Frames{
			FromSIP: fromSIP, ToSIP: make(chan calls.AudioFrame),
		})
	}()
	select {
	case <-m.started:
	case <-ctx.Done():
		t.Fatal("mock ARI active bridge was not established")
	}
	fromSIP <- calls.AudioFrame{ID: localID}
	_ = asterisk.SetReadDeadline(time.Now().Add(time.Second))
	var buf [513]byte
	if _, _, err := asterisk.ReadFromUDP(buf[:]); err != nil {
		t.Fatal("mock media relay was not active before cancellation")
	}
	cancel() // As on subscription loss, cancel without a SIP BYE event.
	select {
	case <-m.cleaned:
	case <-time.After(time.Second):
		t.Fatal("subscription-loss cancellation left an owned bridge")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("mock ARI cancellation failed owned teardown category=%s", ErrorCategory(err))
		}
	case <-time.After(time.Second):
		t.Fatal("mock media controller did not terminate on cancellation")
	}
}

func TestMediaRelaySocketFailureIsReportedWithoutRemoteErrorText(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socket := ownedRTP(t)
	peer := ownedRTP(t)
	r, err := startRelay(ctx, localID, socket, peer.LocalAddr().(*net.UDPAddr).Port,
		Frames{FromSIP: make(chan calls.AudioFrame), ToSIP: make(chan calls.AudioFrame)})
	if err != nil {
		t.Fatal(err)
	}
	_ = socket.Close()
	select {
	case err := <-r.errs:
		if ErrorCategory(err) != "media-relay" {
			t.Fatal("closed local RTP socket did not fail in a fixed category")
		}
	case <-time.After(time.Second):
		t.Fatal("media failure was not detected")
	}
	_ = r.stop()
}

func TestMockSIPToIndependentAsteriskMediaRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	asterisk := ownedRTP(t)
	m := startARI(t, asterisk.LocalAddr().(*net.UDPAddr).Port)
	c := m.client(t)
	gateway := ownedRTP(t)
	m.wantMediaPort = gateway.LocalAddr().(*net.UDPAddr).Port
	probe := ownedRTP(t)
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()
	s, err := calls.New(calls.Config{Port: port, DialedUser: "desk", Destination: calls.Desk,
		OfferTimeout: time.Second, ACKTimeout: time.Second, MaxCall: 5 * time.Second, MediaEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- RunWithMedia(ctx, s.Events(), c, gateway,
			Frames{FromSIP: s.MediaToGateway(), ToSIP: s.MediaFromGateway()})
	}()
	ua, err := sipgo.NewUA()
	if err != nil {
		t.Fatal(err)
	}
	defer ua.Close()
	d := diago.NewDiago(ua,
		diago.WithTransport(diago.Transport{Transport: "udp", BindHost: "127.0.0.1", BindPort: 0}),
		diago.WithMediaConfig(diago.MediaConfig{Codecs: []media.Codec{media.CodecAudioAlaw}}),
		diago.WithLogger(safesip.Logger))
	call, err := d.Invite(ctx, sip.Uri{User: "desk", Host: "127.0.0.1", Port: port}, diago.InviteOptions{})
	if err != nil {
		t.Fatal("synthetic SIP INVITE failed")
	}
	defer call.Close()
	select {
	case <-m.started:
	case <-ctx.Done():
		t.Fatal("mock ARI bridge did not become ready")
	}
	read, err := call.AudioReader()
	if err != nil {
		t.Fatal(err)
	}
	write, err := call.AudioWriter()
	if err != nil {
		t.Fatal(err)
	}
	var payload [160]byte
	for i := range payload {
		payload[i] = byte((i*41 + 77) & 0xff)
	}
	observed := make(chan rtp.Packet, 1)
	go func() {
		var buf [513]byte
		for {
			_ = asterisk.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			n, from, err := asterisk.ReadFromUDP(buf[:])
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			var pkt rtp.Packet
			if pkt.Unmarshal(buf[:n]) != nil || pkt.PayloadType != 8 ||
				!bytes.Equal(pkt.Payload, payload[:]) {
				continue
			}
			observed <- pkt
			_, _ = asterisk.WriteToUDP(packetForTest(t, payload[:], 8, 7), from)
			return
		}
	}()
	received := make(chan []byte, 1)
	go func() {
		var buf [2048]byte
		n, err := read.Read(buf[:])
		if err == nil {
			received <- bytes.Clone(buf[:n])
		}
	}()
	for i := 0; i < 25; i++ {
		if n, err := write.Write(payload[:]); err != nil || n != len(payload) {
			t.Fatal("synthetic SIP media writer stopped")
		}
		select {
		case got := <-received:
			if !bytes.Equal(got, payload[:]) {
				t.Fatal("synthetic SIP audio did not survive independent RTP legs")
			}
			select {
			case packet := <-observed:
				if packet.SSRC == call.RTPPacketWriter.SSRC {
					t.Fatal("SIP RTP identifier leaked to Asterisk")
				}
			case <-ctx.Done():
				t.Fatal("mock Asterisk never received local RTP")
			}
			if err := call.Hangup(ctx); err != nil {
				t.Fatal("synthetic SIP BYE failed")
			}
			select {
			case <-m.cleaned:
			case err := <-done:
				t.Fatalf("ARI controller exited before cleanup: %v", err)
			case <-ctx.Done():
				t.Fatal("owned mock ARI bridge not cleaned")
			}
			cancel()
			if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			return
		default:
		}
	}
	t.Fatal("no synthetic two-way audio through independent RTP sessions")
}
