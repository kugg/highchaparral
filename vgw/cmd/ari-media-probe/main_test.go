package main

import (
	"context"
	"net"
	"testing"

	"github.com/pion/rtp"
)

func TestAcceptOnlyOwnedPCMAEchoFromAssignedLoopbackPort(t *testing.T) {
	payload := make([]byte, frameBytes)
	for i := range payload {
		payload[i] = byte(i ^ 0x5a)
	}
	packet := rtp.Packet{Header: rtp.Header{Version: 2, PayloadType: 8}, Payload: payload}
	raw, err := packet.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	from := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18500}
	if !acceptableReply(raw, from, from.Port, payload) {
		t.Fatal("synthetic PCMA packet from owned peer rejected")
	}
	badPayload := append([]byte(nil), payload...)
	badPayload[0] ^= 1
	for _, bad := range []struct {
		raw  []byte
		from *net.UDPAddr
		port int
		want []byte
	}{
		{raw, from, from.Port, badPayload},
		{raw, from, from.Port + 1, payload},
		{raw, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2), Port: from.Port}, from.Port, payload},
		{raw[:11], from, from.Port, payload},
		{make([]byte, 513), from, from.Port, payload},
	} {
		if acceptableReply(bad.raw, bad.from, bad.port, bad.want) {
			t.Fatal("unowned, malformed or incorrect synthetic RTP accepted")
		}
	}
	packet.PayloadType = 101 // DTMF cannot pass as PCMA.
	raw, err = packet.Marshal()
	if err != nil || acceptableReply(raw, from, from.Port, payload) {
		t.Fatal("DTMF packet accepted as synthetic audio")
	}
}

func TestBridgeLifetimeSeparatesNeverJoinedFromDeparted(t *testing.T) {
	for _, test := range []struct {
		name  string
		first string
		final string
		want  string
	}{
		{"stable", "both", "both", ""},
		{"never", "media-only", "media-only", "ARI target never joined bridge"},
		{"departed", "both", "media-only", "ARI target departed bridge"},
	} {
		t.Run(test.name, func(t *testing.T) {
			seen := 0
			result := checkBridgeDuringWindow(context.Background(), func(context.Context) (string, error) {
				seen++
				if seen == 10 {
					return test.final, nil
				}
				return test.first, nil
			})
			if test.want == "" && result != nil || test.want != "" && (result == nil || result.Error() != test.want) {
				t.Fatal("incorrect sanitized ARI bridge lifecycle classification")
			}
		})
	}
}
