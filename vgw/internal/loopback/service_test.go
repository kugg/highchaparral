package loopback

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/emiago/diago"
	"github.com/emiago/diago/media"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

// TestInviteAnswerBye performs real SIP over UDP loopback using a separate
// library client, rather than invoking the handler directly.
func TestInviteAnswerBye(t *testing.T) {
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server, serverUA, err := New(port)
	if err != nil {
		t.Fatal(err)
	}
	defer serverUA.Close()
	if err := server.ServeBackground(ctx, Handle); err != nil {
		t.Fatal(err)
	}

	clientUA, err := sipgo.NewUA()
	if err != nil {
		t.Fatal(err)
	}
	defer clientUA.Close()
	client := diago.NewDiago(clientUA,
		diago.WithTransport(diago.Transport{Transport: "udp", BindHost: "127.0.0.1", BindPort: 0}),
		diago.WithMediaConfig(diago.MediaConfig{Codecs: []media.Codec{media.CodecAudioAlaw}}),
	)
	if err := client.ServeBackground(ctx, func(*diago.DialogServerSession) {}); err != nil {
		t.Fatal(err)
	}
	var answered bool
	dialog, err := client.Invite(ctx, sip.Uri{User: "echo", Host: "127.0.0.1", Port: port}, diago.InviteOptions{
		OnResponse: func(res *sip.Response) error {
			if res.StatusCode == sip.StatusOK {
				answered = true
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("INVITE/ACK failed: %v", err)
	}
	defer dialog.Close()
	if !answered || dialog.InviteResponse.StatusCode != sip.StatusOK {
		t.Fatal("no successful INVITE response")
	}
	if err := dialog.Hangup(ctx); err != nil {
		t.Fatalf("BYE failed: %v", err)
	}
	t.Log("PASS: loopback INVITE -> 200 OK -> ACK -> BYE")
}

func TestInvalidPort(t *testing.T) {
	for _, port := range []int{0, -1, 65536} {
		if _, _, err := New(port); err == nil {
			t.Fatalf("accepted port %d", port)
		}
	}
}

func TestLoopbackOfferEgressGuard(t *testing.T) {
	offer := []byte("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio 12000 RTP/AVP 8\r\n")
	if !AllowOffer(offer) {
		t.Fatal("rejected loopback PCMA offer")
	}
	for _, bad := range [][]byte{
		[]byte("\n"),
		[]byte("c=IN IP4 127.0.0.1\r\n\r\n"),
		[]byte("c=IN IP4 127.0.0.1\r\nm=audio 12000 RTP/AVP 8\r\nc=IN IP4 203.0.113.10\r\n"),
		bytes.Replace(offer, []byte("127.0.0.1\r\nt=0"), []byte("203.0.113.10\r\nt=0"), 1),
		bytes.Replace(offer, []byte("RTP/AVP 8"), []byte("RTP/AVP 0"), 1),
	} {
		if AllowOffer(bad) {
			t.Fatal("accepted non-loopback or malformed media offer")
		}
	}
}
