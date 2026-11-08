package office

// Provider-free capability proof only: a 200/ACK/BYE dialog on the same
// client-initiated, verified TLS flow used for REGISTER. No RTP is sent,
// no provider or Asterisk is involved and no production service is enabled.

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"example.com/ata/voip-gateway/internal/safesip"
	"github.com/emiago/diago"
	"github.com/emiago/diago/media"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

func syntheticResponse(reader *bufio.Reader, status int) (map[string]string, []byte, bool) {
	fields := make(map[string]string)
	for lineNo := 0; lineNo < 40; lineNo++ {
		line, err := reader.ReadString('\n')
		if err != nil || len(line) > 1024 {
			return nil, nil, false
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if lineNo == 0 {
			if !strings.HasPrefix(line, fmt.Sprintf("SIP/2.0 %d ", status)) {
				return nil, nil, false
			}
			continue
		}
		if line == "" {
			length, err := strconv.Atoi(fields["content-length"])
			if err != nil || length < 0 || length > 2048 || fields["from"] == "" ||
				!strings.Contains(fields["to"], ";tag=") || fields["call-id"] == "" {
				return nil, nil, false
			}
			body := make([]byte, length)
			if _, err := io.ReadFull(reader, body); err != nil {
				return nil, nil, false
			}
			return fields, body, true
		}
		key, value, found := strings.Cut(line, ":")
		if !found || len(value) > 512 || strings.ContainsAny(value, "\r\n\x00") {
			return nil, nil, false
		}
		fields[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}
	return nil, nil, false
}

func TestSameRegisteredTLSFlowCanAnswerACKAndReceiveBYE(t *testing.T) {
	leaf, roots := fixtureLeaf(t)
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{leaf}})
	if err != nil {
		t.Fatal("synthetic TLS provider unavailable")
	}
	defer listener.Close()
	mediaSocket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal("synthetic loopback RTP socket unavailable")
	}
	defer mediaSocket.Close()
	mediaPort := mediaSocket.LocalAddr().(*net.UDPAddr).Port
	port := listener.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	registeredReady := make(chan struct{})
	answerReady := make(chan bool, 1)
	mediaDone := make(chan bool, 1)
	providerDone := make(chan bool, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			providerDone <- false
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(9 * time.Second))
		reader := bufio.NewReader(conn)
		request, err := readSyntheticREGISTER(reader)
		if err != nil {
			providerDone <- false
			return
		}
		_, err = fmt.Fprintf(conn, "SIP/2.0 200 OK\r\nVia: %s\r\nFrom: %s\r\nTo: %s;tag=synthetic\r\nCall-ID: %s\r\nCSeq: %s\r\nContent-Length: 0\r\n\r\n",
			request["via"], request["from"], request["to"], request["call-id"], request["cseq"])
		if err != nil {
			providerDone <- false
			return
		}
		select {
		case <-registeredReady:
		case <-ctx.Done():
			providerDone <- false
			return
		}
		body := strings.ReplaceAll(syntheticSDP, "203.0.113.8", "127.0.0.1")
		body = strings.ReplaceAll(body, "m=audio 20000", "m=audio "+strconv.Itoa(mediaPort))
		_, err = fmt.Fprintf(conn, "INVITE sip:1234@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/TLS localhost:%d;branch=z9hG4bKoffice-answer;rport\r\nFrom: <sip:provider@localhost>;tag=synthetic\r\nTo: <sip:1234@localhost>\r\nCall-ID: office-answer@localhost\r\nCSeq: 1 INVITE\r\nMax-Forwards: 70\r\nContact: <sips:provider@localhost;transport=tls>\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", port, len(body), body)
		if err != nil {
			providerDone <- false
			return
		}
		response, sdpBody, ok := syntheticResponse(reader, 200)
		if !ok || !strings.Contains(string(sdpBody), "c=IN IP4 127.0.0.1") {
			providerDone <- false
			return
		}
		rtpPort := 0
		for _, line := range strings.Split(string(sdpBody), "\r\n") {
			if strings.HasPrefix(line, "m=audio ") {
				parts := strings.Fields(line)
				if len(parts) != 4 || parts[0] != "m=audio" || parts[2] != "RTP/AVP" || parts[3] != "8" {
					providerDone <- false
					return
				}
				rtpPort, err = strconv.Atoi(parts[1])
			}
		}
		if rtpPort < 1024 || rtpPort > 65535 {
			providerDone <- false
			return
		}
		_, err = fmt.Fprintf(conn, "ACK sip:1234@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/TLS localhost:%d;branch=z9hG4bKoffice-ack;rport\r\nFrom: %s\r\nTo: %s\r\nCall-ID: %s\r\nCSeq: 1 ACK\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n", port,
			response["from"], response["to"], response["call-id"])
		if err != nil {
			providerDone <- false
			return
		}
		select {
		case answered := <-answerReady:
			if !answered {
				providerDone <- false
				return
			}
		case <-ctx.Done():
			providerDone <- false
			return
		}
		var packet [172]byte // 12-byte RTP header and one 20-ms PCMA frame.
		packet[0], packet[1] = 0x80, 8
		binary.BigEndian.PutUint16(packet[2:4], 1)
		binary.BigEndian.PutUint32(packet[4:8], 160)
		binary.BigEndian.PutUint32(packet[8:12], 0x1234)
		for i := 12; i < len(packet); i++ {
			packet[i] = 0xd5 // synthetic silence, not recorded audio
		}
		_ = mediaSocket.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := mediaSocket.WriteToUDP(packet[:], &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: rtpPort}); err != nil {
			providerDone <- false
			return
		}
		returned := make([]byte, 2048)
		n, peer, err := mediaSocket.ReadFromUDP(returned)
		if err != nil || peer.Port != rtpPort || !peer.IP.IsLoopback() ||
			n != len(packet) || returned[0]>>6 != 2 || returned[1]&0x7f != 8 {
			providerDone <- false
			return
		}
		_, err = fmt.Fprintf(conn, "BYE sip:1234@127.0.0.1 SIP/2.0\r\nVia: SIP/2.0/TLS localhost:%d;branch=z9hG4bKoffice-bye;rport\r\nFrom: %s\r\nTo: %s\r\nCall-ID: %s\r\nCSeq: 2 BYE\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n", port,
			response["from"], response["to"], response["call-id"])
		if err != nil {
			providerDone <- false
			return
		}
		bye, _, ok := syntheticResponse(reader, 200)
		providerDone <- ok && bye["cseq"] == "2 BYE"
	}()
	ua, err := sipgo.NewUA(sipgo.WithUserAgenTLSConfig(&tls.Config{
		MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "localhost"}),
		sipgo.WithUserAgentTransportLayerOptions(sip.WithTransportLayerLogger(safesip.Logger)),
		sipgo.WithUserAgentTransactionLayerOptions(sip.WithTransactionLayerLogger(safesip.Logger)))
	if err != nil {
		t.Fatal("synthetic SIP client unavailable")
	}
	defer ua.Close()
	policy, ok := newAdmission("1234", "127.0.0.1", []net.IP{net.ParseIP("127.0.0.1")}, true)
	if !ok {
		t.Fatal("synthetic office admission unavailable")
	}
	dg := diago.NewDiago(ua, diago.WithLogger(safesip.Logger),
		diago.WithTransport(diago.Transport{Transport: "tls", BindHost: "127.0.0.1", BindPort: 0}),
		diago.WithMediaConfig(diago.MediaConfig{Codecs: []media.Codec{media.CodecAudioAlaw}}),
		diago.WithServerRequestMiddleware(func(next sipgo.RequestHandler) sipgo.RequestHandler {
			return func(req *sip.Request, tx sip.ServerTransaction) {
				if req.Method == sip.INVITE {
					if policy.Admit(req) != Admit {
						_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusForbidden, "Forbidden", nil))
						return
					}
				}
				next(req, tx)
			}
		}))
	dg.HandleFunc(func(dialog *diago.DialogServerSession) {
		dm, err := dialog.Answer(diago.AnswerOptions{})
		if err != nil {
			answerReady <- false
			return
		}
		session := dm.MediaSession()
		codecs := session.CommonCodecs()
		answerReady <- len(codecs) == 1 && codecs[0].PayloadType == 8
		_ = dm.Echo() // bounded by synthetic remote BYE / context cancellation
		select {
		case <-dialog.Context().Done():
			mediaDone <- true
		case <-ctx.Done():
			mediaDone <- false
		}
	})
	uri := sip.Uri{Scheme: "sips", User: "synthetic", Host: "localhost", Port: port}
	uri.UriParams = sip.NewParams()
	uri.UriParams.Add("transport", "tls")
	registration, err := dg.RegisterTransaction(ctx, uri, diago.RegisterOptions{
		Username: "synthetic", Password: "unit-only", Expiry: 90 * time.Second})
	if err != nil || registration.Register(ctx) != nil {
		t.Fatal("synthetic TLS registration unavailable")
	}
	policy.Registered()
	close(registeredReady)
	select {
	case ok := <-providerDone:
		if !ok {
			t.Fatal("synthetic 200/ACK/BYE transaction incomplete")
		}
	case <-ctx.Done():
		t.Fatal("synthetic dialog timed out")
	}
	select {
	case ended := <-mediaDone:
		if !ended {
			t.Fatal("synthetic media owner did not close after BYE")
		}
	case <-ctx.Done():
		t.Fatal("synthetic media owner did not exit")
	}
}
