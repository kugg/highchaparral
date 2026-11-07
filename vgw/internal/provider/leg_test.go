package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"example.com/ata/voip-gateway/internal/byok"
	"example.com/ata/voip-gateway/internal/calls"
	"example.com/ata/voip-gateway/internal/safesip"
	"github.com/emiago/diago"
	"github.com/emiago/diago/media"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/icholy/digest"
)

func syntheticProvider(t *testing.T) (Profile, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"},
		Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	ua, err := sipgo.NewUA(sipgo.WithUserAgentTransportLayerOptions(
		sip.WithTransportLayerLogger(safesip.Logger)))
	if err != nil {
		t.Fatal(err)
	}
	server, err := sipgo.NewServer(ua, sipgo.WithServerLogger(safesip.Logger))
	if err != nil {
		t.Fatal(err)
	}
	registered, unregistered := &atomic.Int32{}, &atomic.Int32{}
	challenge := digest.Challenge{Realm: "only-tests", Nonce: "only-tests-nonce", Algorithm: "MD5"}
	server.OnRegister(func(req *sip.Request, tx sip.ServerTransaction) {
		auth := req.GetHeader("Authorization")
		if auth == nil {
			res := sip.NewResponseFromRequest(req, sip.StatusUnauthorized, "Unauthorized", nil)
			res.AppendHeader(sip.NewHeader("WWW-Authenticate", challenge.String()))
			_ = tx.Respond(res)
			return
		}
		actual, parseErr := digest.ParseCredentials(auth.Value())
		if parseErr != nil || actual == nil {
			_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusForbidden, "Forbidden", nil))
			return
		}
		expected, digestErr := digest.Digest(&challenge, digest.Options{
			Method: "REGISTER", URI: actual.URI, Username: "synthetic", Password: "only-for-tests",
		})
		if digestErr != nil || actual.Username != "synthetic" ||
			subtle.ConstantTimeCompare([]byte(actual.Response), []byte(expected.Response)) != 1 {
			_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusForbidden, "Forbidden", nil))
			return
		}
		if h := req.GetHeader("Expires"); h != nil && h.Value() == "0" {
			unregistered.Add(1)
		} else {
			registered.Add(1)
		}
		_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusOK, "OK", nil))
	})
	d := diago.NewDiago(ua, diago.WithServer(server),
		diago.WithTransport(diago.Transport{Transport: "tls", BindHost: "127.0.0.1", BindPort: port,
			TLSConf: &tls.Config{MinVersion: tls.VersionTLS12,
				Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}}),
		diago.WithMediaConfig(diago.MediaConfig{Codecs: []media.Codec{media.CodecAudioAlaw}}),
		diago.WithLogger(safesip.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	if err := d.ServeBackground(ctx, func(dialog *diago.DialogServerSession) {
		if dialog.InviteRequest.Recipient.User != "1234" {
			_ = dialog.Respond(sip.StatusNotFound, "Not Found", nil)
			return
		}
		if dialog.Answer() == nil {
			_ = dialog.Echo()
		}
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); ua.Close() })
	return Profile{Host: "localhost", TLSName: "localhost", Port: port,
		BindIPv4: "127.0.0.1", Roots: roots, allowLoopback: true}, registered, unregistered
}

func TestBYOKProviderBridgesOwnedPCMAAndConfirmsTeardown(t *testing.T) {
	profile, registered, unregistered := syntheticProvider(t)
	const id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fromARI := make(chan calls.AudioFrame, 2)
	toARI := make(chan calls.AudioFrame, 2)
	frame := calls.AudioFrame{ID: id}
	for i := range frame.Payload {
		frame.Payload[i] = 0xd5
	}
	fromARI <- frame
	got := make(chan bool, 1)
	go func() {
		select {
		case reply := <-toARI:
			got <- reply.ID == id && reply.Payload == frame.Payload
		case <-time.After(6 * time.Second):
			got <- false
		}
		close(fromARI)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	var answered bool
	profile.OnAnswer = func(context.Context) error { answered = true; return nil }
	var phases []byok.Milestone
	profile.OnMilestone = func(value byok.Milestone) error { phases = append(phases, value); return nil }
	creds := byok.Credentials{Identity: "synthetic", Password: []byte("only-for-tests"), Target: "1234"}
	settled, err := Call(ctx, profile, creds, id, fromARI, toARI)
	frameOK := <-got
	if err != nil || !settled || !frameOK || !answered || registered.Load() != 1 || unregistered.Load() != 1 {
		t.Fatalf("synthetic BYOK lifecycle incomplete settled=%t err=%t frame=%t register=%d unregister=%d",
			settled, err != nil, frameOK, registered.Load(), unregistered.Load())
	}
	for _, expected := range []byok.Milestone{byok.RegisterStart, byok.RegisterOK, byok.InviteStart,
		byok.InviteAnswered, byok.BrowserAnswered, byok.ByeStart, byok.ByeOK,
		byok.UnregisterStart, byok.UnregisterOK} {
		if !slices.Contains(phases, expected) {
			t.Fatal("fixed progress missing provider REGISTER/INVITE/BYE/unregister boundary")
		}
	}
}

func TestBYOKProviderRefusesInvalidTargetOrCredentialBeforeNetwork(t *testing.T) {
	profile, _, _ := syntheticProvider(t)
	fromARI, toARI := make(chan calls.AudioFrame), make(chan calls.AudioFrame)
	for _, creds := range []byok.Credentials{
		{Identity: "synthetic", Password: []byte("only-for-tests"), Target: "sip:human@evil.invalid"},
		{Identity: "synthetic\r\nX-Log: forged", Password: []byte("only-for-tests"), Target: "1234"},
		{Identity: "synthetic", Password: []byte("bad\x1b[31m"), Target: "1234"},
	} {
		if _, err := Call(context.Background(), profile, creds, strings.Repeat("a", 32), fromARI, toARI); err == nil ||
			strings.Contains(err.Error(), "forged") {
			t.Fatal("untrusted BYOK destination/identity/password entered provider network or log")
		}
	}
}

func TestInviteFailureMilestoneUsesOnlyTypedStatusNeverRemoteReason(t *testing.T) {
	for _, test := range []struct {
		err  error
		want byok.Milestone
	}{
		{errors.Join(errors.New("fixed wrapper"), &sipgo.ErrDialogResponse{
			Res: sip.NewResponse(404, "bad\r\nX-Password: injected")}), byok.InviteStatus404},
		{sipgo.ErrDialogResponse{Res: sip.NewResponse(486, "untrusted reason")}, byok.InviteStatus486},
		{&sipgo.ErrDialogResponse{Res: sip.NewResponse(430, "foreign text")}, byok.InviteOtherStatus},
		{context.DeadlineExceeded, byok.InviteTimeout},
		{errors.New("foreign\r\nHeader: injected"), byok.InviteOtherError},
	} {
		actual := inviteFailureMilestone(test.err)
		if actual != test.want || strings.Contains(string(actual), "injected") ||
			strings.Contains(string(actual), "untrusted") || len(actual) > 25 {
			t.Fatal("SIP response reason entered durable milestone or status class changed")
		}
	}
}

func TestSyntheticTLSRejectedInviteRecordsStatusBeforeUnregister(t *testing.T) {
	profile, registered, unregistered := syntheticProvider(t)
	var stages []byok.Milestone
	profile.OnMilestone = func(value byok.Milestone) error {
		stages = append(stages, value)
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	creds := byok.Credentials{Identity: "synthetic", Password: []byte("only-for-tests"), Target: "5678"}
	settled, err := Call(ctx, profile, creds, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		make(chan calls.AudioFrame), make(chan calls.AudioFrame))
	if err == nil || settled || registered.Load() != 1 || unregistered.Load() != 1 {
		t.Fatal("synthetic rejected INVITE was mistaken for a settled call")
	}
	for _, expected := range []byok.Milestone{byok.RegisterOK, byok.InviteStart,
		byok.InviteStatus404, byok.InviteRefused, byok.UnregisterOK} {
		if !slices.Contains(stages, expected) {
			t.Fatal("typed rejected INVITE was not classified before safe unregister")
		}
	}
	if slices.Contains(stages, byok.InviteAnswered) || slices.Contains(stages, byok.ByeStart) {
		t.Fatal("rejected INVITE generated false answer/BYE evidence")
	}
}
