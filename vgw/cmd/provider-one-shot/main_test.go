package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"example.com/ata/voip-gateway/internal/safesip"
	"github.com/emiago/diago"
	"github.com/emiago/diago/media"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/icholy/digest"
)

func TestDedicatedCredentialsCannotSelectAnotherHostOrInjectFields(t *testing.T) {
	good := []byte("SIP-Registrar: hg.eventphone.de\nSIP-Identity: synthetic\nSIP-Password: only-for-tests\n")
	c, err := parseCredentials(good)
	if err != nil || c.user != "synthetic" || c.pass != "only-for-tests" {
		t.Fatal("synthetic dedicated account fixture rejected")
	}
	for _, bad := range [][]byte{
		[]byte(strings.ReplaceAll(string(good), provider, "evil.invalid")),
		[]byte(strings.ReplaceAll(string(good), "synthetic", "a\r\nAuthorization: data")),
		[]byte(strings.ReplaceAll(string(good), "SIP-Password:", "Unknown:")),
		[]byte(strings.ReplaceAll(string(good), "only-for-tests", "")),
		[]byte(string(good) + "Another: extra\n"),
		[]byte(strings.ReplaceAll(string(good), "only-for-tests", "escape\x1b[31m")),
		[]byte(strings.ReplaceAll(string(good), "only-for-tests", "contains space")),
		[]byte(string(good) + "\n"),
	} {
		if _, err := parseCredentials(bad); err == nil || strings.Contains(err.Error(), "only-for-tests") {
			t.Fatal("malformed or redirected provider credential input was accepted or leaked")
		}
	}
}

func TestOneCallAgainstSyntheticTLSRegistrarAndSDESAuthenticatedEcho(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"},
		Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
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
	defer ua.Close()
	server, err := sipgo.NewServer(ua, sipgo.WithServerLogger(safesip.Logger))
	if err != nil {
		t.Fatal(err)
	}
	var registrations, invites, unregisters, challenges atomic.Int32
	challenge := digest.Challenge{Realm: "one-shot-mock", Nonce: "one-time-mock-nonce", Algorithm: "MD5"}
	server.OnRegister(func(req *sip.Request, tx sip.ServerTransaction) {
		h := req.GetHeader("Authorization")
		if h == nil {
			challenges.Add(1)
			response := sip.NewResponseFromRequest(req, sip.StatusUnauthorized, "Unauthorized", nil)
			response.AppendHeader(sip.NewHeader("WWW-Authenticate", challenge.String()))
			_ = tx.Respond(response)
			return
		}
		credentials, parseErr := digest.ParseCredentials(h.Value())
		if parseErr != nil {
			_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusForbidden, "Forbidden", nil))
			return
		}
		expected, authErr := digest.Digest(&challenge, digest.Options{Method: "REGISTER", URI: credentials.URI,
			Username: "synthetic", Password: "only-for-tests"})
		if authErr != nil || credentials.Username != "synthetic" ||
			subtle.ConstantTimeCompare([]byte(credentials.Response), []byte(expected.Response)) != 1 {
			_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusForbidden, "Forbidden", nil))
			return
		}
		if h := req.GetHeader("Expires"); h != nil && h.Value() == "0" {
			unregisters.Add(1)
		} else {
			registrations.Add(1)
		}
		_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusOK, "OK", nil))
	})
	d := diago.NewDiago(ua, diago.WithServer(server),
		diago.WithTransport(diago.Transport{Transport: "tls", BindHost: "127.0.0.1", BindPort: port,
			MediaSRTP: 1,
			TLSConf: &tls.Config{MinVersion: tls.VersionTLS12,
				Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}}),
		diago.WithMediaConfig(diago.MediaConfig{Codecs: []media.Codec{media.CodecAudioAlaw}}),
		diago.WithLogger(safesip.Logger))
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	if err := d.ServeBackground(ctx, func(dialog *diago.DialogServerSession) {
		invites.Add(1)
		if dialog.InviteRequest.Recipient.Scheme != "sip" || dialog.InviteRequest.Recipient.User != "1234" {
			_ = dialog.Respond(sip.StatusNotFound, "Not Found", nil)
			return
		}
		if dm, err := dialog.Answer(diago.AnswerOptions{}); err == nil {
			_ = dm.Echo()
		}
	}); err != nil {
		t.Fatal(err)
	}
	result, category := oneCall(ctx, config{host: "localhost", tlsName: "localhost", bindHost: "127.0.0.1", target: "1234",
		port: port, roots: roots, creds: credentials{user: "synthetic", pass: "only-for-tests"}, allowLoopback: true,
		mediaProfile: "sdes"})
	if category != "pass" || !result.registered || !result.answered || !result.received ||
		!result.bye || !result.unregistered || !result.authenticatedMedia ||
		result.answerTransport != "RTP/SAVP" || result.keying != "sdes" ||
		registrations.Load() != 1 || invites.Load() != 1 ||
		unregisters.Load() != 1 || challenges.Load() < 1 {
		t.Fatalf("synthetic one-shot TLS/media flow incomplete category=%s registered=%t answered=%t media=%t bye=%t unregistered=%t registrations=%d invites=%d unregisters=%d challenges=%d",
			category, result.registered, result.answered, result.received, result.bye, result.unregistered,
			registrations.Load(), invites.Load(), unregisters.Load(), challenges.Load())
	}
}

func TestMediaAnswerInspectionRejectsDowngradeWithoutRetainingSecrets(t *testing.T) {
	response := &sip.Response{StatusCode: sip.StatusOK}
	response.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	response.SetBody([]byte("v=0\r\nm=audio 4000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n"))
	observed, err := inspectMediaAnswer("sdes", response)
	if err == nil || !observed.downgradeRejected || observed.answerTransport != "RTP/AVP" {
		t.Fatal("plaintext downgrade was not recognized and rejected")
	}

	secret := "DO-NOT-RETAIN-THIS-SDES-KEY"
	response.SetBody([]byte("v=0\r\nm=audio 4000 RTP/SAVP 8\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:" + secret + "\r\n"))
	observed, err = inspectMediaAnswer("sdes", response)
	if err != nil || observed.keying != "sdes" || observed.suite != "AES_CM_128_HMAC_SHA1_80" {
		t.Fatal("valid SDES capability answer was not categorized")
	}
	if strings.Contains(fmt.Sprint(observed), secret) {
		t.Fatal("sanitized capability result retained SDES key material")
	}
}

func TestProvisionalSDPDoesNotAbortBeforeAuthenticatedFinalAnswer(t *testing.T) {
	var observed outcome
	provisional := &sip.Response{StatusCode: sip.StatusSessionInProgress}
	provisional.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	provisional.SetBody([]byte("v=0\r\nm=audio 4000 RTP/SAVP 8\r\na=rtpmap:8 PCMA/8000\r\n"))
	if err := observeMediaResponse("sdes", provisional, &observed); err != nil {
		t.Fatal("provisional SDP aborted the invitation before the final answer")
	}
	if observed.provisionalSDPCount != 1 || observed.provisionalTransport != "RTP/SAVP" || observed.finalSDP {
		t.Fatal("provisional SDP was not retained as a separate sanitized observation")
	}

	final := &sip.Response{StatusCode: sip.StatusOK}
	final.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	final.SetBody([]byte("v=0\r\nm=audio 4000 RTP/SAVP 8\r\na=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:DO-NOT-RETAIN\r\n"))
	if err := observeMediaResponse("sdes", final, &observed); err != nil {
		t.Fatal("authenticated final SDES answer was rejected")
	}
	if !observed.finalSDP || observed.answerTransport != "RTP/SAVP" || observed.keying != "sdes" ||
		strings.Contains(fmt.Sprint(observed), "DO-NOT-RETAIN") {
		t.Fatal("final answer was not validated or retained only as safe categories")
	}
}

func TestFinalSDPClassifiesAlternateKeyingWithoutRetainingIt(t *testing.T) {
	secret := "ALTERNATE-KEY-MUST-NOT-BE-RETAINED"
	response := &sip.Response{StatusCode: sip.StatusOK}
	response.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	response.SetBody([]byte("v=0\r\nm=audio 4000 RTP/SAVP 8\r\n" +
		"a=crypto:7 AES_CM_128_HMAC_SHA1_32 inline:" + secret + "\r\n"))
	observed, err := inspectMediaAnswer("sdes", response)
	if err == nil {
		t.Fatal("alternate suite was accepted as the configured suite")
	}
	if observed.keyingObservation != "sdes" || observed.suiteObservation != "aes128-sha1-32" ||
		observed.cryptoAttributeCount != 1 || !observed.inlineKeyPresent {
		t.Fatal("alternate SDES answer was not reduced to fixed safe categories")
	}
	if strings.Contains(fmt.Sprint(observed), secret) {
		t.Fatal("sanitized alternate-suite observation retained key material")
	}
}

func TestDTLSAnswerInspectionRequiresFingerprintAndSetup(t *testing.T) {
	response := &sip.Response{StatusCode: sip.StatusOK}
	response.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	response.SetBody([]byte("v=0\r\nm=audio 4000 UDP/TLS/RTP/SAVP 8\r\na=setup:passive\r\na=fingerprint:sha-256 AA:BB\r\n"))
	observed, err := inspectMediaAnswer("dtls", response)
	if err != nil || observed.keying != "dtls-srtp" || observed.peerBinding != "sdp-fingerprint-over-verified-sip-tls" {
		t.Fatal("valid DTLS-SRTP capability answer was not categorized")
	}
	response.SetBody([]byte("v=0\r\nm=audio 4000 UDP/TLS/RTP/SAVP 8\r\na=setup:passive\r\n"))
	if _, err := inspectMediaAnswer("dtls", response); err == nil {
		t.Fatal("DTLS-SRTP without a signaling-bound fingerprint was accepted")
	}
	if !secureTransportMatches("dtls", "UDP/TLS/RTP/SAVPF") || secureTransportMatches("dtls", "RTP/AVP") {
		t.Fatal("DTLS transport matching did not admit secure feedback or reject plaintext")
	}
}

func TestPrivateFileAbsentDoesNotAccessNetwork(t *testing.T) {
	if _, err := loadCredentials("/nonexistent-one-shot-credential-file"); err == nil ||
		strings.Contains(err.Error(), "nonexistent") {
		t.Fatal("missing private file leaked path or was accepted")
	}
	if _, err := os.Stat("/nonexistent-one-shot-credential-file"); !os.IsNotExist(err) {
		t.Fatal("test fixture unexpectedly exists")
	}
}

func TestAttemptStageIsOneUseOwnerOnlyAndKeepsSanitizedResult(t *testing.T) {
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(previous) })
	dirName, err := stageDir("first")
	if err != nil {
		t.Fatal(err)
	}
	if err := reserveAttempt(dirName); err != nil {
		t.Fatal(err)
	}
	if err := reserveAttempt(dirName); err == nil {
		t.Fatal("ambiguous first attempt could be automatically redialed")
	}
	if err := recordResult(dirName, "no-return-media", outcome{registered: true, answered: true, bye: true}); err != nil {
		t.Fatal(err)
	}
	if err := recordResult(dirName, "pass", outcome{}); err == nil {
		t.Fatal("one-use result was overwritten")
	}
	mazeDir, err := stageDir("maze")
	if err != nil || mazeDir == dirName {
		t.Fatal("separately authorized call would reuse prior stage")
	}
	if err := reserveAttempt(mazeDir); err != nil {
		t.Fatal("separately authorized one-use test stage unavailable")
	}
	if _, err := stageDir("arbitrary"); err == nil {
		t.Fatal("dynamic stage names could bypass no-replay marker")
	}
	announcementDir, err := stageDir("announcement")
	if err != nil || announcementDir == dirName || announcementDir == mazeDir {
		t.Fatal("new authorized automated attempt reused a historical stage")
	}
	if err := prepareAutomatedTarget(announcementDir, "1234"); err != nil {
		t.Fatal("synthetic automated target preparation refused")
	}
	sdesDir, err := stageDir("srtp-sdes-v1")
	if err != nil || sdesDir == announcementDir || !automatedStage("srtp-sdes-v1") {
		t.Fatal("SDES capability probe could reuse a historical stage")
	}
	dtlsDir, err := stageDir("srtp-dtls-v1")
	if err != nil || dtlsDir == sdesDir || dtlsDir == announcementDir || !automatedStage("srtp-dtls-v1") {
		t.Fatal("DTLS capability probe could reuse another one-use stage")
	}
	if profile, err := stageMediaProfile("srtp-sdes-v1"); err != nil || profile != "sdes" {
		t.Fatal("SDES stage was not bound to its fixed media profile")
	}
	if profile, err := stageMediaProfile("srtp-dtls-v1"); err != nil || profile != "dtls" {
		t.Fatal("DTLS stage was not bound to its fixed media profile")
	}
	sdesV2Dir, err := stageDir("srtp-sdes-v2-final-answer")
	if err != nil || sdesV2Dir == sdesDir || !automatedStage("srtp-sdes-v2-final-answer") {
		t.Fatal("corrected SDES final-answer probe could reuse a historical stage")
	}
	if profile, err := stageMediaProfile("srtp-sdes-v2-final-answer"); err != nil || profile != "sdes" {
		t.Fatal("corrected SDES stage was not bound to its fixed media profile")
	}
	sdesV3Dir, err := stageDir("srtp-sdes-v3-keying-category")
	if err != nil || sdesV3Dir == sdesV2Dir || !automatedStage("srtp-sdes-v3-keying-category") {
		t.Fatal("keying-category probe could reuse a historical stage")
	}
	if err := requireAutomatedTarget(announcementDir, "1234"); err != nil {
		t.Fatal("exact reviewed private target refused")
	}
	if err := requireAutomatedTarget(announcementDir, "9876"); err == nil {
		t.Fatal("different numeric target could dial a person")
	}
	if err := prepareAutomatedTarget(announcementDir, "1234"); err == nil {
		t.Fatal("automated target approval could be silently replaced")
	}
	approved := announcementDir + "/approved_target"
	if err := os.Chmod(approved, 0644); err != nil {
		t.Fatal(err)
	}
	if err := requireAutomatedTarget(announcementDir, "1234"); err == nil {
		t.Fatal("world-readable automated target approval accepted")
	}
	info, err := os.Stat("secrets/attended-provider/attempt.json")
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("one-use provider stage not owner-only")
	}
	result, err := os.ReadFile("secrets/attended-provider/result.json")
	if err != nil || !strings.Contains(string(result), "no-return-media") ||
		strings.Contains(string(result), "only-for-tests") {
		t.Fatal("one-use test result was missing or contained a secret")
	}
}
