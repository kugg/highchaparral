// Command provider-one-shot is an attended, bounded provider test harness.
// DRY RUN by default. --run permits one REGISTER and one user-approved INVITE,
// one BYE and one Unregister; no application redial, audio storage or dump.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"example.com/ata/voip-gateway/internal/safesip"
	"github.com/emiago/diago"
	"github.com/emiago/diago/media"
	"github.com/emiago/dtls/v3/pkg/crypto/selfsign"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

const (
	provider       = "hg.eventphone.de"
	port           = 5061
	credentialFile = "../../../../ata/webrtc/gateway/eventphone_creds" // ignored sibling ATA; never publish or copy.
)

type credentials struct{ user, pass string }

func parseCredentials(raw []byte) (credentials, error) {
	var c credentials
	var host string
	if len(raw) < 30 || len(raw) > 1024 || strings.ContainsAny(string(raw), "\r\x00") {
		return c, errors.New("invalid private test credential shape")
	}
	rows := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(rows) != 3 {
		return c, errors.New("invalid private test credential shape")
	}
	for _, row := range rows {
		label, value, ok := strings.Cut(row, ": ")
		if !ok || len(value) < 1 || len(value) > 256 {
			return credentials{}, errors.New("invalid private test credential shape")
		}
		for i := 0; i < len(value); i++ {
			if value[i] < 0x21 || value[i] > 0x7e {
				return credentials{}, errors.New("invalid private test credential shape")
			}
		}
		switch label {
		case "Password", "SIP-Password":
			if c.pass != "" {
				return credentials{}, errors.New("ambiguous private test credential fields")
			}
			c.pass = value
		case "Server/Registrar", "SIP-Registrar":
			if host != "" {
				return credentials{}, errors.New("ambiguous private test credential fields")
			}
			host = value
		case "AuthUser", "SIP-Identity":
			if c.user != "" {
				return credentials{}, errors.New("ambiguous private test credential fields")
			}
			c.user = value
		default:
			return credentials{}, errors.New("ambiguous private test credential fields")
		}
	}
	if host != provider ||
		!regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`).MatchString(c.user) ||
		c.pass == "" {
		return credentials{}, errors.New("invalid dedicated test identity or host")
	}
	return c, nil
}

func loadCredentials(path string) (credentials, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return credentials{}, errors.New("private credential file unavailable")
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm() != 0600 ||
		stat.Size() > 4096 || stat.Size() == 0 ||
		stat.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) ||
		stat.Sys().(*syscall.Stat_t).Nlink != 1 {
		return credentials{}, errors.New("private credential ownership invalid")
	}
	raw := make([]byte, stat.Size())
	if n, err := io.ReadFull(f, raw); err != nil || int64(n) != stat.Size() {
		return credentials{}, errors.New("private credential file unreadable")
	}
	return parseCredentials(raw)
}

type config struct {
	host, tlsName, bindHost, target, mediaProfile string
	port                                          int
	roots                                         *x509.CertPool
	creds                                         credentials
	allowLoopback                                 bool // tests only; the executable never sets this
}

type outcome struct {
	registered, answered, received, bye, unregistered bool
	registerStatus, inviteStatus                      int
	mediaProfile, answerTransport, keying, suite      string
	peerBinding                                       string
	authenticatedMedia, downgradeRejected             bool
	provisionalSDPCount                               int
	provisionalTransport                              string
	finalSDP                                          bool
	keyingObservation, suiteObservation               string
	cryptoAttributeCount                              int
	inlineKeyPresent                                  bool
}

type mediaOffer struct {
	mode        int
	dtls        media.DTLSConfig
	transport   string
	keying      string
	suite       string
	peerBinding string
}

func mediaOfferFor(profile string) (mediaOffer, error) {
	switch profile {
	case "plaintext":
		return mediaOffer{transport: "RTP/AVP", keying: "none", suite: "none", peerBinding: "none"}, nil
	case "sdes":
		return mediaOffer{mode: 1, transport: "RTP/SAVP", keying: "sdes",
			suite: "AES_CM_128_HMAC_SHA1_80", peerBinding: "sdp-key-over-verified-sip-tls"}, nil
	case "dtls":
		certificate, err := selfsign.GenerateSelfSigned()
		if err != nil {
			return mediaOffer{}, errors.New("local DTLS certificate unavailable")
		}
		return mediaOffer{mode: 2, dtls: media.DTLSConfig{Certificates: []tls.Certificate{certificate}},
			transport: "UDP/TLS/RTP/SAVP", keying: "dtls-srtp",
			suite: "dtls-selected-srtp-profile", peerBinding: "sdp-fingerprint-over-verified-sip-tls"}, nil
	default:
		return mediaOffer{}, errors.New("unreviewed media profile")
	}
}

// inspectMediaAnswer returns only fixed capability categories. It never returns
// raw SDP, inline SDES key material, fingerprints, addresses or SIP headers.
func inspectMediaAnswer(profile string, response *sip.Response) (outcome, error) {
	var result outcome
	result.mediaProfile = profile
	if response == nil || response.StatusCode < 180 || response.StatusCode >= 300 ||
		response.ContentType() == nil || !strings.EqualFold(response.ContentType().Value(), "application/sdp") {
		return result, nil
	}
	var crypto, fingerprint, setup, mikey, zrtp bool
	for _, raw := range strings.Split(strings.ReplaceAll(string(response.Body()), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "m=audio ") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				result.answerTransport = fields[2]
			}
		}
		if strings.HasPrefix(line, "a=crypto:") {
			fields := strings.Fields(line)
			result.cryptoAttributeCount++
			if len(fields) < 3 {
				result.suiteObservation = mergeObservation(result.suiteObservation, "malformed")
				continue
			}
			result.suiteObservation = mergeObservation(result.suiteObservation, sdesSuiteCategory(fields[1]))
			inline := strings.HasPrefix(fields[2], "inline:") && len(strings.TrimPrefix(fields[2], "inline:")) > 0
			result.inlineKeyPresent = result.inlineKeyPresent || inline
			crypto = crypto || fields[1] == "AES_CM_128_HMAC_SHA1_80" && inline
		}
		if strings.HasPrefix(strings.ToLower(line), "a=fingerprint:sha-256 ") {
			fingerprint = true
		}
		if strings.HasPrefix(line, "a=setup:") {
			role := strings.TrimPrefix(line, "a=setup:")
			setup = role == "active" || role == "passive" || role == "actpass"
		}
		mikey = mikey || strings.HasPrefix(strings.ToLower(line), "a=key-mgmt:mikey")
		zrtp = zrtp || strings.HasPrefix(strings.ToLower(line), "a=zrtp-hash:")
	}
	result.keyingObservation = keyingCategory(result.cryptoAttributeCount > 0, fingerprint, mikey, zrtp)
	// A provisional SDP answer can describe early media without containing the
	// keying material that will be present in the final answer. It is useful
	// evidence, but it is not the negotiated session and must never abort the
	// INVITE. The final 2xx answer is validated below.
	if response.StatusCode < 200 {
		return result, nil
	}
	switch profile {
	case "plaintext":
		if result.answerTransport != "RTP/AVP" {
			return result, errors.New("unexpected plaintext media answer")
		}
		result.keying, result.suite, result.peerBinding = "none", "none", "none"
	case "sdes":
		result.downgradeRejected = result.answerTransport == "RTP/AVP"
		if result.answerTransport != "RTP/SAVP" || !crypto {
			return result, errors.New("authenticated SDES media not negotiated")
		}
		result.keying, result.suite, result.peerBinding = "sdes", "AES_CM_128_HMAC_SHA1_80", "sdp-key-over-verified-sip-tls"
	case "dtls":
		result.downgradeRejected = result.answerTransport == "RTP/AVP"
		if (result.answerTransport != "UDP/TLS/RTP/SAVP" && result.answerTransport != "UDP/TLS/RTP/SAVPF") || !fingerprint || !setup {
			return result, errors.New("authenticated DTLS-SRTP media not negotiated")
		}
		result.keying, result.suite, result.peerBinding = "dtls-srtp", "dtls-selected-srtp-profile", "sdp-fingerprint-over-verified-sip-tls"
	default:
		return result, errors.New("unreviewed media profile")
	}
	return result, nil
}

func mergeObservation(current, next string) string {
	if current == "" || current == next {
		return next
	}
	return "multiple"
}

func sdesSuiteCategory(suite string) string {
	switch suite {
	case "AES_CM_128_HMAC_SHA1_80":
		return "aes128-sha1-80"
	case "AES_CM_128_HMAC_SHA1_32":
		return "aes128-sha1-32"
	case "AES_CM_256_HMAC_SHA1_80":
		return "aes256-sha1-80"
	case "AES_CM_256_HMAC_SHA1_32":
		return "aes256-sha1-32"
	case "AEAD_AES_128_GCM":
		return "aead-aes128-gcm"
	case "AEAD_AES_256_GCM":
		return "aead-aes256-gcm"
	case "NULL_HMAC_SHA1_80", "NULL_HMAC_SHA1_32":
		return "null-cipher"
	default:
		return "other"
	}
}

func keyingCategory(sdes, fingerprint, mikey, zrtp bool) string {
	categories := 0
	category := "none"
	for name, present := range map[string]bool{"sdes": sdes, "dtls": fingerprint, "mikey": mikey, "zrtp": zrtp} {
		if present {
			categories++
			category = name
		}
	}
	if categories > 1 {
		return "multiple"
	}
	return category
}

// observeMediaResponse keeps provisional and final SDP evidence distinct.
// It returns a negotiation error only for a final response. No raw SDP,
// addresses, key material or fingerprints are retained.
func observeMediaResponse(profile string, response *sip.Response, result *outcome) error {
	observed, err := inspectMediaAnswer(profile, response)
	if observed.answerTransport == "" {
		return err
	}
	if response.StatusCode < 200 {
		result.provisionalSDPCount++
		result.provisionalTransport = observed.answerTransport
		return nil
	}
	result.finalSDP = true
	result.answerTransport = observed.answerTransport
	result.keying = observed.keying
	result.suite = observed.suite
	result.peerBinding = observed.peerBinding
	result.downgradeRejected = observed.downgradeRejected
	result.keyingObservation = observed.keyingObservation
	result.suiteObservation = observed.suiteObservation
	result.cryptoAttributeCount = observed.cryptoAttributeCount
	result.inlineKeyPresent = observed.inlineKeyPresent
	return err
}

func secureTransportMatches(profile, answer string) bool {
	switch profile {
	case "plaintext":
		return answer == "RTP/AVP"
	case "sdes":
		return answer == "RTP/SAVP"
	case "dtls":
		return answer == "UDP/TLS/RTP/SAVP" || answer == "UDP/TLS/RTP/SAVPF"
	default:
		return false
	}
}

func localBindIP(host string, port int) (string, error) {
	addresses, err := net.LookupIP(host)
	if err != nil {
		return "", errors.New("provider IPv4 DNS unavailable")
	}
	for _, ip := range addresses {
		if ip4 := ip.To4(); ip4 != nil {
			conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: ip4, Port: port})
			if err != nil {
				return "", errors.New("outbound IPv4 route unavailable")
			}
			defer conn.Close()
			local := conn.LocalAddr().(*net.UDPAddr).IP
			if local == nil || local.To4() == nil || local.IsLoopback() {
				return "", errors.New("provider route is not a host LAN IPv4 address")
			}
			return local.String(), nil
		}
	}
	return "", errors.New("provider IPv4 DNS unavailable")
}

func statusCategory(err error) int {
	var response *diago.RegisterResponseError
	if errors.As(err, &response) {
		return response.StatusCode()
	}
	var dialog *sipgo.ErrDialogResponse
	if errors.As(err, &dialog) && dialog.Res != nil {
		return dialog.Res.StatusCode
	}
	return 0
}

func oneCall(ctx context.Context, c config) (result outcome, category string) {
	if c.host == "" || c.tlsName == "" || c.roots == nil || c.port < 1 || c.port > 65535 ||
		net.ParseIP(c.bindHost).To4() == nil || c.creds.user == "" || c.creds.pass == "" ||
		!regexp.MustCompile(`^[0-9]{2,5}$`).MatchString(c.target) {
		return result, "invalid-config"
	}
	offer, err := mediaOfferFor(c.mediaProfile)
	if err != nil {
		return result, "invalid-media-profile"
	}
	result.mediaProfile = c.mediaProfile
	quiet := safesip.Logger
	ua, err := sipgo.NewUA(sipgo.WithUserAgenTLSConfig(&tls.Config{
		MinVersion: tls.VersionTLS12, RootCAs: c.roots, ServerName: c.tlsName,
	}), sipgo.WithUserAgentTransportLayerOptions(sip.WithTransportLayerLogger(quiet)),
		sipgo.WithUserAgentTransactionLayerOptions(sip.WithTransactionLayerLogger(quiet),
			sip.WithTransactionLayerUnhandledResponseHandler(func(*sip.Response) {})))
	if err != nil {
		return result, "local-ua"
	}
	defer ua.Close()
	dg := diago.NewDiago(ua, diago.WithTransport(diago.Transport{
		Transport: "tls", BindHost: c.bindHost, BindPort: 0,
		MediaSRTP: offer.mode, MediaDTLSConf: offer.dtls,
	}), diago.WithMediaConfig(diago.MediaConfig{Codecs: []media.Codec{media.CodecAudioAlaw}}),
		diago.WithLogger(quiet))
	uri := sip.Uri{Scheme: "sips", User: c.creds.user, Host: c.host, Port: c.port}
	uri.UriParams = sip.NewParams()
	uri.UriParams.Add("transport", "tls")
	registration, err := dg.RegisterTransaction(ctx, uri, diago.RegisterOptions{
		Username: c.creds.user, Password: c.creds.pass, Expiry: 90 * time.Second,
	})
	if err != nil {
		return result, "registration-setup"
	}
	registerCtx, stopRegister := context.WithTimeout(ctx, 8*time.Second)
	err = registration.Register(registerCtx)
	stopRegister()
	if err != nil {
		result.registerStatus = statusCategory(err)
		return result, "register-failed"
	}
	result.registered = true
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := registration.Unregister(stop); err == nil {
			result.unregistered = true
		} else if category == "pass" {
			category = "unregister-ambiguous"
		}
	}()
	// Eventphone documents sip: extension URIs even when the first hop is
	// authenticated SIP/TLS. Transport remains explicitly tls with verified
	// server name; this is not a UDP/TCP downgrade or automatic redial.
	recipient := sip.Uri{Scheme: "sip", User: c.target, Host: c.host, Port: c.port}
	recipient.UriParams = sip.NewParams()
	recipient.UriParams.Add("transport", "tls")
	inviteCtx, stopInvite := context.WithTimeout(ctx, 12*time.Second)
	call, med, err := dg.Invite(inviteCtx, recipient, diago.InviteOptions{
		Transport: "tls", Username: c.creds.user, Password: c.creds.pass,
		OnResponse: func(response *sip.Response) error {
			return observeMediaResponse(c.mediaProfile, response, &result)
		},
	})
	stopInvite()
	if err != nil {
		result.inviteStatus = statusCategory(err)
		return result, "invite-failed"
	}
	result.answered = true
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := call.Hangup(stop); err == nil {
			result.bye = true
		} else {
			category = "bye-ambiguous"
		}
		_ = call.Close()
	}()
	session := med.MediaSession()
	if session == nil || session.Raddr.IP.To4() == nil || session.Raddr.Port < 1 ||
		(!c.allowLoopback && (session.Raddr.IP.IsLoopback() || session.Raddr.IP.IsPrivate() ||
			session.Raddr.IP.IsMulticast() || session.Raddr.IP.IsUnspecified())) {
		return result, "provider-sdp-refused"
	}
	if !result.finalSDP || session.SecureRTP != offer.mode || !secureTransportMatches(c.mediaProfile, result.answerTransport) {
		result.downgradeRejected = result.answerTransport == "RTP/AVP" && offer.mode > 0
		return result, "media-downgrade-refused"
	}
	if codecs := session.CommonCodecs(); len(codecs) != 1 || codecs[0].PayloadType != 8 {
		return result, "provider-codec-refused"
	}
	reader, err := med.AudioReader()
	if err != nil {
		return result, "media-unavailable"
	}
	writer, err := med.AudioWriter()
	if err != nil {
		return result, "media-unavailable"
	}
	got := make(chan bool, 1)
	go func() {
		var buf [2048]byte
		for ctx.Err() == nil {
			n, err := reader.Read(buf[:])
			if err != nil {
				return
			}
			from, ok := session.ReadRTPFromAddr.(*net.UDPAddr)
			if !ok || !from.IP.Equal(session.Raddr.IP) || from.Port != session.Raddr.Port ||
				n != 160 || med.RTPPacketReader.PacketHeader.PayloadType != 8 {
				continue
			}
			select {
			case got <- true:
			default:
			}
			return
		}
	}()
	var silence [160]byte
	for i := range silence {
		silence[i] = 0xd5
	} // PCMA silence, not speech
	for i := 0; i < 50; i++ {
		if _, err := writer.Write(silence[:]); err != nil {
			return result, "media-send-failed"
		}
		select {
		case <-got:
			result.received = true
			result.authenticatedMedia = offer.mode > 0
			return result, "pass"
		case <-ctx.Done():
			return result, "media-timeout"
		default:
		}
	}
	select {
	case <-got:
		result.received = true
		result.authenticatedMedia = offer.mode > 0
		return result, "pass"
	case <-time.After(4 * time.Second):
		return result, "no-return-media"
	case <-ctx.Done():
		return result, "media-timeout"
	}
}

func main() {
	run := flag.Bool("run", false, "one attended REGISTER/INVITE/BYE/unregister; no redial")
	check := flag.Bool("check-credentials", false, "validate ignored dedicated credential structure without network")
	testID := flag.String("test-id", "first", "reviewed one-use attempt identity")
	approve := flag.Bool("approve-automated", false, "stage one owner-private automated destination; no network")
	flag.Parse()
	if !*run && !*check && !*approve {
		fmt.Println("DRY RUN: one dedicated test account, verified SIP/TLS, fixed one-use media profile, operator-approved numeric extension, bounded media/BYE/unregister")
		return
	}
	if (*run && *check) || (*approve && (*run || *check)) || flag.NArg() != 0 {
		slog.Error("provider test refused", "category", "conflicting-operations")
		os.Exit(2)
	}
	dirName, err := stageDir(*testID)
	if err != nil {
		slog.Error("provider test refused", "category", "unknown-one-use-stage")
		os.Exit(2)
	}
	mediaProfile, err := stageMediaProfile(*testID)
	if err != nil {
		slog.Error("provider test refused", "category", "unknown-media-profile")
		os.Exit(2)
	}
	if *approve {
		target := os.Getenv("ATA_PROVIDER_TEST_EXTENSION")
		if target == "" && *testID != "announcement" {
			source := os.Getenv("ATA_PROVIDER_APPROVED_TARGET_STAGE")
			if source != "" {
				target, err = readAutomatedTarget(source)
			}
		}
		if err != nil || !automatedStage(*testID) || prepareAutomatedTarget(dirName, target) != nil {
			slog.Error("provider test refused", "category", "automated-approval")
			os.Exit(2)
		}
		slog.Info("automated target approved in owner-private one-use stage; no network used")
		return
	}
	credentialPath := credentialFile
	if configured := os.Getenv("ATA_PROVIDER_TEST_CREDENTIAL_FILE"); configured != "" {
		credentialPath = configured
	}
	creds, err := loadCredentials(credentialPath)
	if err != nil {
		slog.Error("provider test refused", "category", "credential-file")
		os.Exit(2)
	}
	if *check {
		slog.Info("private provider test credential structure accepted; no network used")
		return
	}
	target := os.Getenv("ATA_PROVIDER_TEST_EXTENSION")
	if target == "" && automatedStage(*testID) {
		target, err = readAutomatedTarget(dirName)
	}
	if err != nil || !regexp.MustCompile(`^[0-9]{2,5}$`).MatchString(target) {
		slog.Error("provider test refused", "category", "missing-approved-target")
		os.Exit(2)
	}
	if !automatedStage(*testID) || requireAutomatedTarget(dirName, target) != nil {
		slog.Error("provider test refused", "category", "unapproved-automated-target")
		os.Exit(2)
	}
	bind, err := localBindIP(provider, port)
	if err != nil {
		slog.Error("provider test refused", "category", "lan-route")
		os.Exit(2)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		slog.Error("provider test refused", "category", "ca-roots")
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 32*time.Second)
	defer cancel()
	if err := reserveAttempt(dirName); err != nil {
		slog.Error("provider test refused", "category", "one-use-stage")
		os.Exit(2)
	}
	result, category := oneCall(ctx, config{host: provider, tlsName: provider, port: port, target: target,
		roots: roots, bindHost: bind, creds: creds, mediaProfile: mediaProfile})
	if err := recordResult(dirName, category, result); err != nil {
		slog.Error("provider test outcome needs manual review", "category", "stage-result-ambiguous")
		os.Exit(2)
	}
	slog.Info("one-shot provider test finished", "category", category,
		"registered", result.registered, "register_status", result.registerStatus,
		"invite_status", result.inviteStatus, "answered", result.answered,
		"media_returned", result.received, "bye", result.bye,
		"unregistered", result.unregistered, "media_profile", result.mediaProfile,
		"answer_transport", result.answerTransport, "keying", result.keying,
		"suite", result.suite, "peer_binding", result.peerBinding,
		"authenticated_media", result.authenticatedMedia,
		"downgrade_rejected", result.downgradeRejected,
		"provisional_sdp_count", result.provisionalSDPCount,
		"provisional_transport", result.provisionalTransport,
		"final_sdp", result.finalSDP,
		"keying_observation", result.keyingObservation,
		"suite_observation", result.suiteObservation,
		"crypto_attribute_count", result.cryptoAttributeCount,
		"inline_key_present", result.inlineKeyPresent)
	if category != "pass" {
		os.Exit(2)
	}
}
