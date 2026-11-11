package main

// Synthetic regression is a mode of this already-inventoried ARI caller.
// The same canonical HTTPS+leaf-pinned constructor in main.go owns both
// modes. No provider destination, SIP socket or credential is accepted.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"syscall"
	"time"

	"example.com/ata/voip-gateway/internal/asterisk"
	"example.com/ata/voip-gateway/internal/calls"
	"example.com/ata/voip-gateway/internal/regressionutil"
)

const regressionPeerPath = "/tmp/vgw-regression-ari-peer.crt" // public synthetic leaf

var regressionNonce = regexp.MustCompile(`^[a-f0-9]{32}$`)
var regressionPassword = regexp.MustCompile(`^[A-Za-z0-9_-]{32,64}$`)

func regressionInputs() (user, password, expected string, peer *x509.Certificate, err error) {
	user, password, expected = os.Getenv("HOME_MOCK_ARI_USER"), os.Getenv("HOME_MOCK_ARI_PASSWORD"), os.Getenv("HOME_MOCK_NONCE")
	if user != "home-control" || !regressionPassword.MatchString(password) || !regressionNonce.MatchString(expected) {
		return "", "", "", nil, errors.New("synthetic owner refused")
	}
	file, openErr := os.OpenFile(regressionPeerPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if openErr != nil {
		return "", "", "", nil, errors.New("synthetic peer unavailable")
	}
	defer file.Close()
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 16384 {
		return "", "", "", nil, errors.New("synthetic peer shape refused")
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, 16385))
	if readErr != nil || len(raw) != int(info.Size()) {
		return "", "", "", nil, errors.New("synthetic peer read refused")
	}
	block, remaining := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(remaining) != 0 {
		return "", "", "", nil, errors.New("synthetic peer PEM refused")
	}
	peer, err = x509.ParseCertificate(block.Bytes)
	if err != nil || peer.VerifyHostname("127.0.0.1") != nil {
		return "", "", "", nil, errors.New("synthetic peer identity refused")
	}
	return user, password, expected, peer, nil
}

func regressionClient(peer *x509.Certificate) (*http.Client, *http.Transport) {
	roots := x509.NewCertPool()
	roots.AddCert(peer)
	pinned := sha256.Sum256(peer.Raw)
	policy := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: "127.0.0.1", RootCAs: roots,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("synthetic ARI peer absent")
			}
			actual := sha256.Sum256(state.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(actual[:], pinned[:]) != 1 {
				return errors.New("synthetic ARI peer changed")
			}
			return nil
		}}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: policy,
		TLSHandshakeTimeout: 2 * time.Second,
		DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
			if network != "tcp" || target != "127.0.0.1:8089" {
				return nil, errors.New("synthetic ARI address refused")
			}
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", target)
		}}
	return &http.Client{Transport: transport, Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, transport
}

func regressionSettled(ctx context.Context, user, password string, peer *x509.Certificate) bool {
	client, transport := regressionClient(peer)
	defer transport.CloseIdleConnections()
	return regressionutil.WaitForZero(ctx, func(current context.Context, path string) (int, []byte, error) {
		req, err := http.NewRequestWithContext(current, http.MethodGet, "https://127.0.0.1:8089"+path, nil)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+password)))
		response, err := client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 1025))
		return response.StatusCode, body, err
	})
}

func regressionCall(ctx context.Context, client *asterisk.Client, events <-chan asterisk.BrowserStart,
	gone <-chan error, expected, user, password string, peer *x509.Certificate) string {
	var start asterisk.BrowserStart
	select {
	case <-ctx.Done():
		return "MOCK_NO_BROWSER_CHANNEL"
	case <-gone:
		return "MOCK_SUBSCRIPTION_GONE"
	case event, ok := <-events:
		if !ok {
			return "MOCK_SUBSCRIPTION_GONE"
		}
		start = event
	}
	read, done := context.WithTimeout(ctx, 3*time.Second)
	dial, err := client.ReadBrowserDial(read, start)
	done()
	if err != nil || dial.Destination != "1234" || dial.Nonce != expected {
		return "MOCK_BROWSER_ADMISSION_REFUSED"
	}
	fmt.Println("MOCK_BROWSER_ADMITTED")
	media, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return "MOCK_MEDIA_SOCKET_REFUSED"
	}
	defer media.Close()
	attached, err := client.AttachBrowser(ctx, asterisk.BrowserStart{ChannelID: dial.ChannelID, Nonce: dial.Nonce}, media)
	if err != nil {
		return "MOCK_ATTACH_REFUSED"
	}
	fmt.Println("MOCK_ATTACH_OK")
	defer attached.Close()
	from, to := make(chan calls.AudioFrame, 2), make(chan calls.AudioFrame, 2)
	mediaID := "0123456789abcdef0123456789abcdef" // synthetic only
	stopRelay, err := attached.StartBrowserRelay(ctx, mediaID, media, asterisk.Frames{FromSIP: to, ToSIP: from})
	if err != nil {
		return "MOCK_RELAY_REFUSED"
	}
	defer stopRelay()
	if client.AnswerBrowser(ctx, asterisk.BrowserStart{ChannelID: dial.ChannelID, Nonce: dial.Nonce}) != nil {
		return "MOCK_ANSWER_REFUSED"
	}
	fmt.Println("MOCK_PROVIDER_200_ANSWERED")
	var silence calls.AudioFrame
	silence.ID = mediaID
	for i := range silence.Payload {
		silence.Payload[i] = 0xd5
	}
	select {
	case to <- silence:
	case <-time.After(2 * time.Second):
		return "MOCK_AUDIO_BUFFER_REFUSED"
	}
	select {
	case <-time.After(5 * time.Second):
	case <-ctx.Done():
		return "MOCK_DIALOG_UNCERTAIN"
	}
	if stopRelay() != nil || attached.Close() != nil {
		return "MOCK_RESOURCE_CLEANUP_REFUSED"
	}
	settle, finish := context.WithTimeout(context.Background(), 10*time.Second)
	defer finish()
	if !regressionSettled(settle, user, password, peer) {
		return "MOCK_CLEANUP_UNKNOWN"
	}
	return "MOCK_PROVIDER_SETTLED_LOCAL_ONLY"
}
