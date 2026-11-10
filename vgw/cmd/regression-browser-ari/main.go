// Disposable browser→real Asterisk→VGW synthetic response regression.
// This executable cannot contact Eventphone or originate a provider SIP call.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"syscall"
	"time"

	"example.com/ata/voip-gateway/internal/asterisk"
	"example.com/ata/voip-gateway/internal/calls"
)

var nonce = regexp.MustCompile(`^[a-f0-9]{32}$`)

func localClient() (*http.Client, *http.Transport) {
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "127.0.0.1:8088" {
				return nil, errors.New("foreign regression ARI endpoint")
			}
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", address)
		}}
	return &http.Client{Transport: transport, Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, transport
}

// Only a bounded GET may be repeated after a completed, exact-owned Close.
// Never retry SIP, ARI DELETE, media frames or an ambiguous provider response.
func waitForZero(ctx context.Context, get func(context.Context, string) (int, []byte, error)) bool {
	for {
		allEmpty := true
		for _, path := range []string{"/ari/channels", "/ari/bridges"} {
			code, body, err := get(ctx, path)
			if err != nil || code != http.StatusOK || len(body) > 1024 {
				return false
			}
			var entries []json.RawMessage
			if json.Unmarshal(body, &entries) != nil || entries == nil {
				return false
			}
			if len(entries) != 0 {
				allEmpty = false
			}
		}
		if allEmpty {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func settled(ctx context.Context, user, password string) bool {
	client, transport := localClient()
	defer transport.CloseIdleConnections()
	return waitForZero(ctx, func(current context.Context, path string) (int, []byte, error) {
		req, err := http.NewRequestWithContext(current, http.MethodGet, "http://127.0.0.1:8088"+path, nil)
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

func run(out io.Writer) string {
	user, password, expected := os.Getenv("HOME_MOCK_ARI_USER"), os.Getenv("HOME_MOCK_ARI_PASSWORD"), os.Getenv("HOME_MOCK_NONCE")
	if user != "home-control" || len(password) < 32 || len(password) > 64 || !nonce.MatchString(expected) {
		return "MOCK_CONFIG_REFUSED"
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	ari, err := asterisk.New(asterisk.Config{BaseURL: "http://127.0.0.1:8088", Username: user,
		Password: password, Target: asterisk.BrowserIngress, Timeout: 3 * time.Second})
	if err != nil {
		return "MOCK_ARI_REFUSED"
	}
	defer ari.Close()
	events, gone, err := ari.SubscribeBrowser(ctx)
	if err != nil {
		return "MOCK_SUBSCRIBE_REFUSED"
	}
	_, _ = fmt.Fprintln(out, "MOCK_WATCHER_READY")
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
	dial, err := ari.ReadBrowserDial(read, start)
	done()
	if err != nil || dial.Destination != "1234" || dial.Nonce != expected {
		return "MOCK_BROWSER_ADMISSION_REFUSED"
	}
	_, _ = fmt.Fprintln(out, "MOCK_BROWSER_ADMITTED")
	media, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return "MOCK_MEDIA_SOCKET_REFUSED"
	}
	defer media.Close()
	attached, err := ari.AttachBrowser(ctx, asterisk.BrowserStart{ChannelID: dial.ChannelID, Nonce: dial.Nonce}, media)
	if err != nil {
		return "MOCK_ATTACH_REFUSED"
	}
	_, _ = fmt.Fprintln(out, "MOCK_ATTACH_OK")
	defer attached.Close()
	from := make(chan calls.AudioFrame, 2)
	to := make(chan calls.AudioFrame, 2)
	mediaID := "0123456789abcdef0123456789abcdef" // synthetic local only
	stopRelay, err := attached.StartBrowserRelay(ctx, mediaID, media, asterisk.Frames{FromSIP: to, ToSIP: from})
	if err != nil {
		return "MOCK_RELAY_REFUSED"
	}
	defer stopRelay()
	if ari.AnswerBrowser(ctx, asterisk.BrowserStart{ChannelID: dial.ChannelID, Nonce: dial.Nonce}) != nil {
		return "MOCK_ANSWER_REFUSED"
	}
	_, _ = fmt.Fprintln(out, "MOCK_PROVIDER_200_ANSWERED")
	var frame calls.AudioFrame
	frame.ID = mediaID
	for i := range frame.Payload {
		frame.Payload[i] = 0xd5
	}
	select {
	case to <- frame:
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
	check, finish := context.WithTimeout(context.Background(), 10*time.Second)
	defer finish()
	if !settled(check, user, password) {
		return "MOCK_CLEANUP_UNKNOWN"
	}
	return "MOCK_PROVIDER_SETTLED_LOCAL_ONLY"
}

func main() { fmt.Println(run(os.Stdout)) }
