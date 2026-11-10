package asterisk

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"example.com/ata/voip-gateway/internal/calls"
	"example.com/ata/voip-gateway/internal/safesip"
	"github.com/emiago/diago"
	"github.com/emiago/diago/media"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

func TestErrorCategoryNeverReflectsUntrustedText(t *testing.T) {
	if ErrorCategory(errors.New("ARI bridge creation failed")) != "bridge-create" {
		t.Fatal("known ARI category missing")
	}
	if got := ErrorCategory(errors.New("Authorization: secret\r\ncaller-data")); got != "other" {
		t.Fatal("untrusted error escaped category allowlist")
	}
	if got := ErrorCategory(errors.New("ARI RTP address not local")); got != "media-address-nonloopback" {
		t.Fatal("safe media address diagnostic missing")
	}
}

const localID = "0123456789abcdef0123456789abcdef"

func ownedRTP(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

type mockARI struct {
	t                  *testing.T
	server             *httptest.Server
	rtpPort            int
	wantMediaPort      int
	mu                 sync.Mutex
	steps              []string
	targetTries        int
	callID             string
	failAt             string
	failDeletes        bool
	conflictBridge     bool
	badAddress         string
	badPort            string
	badMediaID         string
	badContentType     bool
	largeResponse      bool
	malformedJSON      bool
	started            chan struct{}
	cleaned            chan struct{}
	subscribed         chan struct{}
	dropSubscription   chan struct{}
	badWebsocketProof  bool
	bridgeChannels     []string
	onlyMedia          bool
	targetApp          string
	targetState        string
	pingOnSubscribe    bool
	oversizedEvent     bool
	pongSeen           chan struct{}
	wantApp            string
	wantEndpoint       string
	browserEvent       []byte
	secondBrowserEvent []byte
	browserExistingID  string
	mediaEvents        chan []byte
	mediaDelivered     chan struct{}
}

func startARI(t *testing.T, rtpPort int) *mockARI {
	t.Helper()
	m := &mockARI{t: t, rtpPort: rtpPort, started: make(chan struct{}, 1), cleaned: make(chan struct{}, 1), subscribed: make(chan struct{}, 1), wantApp: appName, wantEndpoint: endpoint}
	m.server = httptest.NewTLSServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.server.Close)
	return m
}

func (m *mockARI) client(t *testing.T) *Client {
	return m.clientWithTarget(t, LabEcho)
}

func (m *mockARI) clientWithTarget(t *testing.T, target Target) *Client {
	t.Helper()
	c, err := New(Config{BaseURL: m.server.URL, PeerCertificate: m.server.Certificate(), Username: "lab", Password: "only-for-tests", Timeout: time.Second, Target: target})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func (m *mockARI) handle(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if !ok || user != "lab" || pass != "only-for-tests" {
		m.t.Error("local ARI Basic authentication missing")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.URL.RawQuery != "" && strings.Contains(r.URL.RawQuery, "only-for-tests") {
		m.t.Error("secret in ARI URL")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if r.URL.Path == "/ari/events" {
		if r.Method != http.MethodGet || r.URL.RawQuery != "app="+m.wantApp ||
			!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") ||
			r.Header.Get("Sec-WebSocket-Version") != "13" {
			m.t.Error("incorrect fixed Stasis subscription")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		key := r.Header.Get("Sec-WebSocket-Key")
		if nonce, err := base64.StdEncoding.DecodeString(key); err != nil || len(nonce) != 16 {
			m.t.Error("invalid Stasis WebSocket nonce")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			m.t.Error("mock Stasis handshake unavailable")
			return
		}
		defer conn.Close()
		proof := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		if m.badWebsocketProof {
			proof = sha1.Sum([]byte("incorrect handshake proof"))
		}
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: %s\r\n\r\n",
			base64.StdEncoding.EncodeToString(proof[:]))
		select {
		case m.subscribed <- struct{}{}:
		default:
		}
		if len(m.browserEvent) != 0 {
			_ = wsutil.WriteServerMessage(conn, ws.OpText, m.browserEvent)
		}
		if len(m.secondBrowserEvent) != 0 {
			_ = wsutil.WriteServerMessage(conn, ws.OpText, m.secondBrowserEvent)
		}
		if m.mediaEvents != nil {
			for i := 0; i < 2; i++ {
				select {
				case local := <-m.mediaEvents:
					if err := wsutil.WriteServerMessage(conn, ws.OpText, local); err != nil {
						m.t.Error("owned ExternalMedia event delivery failed")
						return
					}
					if m.mediaDelivered != nil {
						m.mediaDelivered <- struct{}{}
					}
				case <-time.After(2 * time.Second):
					return
				}
			}
		}
		if m.pingOnSubscribe {
			if err := wsutil.WriteServerMessage(conn, ws.OpPing, []byte("local-health")); err != nil {
				m.t.Error("mock Stasis ping failed")
				return
			}
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			messages, err := wsutil.ReadClientMessage(conn, nil)
			if err != nil || len(messages) != 1 || messages[0].OpCode != ws.OpPong ||
				!bytes.Equal(messages[0].Payload, []byte("local-health")) {
				m.t.Error("ARI Stasis subscription did not answer a bounded ping")
				return
			}
			_ = conn.SetReadDeadline(time.Time{})
			m.pongSeen <- struct{}{}
		}
		if m.oversizedEvent {
			_ = wsutil.WriteServerMessage(conn, ws.OpText, bytes.Repeat([]byte("X"), 4097))
		}
		if m.dropSubscription != nil {
			<-m.dropSubscription
		} else {
			_, _ = io.Copy(io.Discard, conn)
		}
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := r.Method + " " + r.URL.Path
	m.steps = append(m.steps, key)
	if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/ari/bridges/b-") && m.callID == "" {
		m.callID = strings.TrimPrefix(r.URL.Path, "/ari/bridges/b-")
		if !localCallID(m.callID) {
			m.t.Error("nonlocal bridge ID")
		}
	}
	if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/ari/bridges/b-") {
		if m.largeResponse {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(strings.Repeat("X", 10000)))
			return
		}
		if m.malformedJSON {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte("{untrusted: invalid}"))
			return
		}
	}
	if !m.badContentType {
		w.Header().Set("Content-Type", "application/json")
	}
	if m.conflictBridge && r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/ari/bridges/b-") {
		w.WriteHeader(http.StatusConflict)
		return
	}
	if m.failDeletes && r.Method == http.MethodDelete {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if key == m.failAt {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("caller-controlled\r\nSensitive: data"))
		return
	}
	bridge, mediaID, targetID := "b-"+m.callID, "m-"+m.callID, "t-"+m.callID
	if m.browserExistingID != "" {
		targetID = m.browserExistingID
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/ari/bridges/"+bridge:
		if r.URL.Query().Get("type") != "mixing" {
			m.t.Error("bridge not mixing")
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"` + bridge + `"}`))
	case r.Method == http.MethodGet && r.URL.Path == "/ari/bridges/"+bridge:
		channels := []string{mediaID, targetID}
		if m.onlyMedia {
			channels = []string{mediaID}
		}
		if m.bridgeChannels != nil {
			channels = m.bridgeChannels
		}
		_ = json.NewEncoder(w).Encode(struct {
			ID       string   `json:"id"`
			Channels []string `json:"channels"`
		}{bridge, channels})
	case m.browserExistingID != "" && r.Method == http.MethodGet && r.URL.Path == "/ari/channels/"+targetID:
		_, _ = w.Write([]byte(`{"id":"1693496751.43","name":"PJSIP/webrtc-lan-000000ab","state":"Ring","dialplan":{"context":"from-webrtc","exten":"e-1234","app_name":"Stasis"}}`))
	case m.browserExistingID != "" && r.Method == http.MethodGet && r.URL.Path == "/ari/channels/"+targetID+"/variable":
		if r.URL.Query().Get("variable") != "PJSIP_HEADER(read,X-VGW-Nonce)" {
			m.t.Error("ARI read a dynamic SIP header")
		}
		_, _ = w.Write([]byte(`{"value":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
	case r.Method == http.MethodPost && r.URL.Path == "/ari/channels/externalMedia":
		q := r.URL.Query()
		if q.Get("app") != m.wantApp || q.Get("format") != "alaw" ||
			q.Get("encapsulation") != "rtp" || q.Get("transport") != "udp" ||
			q.Get("connection_type") != "client" || q.Get("channelId") != mediaID ||
			q.Get("external_host") == "" || !strings.HasPrefix(q.Get("external_host"), "127.0.0.1:") ||
			(m.wantMediaPort != 0 && q.Get("external_host") != fmt.Sprintf("127.0.0.1:%d", m.wantMediaPort)) {
			m.t.Error("unexpected External Media parameters")
		}
		if m.mediaEvents != nil {
			m.mediaEvents <- []byte(fmt.Sprintf(`{"type":"StasisStart","application":"%s","args":[],"channel":{"id":"%s","name":"UnicastRTP/127.0.0.1:41000","dialplan":{"app_name":"Stasis"}}}`, m.wantApp, mediaID))
			select {
			case <-m.mediaDelivered:
			case <-time.After(time.Second):
				m.t.Error("owned media event did not reach subscription before REST response")
			}
		}
		w.WriteHeader(http.StatusCreated)
		if m.badMediaID != "" {
			mediaID = m.badMediaID
		}
		_, _ = w.Write([]byte(`{"id":"` + mediaID + `"}`))
	case r.Method == http.MethodGet && r.URL.Path == "/ari/channels/"+mediaID+"/variable":
		value := ""
		switch r.URL.Query().Get("variable") {
		case "UNICASTRTP_LOCAL_ADDRESS":
			value = "127.0.0.1"
			if m.badAddress != "" {
				value = m.badAddress
			}
		case "UNICASTRTP_LOCAL_PORT":
			value = fmt.Sprint(m.rtpPort)
			if m.badPort != "" {
				value = m.badPort
			}
		default:
			m.t.Error("unexpected ARI variable")
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"value": value})
	case r.Method == http.MethodPost && r.URL.Path == "/ari/bridges/"+bridge+"/addChannel":
		ch := r.URL.Query().Get("channel")
		if ch == targetID {
			m.targetTries++
			if m.targetTries == 1 {
				w.WriteHeader(http.StatusUnprocessableEntity) // Stasis not ready
				return
			}
		} else if ch != mediaID {
			m.t.Error("unexpected channel in bridge")
		}
		if ch == targetID {
			select {
			case m.started <- struct{}{}:
			default:
			}
		}
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && r.URL.Path == "/ari/channels/create":
		q := r.URL.Query()
		if q.Get("endpoint") != m.wantEndpoint || q.Get("app") != m.wantApp ||
			q.Get("channelId") != targetID || q.Get("formats") != "alaw" {
			m.t.Error("dynamic or incorrect ARI originate target")
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"` + targetID + `"}`))
	case r.Method == http.MethodPost && r.URL.Path == "/ari/channels/"+targetID+"/dial":
		w.WriteHeader(http.StatusNoContent)
	case m.browserExistingID != "" && r.Method == http.MethodPost && r.URL.Path == "/ari/channels/"+targetID+"/answer":
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet && r.URL.Path == "/ari/channels/"+targetID:
		app := m.targetApp
		if app == "" {
			app = "Stasis"
		}
		state := m.targetState
		if state == "" {
			state = "Up"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": targetID, "state": state, "dialplan": map[string]string{"app_name": app},
		})
	case r.Method == http.MethodDelete && (r.URL.Path == "/ari/channels/"+targetID ||
		r.URL.Path == "/ari/channels/"+mediaID || r.URL.Path == "/ari/bridges/"+bridge):
		if m.mediaEvents != nil && r.URL.Path == "/ari/channels/"+mediaID {
			m.mediaEvents <- []byte(fmt.Sprintf(`{"type":"StasisEnd","application":"%s","channel":{"id":"%s","name":"UnicastRTP/127.0.0.1:41000"}}`, m.wantApp, mediaID))
		}
		if r.URL.Path == "/ari/bridges/"+bridge {
			select {
			case m.cleaned <- struct{}{}:
			default:
			}
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		m.t.Error("unexpected ARI request path or method")
		w.WriteHeader(http.StatusNotFound)
	}
}

func (m *mockARI) snapshot() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.steps...)
}

func TestFixedLabARIFlowAndCleanup(t *testing.T) {
	if endpoint != "Local/echo@eventphone-gateway-lab/n" {
		t.Fatal("local ARI target may optimize away its only Echo channel")
	}
	asteriskRTP, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer asteriskRTP.Close()
	m := startARI(t, asteriskRTP.LocalAddr().(*net.UDPAddr).Port)
	c := m.client(t)
	gatewayRTP, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer gatewayRTP.Close()
	m.wantMediaPort = gatewayRTP.LocalAddr().(*net.UDPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s, err := c.Start(ctx, localID, gatewayRTP.(*net.UDPConn))
	if err != nil {
		t.Fatal(err)
	}
	if s.LocalPort != m.rtpPort || m.targetTries != 2 {
		t.Fatal("ARI peer media address or Stasis wait missing")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal("second cleanup failed")
	}
	steps := m.snapshot()
	if len(steps) != 14 || steps[8] != "GET /ari/bridges/b-"+m.callID ||
		steps[9] != "POST /ari/channels/t-"+m.callID+"/dial" ||
		steps[10] != "GET /ari/bridges/b-"+m.callID ||
		steps[len(steps)-1] != "DELETE /ari/bridges/b-"+m.callID || m.callID == localID {
		t.Fatal("missing owned ARI resources or cleanup")
	}
}

func TestFixedDeskTargetUsesOwnedContextAndCleansOnlyItsResources(t *testing.T) {
	if deskEndpoint != "Local/desk@vgw-owned-ata/n" || deskApp != "eventphone-vgw-desk" {
		t.Fatal("desk target must be the new fixed owned APU context")
	}
	m := startARI(t, ownedRTP(t).LocalAddr().(*net.UDPAddr).Port)
	m.wantApp, m.wantEndpoint = deskApp, deskEndpoint
	c := m.clientWithTarget(t, ATADesk)
	if c.app != deskApp || c.endpoint != deskEndpoint {
		t.Fatal("untrusted input selected the ARI app/target")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s, err := c.Start(ctx, localID, ownedRTP(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{BaseURL: m.server.URL, PeerCertificate: m.server.Certificate(), Username: "lab", Password: "only-for-tests", Timeout: time.Second, Target: 255}); err == nil {
		t.Fatal("unknown ARI destination accepted")
	}
}

func TestReadOnlyBridgeMemberClassNeverTrustsRemoteChannelID(t *testing.T) {
	m := startARI(t, 20000)
	c := m.client(t)
	s, err := c.Start(context.Background(), localID, ownedRTP(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, test := range []struct {
		channels []string
		want     string
	}{
		{[]string{s.media, s.target}, "both"},
		{[]string{s.media}, "media-only"},
		{[]string{s.target}, "target-only"},
		{[]string{}, "none"},
	} {
		m.mu.Lock()
		m.bridgeChannels = test.channels
		m.mu.Unlock()
		got, err := s.BridgeMemberClass(context.Background())
		if err != nil || got != test.want {
			t.Fatal("owned bridge member class incorrect")
		}
	}
	for _, invalid := range [][]string{{s.media, "attacker\r\nInjected"}, {s.media, s.media}, {s.media, s.target, s.media}} {
		m.mu.Lock()
		m.bridgeChannels = invalid
		m.mu.Unlock()
		if got, err := s.BridgeMemberClass(context.Background()); err == nil || got != "" ||
			strings.Contains(err.Error(), "Injected") {
			t.Fatal("remote ARI channel ID reflected into diagnostic")
		}
	}
}

func TestReadOnlyTargetStatusNeverReflectsUntrustedApp(t *testing.T) {
	m := startARI(t, 20000)
	c := m.client(t)
	s, err := c.Start(context.Background(), localID, ownedRTP(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, test := range []struct{ app, state, want string }{
		{"Stasis", "Up", "up-stasis"},
		{"Echo", "Up", "up-other"},
		{"Stasis", "Down", "down-stasis"},
	} {
		m.mu.Lock()
		m.targetApp, m.targetState = test.app, test.state
		m.mu.Unlock()
		got, err := s.TargetStatusClass(context.Background())
		if err != nil || got != test.want {
			t.Fatal("local target Stasis state classification failed")
		}
	}
	m.mu.Lock()
	m.targetApp, m.targetState = "other\r\nSensitive: injected", "Up"
	m.mu.Unlock()
	if got, err := s.TargetStatusClass(context.Background()); err != nil || got != "up-other" {
		t.Fatal("untrusted target application name escaped allowlist")
	}
}

func TestOptimisticARI204WithoutSecondBridgeMemberFailsClosed(t *testing.T) {
	m := startARI(t, 20000)
	m.onlyMedia = true
	c := m.client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := c.Start(ctx, localID, ownedRTP(t)); ErrorCategory(err) != "target-membership" {
		t.Fatal("optimistic 204 accepted an empty Local/Echo bridge")
	}
	steps := m.snapshot()
	var originated, targetAdds, cleanups, dials int
	for _, step := range steps {
		if step == "POST /ari/channels/create" {
			originated++
		}
		if step == "POST /ari/bridges/b-"+m.callID+"/addChannel" {
			targetAdds++
		}
		if strings.HasPrefix(step, "DELETE ") {
			cleanups++
		}
		if strings.HasSuffix(step, "/dial") {
			dials++
		}
	}
	if originated != 1 || targetAdds != 3 || cleanups != 3 || dials != 0 {
		// One media add, first target add gets 422, one target add returns
		// 204; only bounded read-only GETs may follow.
		t.Fatal("failed bridge membership caused a side-effecting replay or orphan")
	}
}

func TestStasisSubscriptionRejectsBadProofAndDetectsDisconnect(t *testing.T) {
	invalid := startARI(t, 20000)
	invalid.badWebsocketProof = true
	c := invalid.client(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := c.Subscribe(ctx); ErrorCategory(err) != "stasis-subscribe" {
		t.Fatal("invalid WebSocket handshake was accepted")
	}
	m := startARI(t, 20000)
	m.dropSubscription = make(chan struct{})
	c = m.client(t)
	gone, err := c.Subscribe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-m.subscribed:
	default:
		t.Fatal("mock Stasis subscription was not opened")
	}
	close(m.dropSubscription)
	select {
	case err := <-gone:
		if ErrorCategory(err) != "stasis-lost" {
			t.Fatal("disconnected Stasis socket did not fail closed")
		}
	case <-time.After(time.Second):
		t.Fatal("subscription disconnect was not detected")
	}
}

func TestStasisSubscriptionAnswersPingAndRefusesOversizedEvents(t *testing.T) {
	m := startARI(t, 20000)
	m.pingOnSubscribe = true
	m.oversizedEvent = true
	m.pongSeen = make(chan struct{}, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c := m.client(t)
	gone, err := c.Subscribe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-m.pongSeen:
	case <-ctx.Done():
		t.Fatal("bounded Stasis ping did not receive a masked Pong")
	}
	select {
	case err := <-gone:
		if ErrorCategory(err) != "stasis-lost" {
			t.Fatal("oversized untrusted ARI event did not fail closed")
		}
	case <-ctx.Done():
		t.Fatal("oversized ARI event was not rejected")
	}
}

func TestBrowserStasisSubscriptionEmitsOnlyReviewedChannel(t *testing.T) {
	m := startARI(t, 20000)
	m.wantApp = browserApp
	m.browserEvent = []byte(validBrowserEvent)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	c := m.clientWithTarget(t, BrowserIngress)
	if _, err := c.Subscribe(ctx); ErrorCategory(err) != "browser-admission" {
		t.Fatal("browser app allowed discard-only subscription")
	}
	if _, err := c.Start(ctx, localID, ownedRTP(t)); ErrorCategory(err) != "browser-admission" {
		t.Fatal("browser inlet originated a different Asterisk target")
	}
	events, gone, err := c.SubscribeBrowser(ctx)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case start := <-events:
		if start.ChannelID != "1693496751.43" {
			t.Fatal("typed browser subscriber emitted wrong channel identity")
		}
	case <-ctx.Done():
		t.Fatal("typed browser StasisStart was not delivered")
	}
	cancel()
	select {
	case <-gone:
	case <-time.After(time.Second):
		t.Fatal("browser Stasis socket did not close after cancellation")
	}
	for _, step := range m.snapshot() {
		if strings.HasPrefix(step, "POST ") {
			t.Fatal("browser event subscription wrote a PBX resource")
		}
	}
}

func TestBrowserStasisRejectsForeignEventAndSecondCallWithoutLeak(t *testing.T) {
	for _, candidate := range [][]byte{
		[]byte(strings.Replace(validBrowserEvent, "from-webrtc", "from-ata", 1)),
		[]byte(strings.Repeat("X", 4097)),
	} {
		m := startARI(t, 20000)
		m.wantApp = browserApp
		m.browserEvent = candidate
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		c := m.clientWithTarget(t, BrowserIngress)
		events, gone, err := c.SubscribeBrowser(ctx)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		select {
		case lost := <-gone:
			if ErrorCategory(lost) != "stasis-lost" {
				t.Fatal("foreign browser event did not terminate owned subscription")
			}
		case <-ctx.Done():
			t.Fatal("foreign browser event did not fail closed")
		}
		for event := range events {
			if event.ChannelID != "" {
				cancel()
				t.Fatal("foreign channel escaped browser admission")
			}
		}
		cancel()
	}
	m := startARI(t, 20000)
	m.wantApp = browserApp
	m.browserEvent = []byte(validBrowserEvent)
	m.secondBrowserEvent = []byte(validBrowserEvent)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c := m.clientWithTarget(t, BrowserIngress)
	events, gone, err := c.SubscribeBrowser(ctx)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case lost := <-gone:
		if ErrorCategory(lost) != "stasis-lost" {
			t.Fatal("second browser channel was not rejected")
		}
	case <-ctx.Done():
		t.Fatal("second browser channel was not bounded")
	}
	if first := <-events; first.ChannelID != "1693496751.43" {
		t.Fatal("invalid first event after second channel rejection")
	}
}

func TestBrowserStasisIgnoresOnlyLocallyTrackedExternalMedia(t *testing.T) {
	const id = "m-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	valid := []byte(`{"type":"StasisStart","application":"eventphone-vgw-browser","args":[],"channel":{"id":"` + id + `","name":"UnicastRTP/127.0.0.1:41000"}}`)
	owned := func(candidate string) bool { return candidate == id }
	if _, ok := ownedExternalMediaEvent(valid, "StasisStart", owned); !ok {
		t.Fatal("locally generated ExternalMedia event closed the browser subscription")
	}
	for _, candidate := range []string{
		strings.Replace(string(valid), id, "m-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1),
		strings.Replace(string(valid), "UnicastRTP/", "PJSIP/", 1),
		strings.Replace(string(valid), `"application":"eventphone-vgw-browser"`, `"application":"foreign"`, 1),
	} {
		if _, ok := ownedExternalMediaEvent([]byte(candidate), "StasisStart", owned); ok {
			t.Fatal("foreign or spoofed media StasisStart bypassed browser admission")
		}
	}
	rtp := ownedRTP(t)
	m := startARI(t, rtp.LocalAddr().(*net.UDPAddr).Port)
	m.wantApp = browserApp
	m.browserExistingID = "1693496751.43"
	m.browserEvent = []byte(validBrowserEvent)
	m.mediaEvents = make(chan []byte, 2)
	m.mediaDelivered = make(chan struct{}, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	c := m.clientWithTarget(t, BrowserIngress)
	events, gone, err := c.SubscribeBrowser(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var start BrowserStart
	select {
	case start = <-events:
	case <-ctx.Done():
		t.Fatal("owned browser event not delivered")
	}
	session, err := c.AttachBrowser(ctx, start, rtp)
	if err != nil {
		t.Fatal("owned media StasisStart prevented browser bridge attachment")
	}
	select {
	case <-gone:
		t.Fatal("owned media event killed the ARI browser subscription")
	default:
	}
	if session.Close() != nil {
		t.Fatal("owned bridge/media cleanup failed")
	}
	select {
	case <-m.mediaDelivered: // externally created media StasisEnd reached browser socket
	case <-time.After(time.Second):
		t.Fatal("owned media end did not reach ARI subscription")
	}
	limit := time.Now().Add(time.Second)
	for c.ownsMediaID(session.media) && time.Now().Before(limit) {
		time.Sleep(time.Millisecond)
	}
	if c.ownsMediaID(session.media) {
		t.Fatal("definite media StasisEnd did not release its local ID")
	}
}

func TestAttachBrowserBridgesExistingCallerButNeverDeletesOrDialsIt(t *testing.T) {
	rtp := ownedRTP(t)
	m := startARI(t, rtp.LocalAddr().(*net.UDPAddr).Port)
	m.wantApp = browserApp
	m.browserExistingID = "1693496751.43"
	c := m.clientWithTarget(t, BrowserIngress)
	start, err := ParseBrowserStart([]byte(validBrowserEvent))
	if err != nil {
		t.Fatal(err)
	}
	session, err := c.AttachBrowser(context.Background(), start, rtp)
	if err != nil {
		t.Fatal(err)
	}
	if session.target != start.ChannelID || session.targetAttempted {
		t.Fatal("browser-owned channel was misclassified as gateway-owned")
	}
	if state, err := session.BridgeMemberClass(context.Background()); err != nil || state != "both" {
		t.Fatal("browser and external media did not join an owned bridge")
	}
	if err := c.AnswerBrowser(context.Background(), start); err != nil {
		t.Fatal("verified browser channel could not be answered after provider media")
	}
	lanes := Frames{FromSIP: make(chan calls.AudioFrame, 1), ToSIP: make(chan calls.AudioFrame, 1)}
	if _, err := session.StartBrowserRelay(context.Background(), localID, ownedRTP(t), lanes); err == nil {
		t.Fatal("changed owned media socket accepted for browser relay")
	}
	stop, err := session.StartBrowserRelay(context.Background(), localID, rtp, lanes)
	if err != nil || stop == nil {
		t.Fatal("owned browser PCMA lanes were not connected")
	}
	if err := stop(); err != nil {
		t.Fatal("browser relay worker did not stop cleanly")
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
	for _, step := range m.snapshot() {
		if step == "DELETE /ari/channels/1693496751.43" ||
			step == "POST /ari/channels/create" ||
			step == "POST /ari/channels/1693496751.43/dial" {
			t.Fatal("gateway dialed or deleted the browser caller")
		}
	}
}

func TestAttachBrowserFailureCleansOnlyOwnedResources(t *testing.T) {
	rtp := ownedRTP(t)
	m := startARI(t, rtp.LocalAddr().(*net.UDPAddr).Port)
	m.wantApp = browserApp
	m.browserExistingID = "1693496751.43"
	m.failAt = "POST /ari/channels/externalMedia"
	c := m.clientWithTarget(t, BrowserIngress)
	start, err := ParseBrowserStart([]byte(validBrowserEvent))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.AttachBrowser(context.Background(), start, rtp); err == nil {
		t.Fatal("failed browser media setup returned a session")
	}
	for _, step := range m.snapshot() {
		if step == "DELETE /ari/channels/1693496751.43" || step == "POST /ari/channels/create" {
			t.Fatal("failed media setup damaged the existing browser call")
		}
	}
}

func TestStasisUpgradeHeaderHasTotalBound(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error("mock upgrade socket unavailable")
			return
		}
		defer conn.Close()
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-Untrusted: %s\r\n\r\n", strings.Repeat("X", 8000))
	}))
	defer server.Close()
	c, err := New(Config{BaseURL: server.URL, PeerCertificate: server.Certificate(), Username: "lab", Password: "synthetic", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.Subscribe(ctx); ErrorCategory(err) != "stasis-subscribe" {
		t.Fatal("unbounded or leaked untrusted upgrade headers")
	}
}

func TestARIIDConflictDoesNotDeleteAnotherBridge(t *testing.T) {
	m := startARI(t, 20000)
	m.conflictBridge = true
	c := m.client(t)
	if _, err := c.Start(context.Background(), localID, ownedRTP(t)); err == nil {
		t.Fatal("bridge ID collision accepted")
	}
	for _, step := range m.snapshot() {
		if strings.HasPrefix(step, "DELETE ") {
			t.Fatal("deleted a bridge not owned by this call")
		}
	}
}

func TestFailureRollsBackAndDoesNotRedial(t *testing.T) {
	m := startARI(t, 20000)
	m.failAt = "POST /ari/channels/create"
	c := m.client(t)
	_, err := c.Start(context.Background(), localID, ownedRTP(t))
	if err == nil || strings.Contains(err.Error(), "Sensitive") {
		t.Fatal("untrusted ARI error escaped or failure was accepted")
	}
	steps := m.snapshot()
	var originated, cleanups int
	for _, step := range steps {
		if step == "POST /ari/channels/create" {
			originated++
		}
		if strings.HasPrefix(step, "DELETE ") {
			cleanups++
		}
	}
	if originated != 1 || cleanups != 3 {
		t.Fatal("ambiguous originate retried or owned resources not cleaned")
	}
}

func TestCleanupFailureIsNotHidden(t *testing.T) {
	m := startARI(t, 20000)
	m.failAt = "POST /ari/channels/create"
	m.failDeletes = true
	c := m.client(t)
	if _, err := c.Start(context.Background(), localID, ownedRTP(t)); err == nil ||
		err.Error() != "ARI failure and owned cleanup incomplete" {
		t.Fatal("ambiguous cleanup failure was hidden")
	}
}

func TestMalformedAsteriskRTPMetadataFailsClosed(t *testing.T) {
	for _, edit := range []func(*mockARI){
		func(m *mockARI) { m.badAddress = "192.0.2.1" },
		func(m *mockARI) { m.badPort = "0" },
		func(m *mockARI) { m.badPort = "65536" },
		func(m *mockARI) { m.badPort = "1\r\nSensitive: injected" },
		func(m *mockARI) { m.badMediaID = "attacker-chosen" },
	} {
		m := startARI(t, 20000)
		edit(m)
		c := m.client(t)
		if _, err := c.Start(context.Background(), localID, ownedRTP(t)); err == nil || strings.Contains(err.Error(), "Sensitive") {
			t.Fatal("unsafe ARI RTP metadata accepted or logged")
		}
		for _, step := range m.snapshot() {
			if step == "POST /ari/channels/create" {
				t.Fatal("local target originated after invalid media metadata")
			}
		}
	}
}

func TestBadARIResponseDoesNotLeakOrOriginate(t *testing.T) {
	for _, edit := range []func(*mockARI){
		func(m *mockARI) { m.badContentType = true },
		func(m *mockARI) { m.largeResponse = true },
		func(m *mockARI) { m.malformedJSON = true },
	} {
		m := startARI(t, 20000)
		edit(m)
		c := m.client(t)
		if _, err := c.Start(context.Background(), localID, ownedRTP(t)); err == nil ||
			strings.Contains(err.Error(), "untrusted") || len(err.Error()) > 128 {
			t.Fatal("invalid ARI response accepted or leaked into error")
		}
		for _, step := range m.snapshot() {
			if step == "POST /ari/channels/create" {
				t.Fatal("ARI originated despite invalid bridge response")
			}
		}
	}
}

func TestARIAuthAndConnectionFailuresAreSanitized(t *testing.T) {
	unauthorized := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			t.Error("Basic auth was not sent in header")
		}
		w.Header().Set("X-Error", "Untrusted\r\nSensitive: hidden")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Sensitive: password-like reply"))
	}))
	defer unauthorized.Close()
	c, err := New(Config{BaseURL: unauthorized.URL, PeerCertificate: unauthorized.Certificate(), Username: "lab", Password: "synthetic-only", Timeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Start(context.Background(), localID, ownedRTP(t)); err == nil ||
		strings.Contains(err.Error(), "Sensitive") || strings.Contains(err.Error(), "synthetic-only") {
		t.Fatal("authentication failure leaked untrusted ARI data")
	}
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	missing, err := New(Config{BaseURL: fmt.Sprintf("https://127.0.0.1:%d", port), PeerCertificate: unauthorized.Certificate(),
		Username: "lab", Password: "synthetic-only", Timeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer missing.Close()
	if _, err := missing.Start(context.Background(), localID, ownedRTP(t)); err == nil ||
		strings.Contains(err.Error(), "synthetic-only") {
		t.Fatal("connection failure leaked credentials or succeeded")
	}
}

func TestRejectRemoteOrRedirectARI(t *testing.T) {
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	defer certServer.Close()
	for _, base := range []string{
		"http://example.invalid:8088", "http://192.0.2.1:8088",
		"http://localhost:8088", "http://[::1]:8088", "http://[2001:db8::1]:8088",
		"http://127.0.0.1:8088/other", "http://127.0.0.1:8088/",
		"http://user:pass@127.0.0.1:8088", "http://127.0.0.1:8088#fragment",
		"http://127.0.0.1:0", "http://127.0.0.1:65536",
		"http://127.0.0.1:-1", "http://127.0.0.1:70000",
		"http://127.0.0.1:notanumber", "ftp://127.0.0.1:8088",
		"http://127.0.0.1:8088", "https://127.0.0.1:8088/?secret=1",
	} {
		if _, err := New(Config{BaseURL: base, PeerCertificate: certServer.Certificate(), Username: "lab", Password: "synthetic", Timeout: time.Second}); err == nil {
			t.Fatal("remote or ambiguous ARI endpoint accepted")
		}
	}
	for _, base := range []string{"https://127.0.0.1:1", "https://127.0.0.1:65535"} {
		c, err := New(Config{BaseURL: base, PeerCertificate: certServer.Certificate(), Username: "lab", Password: "synthetic", Timeout: time.Second})
		if err != nil {
			t.Fatal("valid loopback ARI port rejected")
		}
		c.Close()
	}
	m := &mockARI{t: t, failAt: "", started: make(chan struct{}, 1), cleaned: make(chan struct{}, 1)}
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("followed ARI redirect"); w.WriteHeader(200) }))
	defer remote.Close()
	m.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, remote.URL, http.StatusFound)
	}))
	defer m.server.Close()
	c := m.client(t)
	if _, err := c.Start(context.Background(), localID, ownedRTP(t)); err == nil {
		t.Fatal("redirect accepted")
	}
}

func TestEventReplayDoesNotOriginate(t *testing.T) {
	m := startARI(t, 20000)
	c := m.client(t)
	for _, events := range [][]calls.Event{
		{{ID: localID, Destination: calls.Desk, Kind: calls.Answered}},
		{{ID: localID, Destination: calls.Desk, Kind: calls.Incoming},
			{ID: localID, Destination: calls.Desk, Kind: calls.Ended},
			{ID: localID, Destination: calls.Desk, Kind: calls.Answered}},
	} {
		ch := make(chan calls.Event, len(events))
		for _, e := range events {
			ch <- e
		}
		close(ch)
		if err := Run(context.Background(), ch, c, ownedRTP(t)); err == nil {
			t.Fatal("orphaned/replayed answer accepted")
		}
	}
	if len(m.snapshot()) != 0 {
		t.Fatal("event replay caused ARI origination")
	}
}

func TestEventToARIControlLoopback(t *testing.T) {
	astRTP, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer astRTP.Close()
	m := startARI(t, astRTP.LocalAddr().(*net.UDPAddr).Port)
	c := m.client(t)
	gwRTP, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer gwRTP.Close()
	m.wantMediaPort = gwRTP.LocalAddr().(*net.UDPAddr).Port
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()
	s, err := calls.New(calls.Config{Port: port, DialedUser: "desk", Destination: calls.Desk,
		OfferTimeout: time.Second, ACKTimeout: 250 * time.Millisecond, MaxCall: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	defer s.Close()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- Run(ctx, s.Events(), c, gwRTP.(*net.UDPConn)) }()
	ua, err := sipgo.NewUA()
	if err != nil {
		t.Fatal(err)
	}
	defer ua.Close()
	d := diago.NewDiago(ua, diago.WithTransport(diago.Transport{Transport: "udp", BindHost: "127.0.0.1", BindPort: 0}),
		diago.WithMediaConfig(diago.MediaConfig{Codecs: []media.Codec{media.CodecAudioAlaw}}),
		diago.WithLogger(safesip.Logger))
	call, _, err := d.Invite(ctx, sip.Uri{User: "desk", Host: "127.0.0.1", Port: port}, diago.InviteOptions{})
	if err != nil {
		t.Fatal("mock SIP call failed")
	}
	defer call.Close()
	// Asterisk mock ARI has only fixed Local/Echo; no real phone is called.
	select {
	case <-m.started:
	case err := <-done:
		t.Fatalf("ARI controller stopped before bridge became ready: %v", err)
	case <-ctx.Done():
		t.Fatal("ARI bridge was not ready")
	}
	if err := call.Hangup(ctx); err != nil {
		t.Fatal("mock SIP BYE failed")
	}
	select {
	case <-m.cleaned:
	case err := <-done:
		t.Fatalf("ARI controller stopped before cleanup: %v", err)
	case <-ctx.Done():
		t.Fatal("ARI cleanup did not follow SIP call end")
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestLocalARILabCommandAgainstMock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "local-ari-lab")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/local-ari-lab")
	build.Dir = "../.." // from internal/asterisk to the nested Go module
	if err := build.Run(); err != nil {
		t.Fatal("local ARI lab command did not build")
	}
	astRTP := ownedRTP(t)
	m := startARI(t, astRTP.LocalAddr().(*net.UDPAddr).Port)
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()
	ariPort := strings.TrimPrefix(m.server.URL, "https://127.0.0.1:")
	peerDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(peerDir, 0700); err != nil {
		t.Fatal(err)
	}
	peerPath := filepath.Join(peerDir, "peer.pem")
	if err := os.WriteFile(peerPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, bin, "-sip-port", fmt.Sprint(port), "-ari-port", ariPort,
		"-ari-peer-cert", peerPath, "-ack-timeout", "500ms")
	cmd.Env = append(os.Environ(), "GATEWAY_LAB_ARI_USER=lab", "GATEWAY_LAB_ARI_PASSWORD=only-for-tests")
	var commandOutput bytes.Buffer
	cmd.Stdout, cmd.Stderr = &commandOutput, &commandOutput
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	// The command has no public readiness endpoint. Observe only its owned
	// loopback UDP bind before sending the synthetic SIP INVITE.
	ready := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		check, err := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			ready = true
			break
		}
		check.Close()
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("local command did not bind SIP loopback: %s", commandOutput.String())
	}
	select {
	case <-m.subscribed:
	case <-ctx.Done():
		t.Fatal("gateway failed to register Stasis before synthetic SIP call")
	}
	ua, err := sipgo.NewUA()
	if err != nil {
		t.Fatal(err)
	}
	defer ua.Close()
	d := diago.NewDiago(ua, diago.WithTransport(diago.Transport{Transport: "udp", BindHost: "127.0.0.1", BindPort: 0}),
		diago.WithMediaConfig(diago.MediaConfig{Codecs: []media.Codec{media.CodecAudioAlaw}}),
		diago.WithLogger(safesip.Logger))
	call, med, err := d.Invite(ctx, sip.Uri{User: "desk", Host: "127.0.0.1", Port: port}, diago.InviteOptions{})
	if err != nil {
		t.Fatal("synthetic command SIP INVITE failed")
	}
	defer call.Close()
	select {
	case <-m.started:
	case <-ctx.Done():
		t.Fatal("local command did not create mock ARI bridge")
	}
	var fixture [160]byte
	for i := range fixture {
		fixture[i] = byte((i*19 + 113) & 0xff)
	}
	echoed := startMockEcho(t, ctx, astRTP, fixture[:])
	writer, err := med.AudioWriter()
	if err != nil {
		t.Fatal(err)
	}
	reader, err := med.AudioReader()
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan []byte, 1)
	go func() {
		var buf [2048]byte
		if n, err := reader.Read(buf[:]); err == nil {
			received <- bytes.Clone(buf[:n])
		}
	}()
	for i := 0; i < 25; i++ {
		if n, err := writer.Write(fixture[:]); err != nil || n != len(fixture) {
			t.Fatal("synthetic command SIP media send failed")
		}
		select {
		case got := <-received:
			if !bytes.Equal(got, fixture[:]) {
				t.Fatal("synthetic command returned incorrect media")
			}
			select {
			case <-echoed:
			case <-ctx.Done():
				t.Fatal("mock Asterisk media was not observed")
			}
			goto mediaPassed
		default:
		}
	}
	t.Fatal("local command did not forward two independent media legs")

mediaPassed:
	if err := call.Hangup(ctx); err != nil {
		t.Fatal("synthetic command BYE failed")
	}
	select {
	case <-m.cleaned:
	case <-ctx.Done():
		t.Fatal("local command did not clean mock ARI bridge")
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal("could not stop disposable lab command")
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal("local ARI lab command did not exit cleanly")
	}
}
