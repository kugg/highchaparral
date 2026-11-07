// Package asterisk is a local-lab ARI adapter. It never accepts a dial
// target or media address from SIP input, and cannot contact a remote PBX.
package asterisk

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"example.com/ata/voip-gateway/internal/calls"
	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"
)

const (
	appName      = "eventphone-gateway-lab"
	endpoint     = "Local/echo@eventphone-gateway-lab/n" // Preserve the Local leg in the ARI bridge.
	deskApp      = "eventphone-vgw-desk"
	deskEndpoint = "Local/desk@vgw-owned-ata/n" // New owned context; never use legacy from-ata/from-webrtc.
)

// Target is a closed, local Asterisk endpoint policy. SIP headers, user
// strings, provider responses and remote SDP cannot choose an ARI target.
type Target uint8

const (
	LabEcho        Target = iota // historical isolated lab, the default
	ATADesk                      // requires a separately installed owned APU context
	BrowserIngress               // accepts only a future owned browser Stasis leg
)

// ErrorCategory is an allowlisted label for local lab diagnostics. Never
// serialize a library error, response body, header, SIP message or secret.
func ErrorCategory(err error) string {
	if err == nil {
		return "none"
	}
	switch err.Error() {
	case "ARI bridge creation failed":
		return "bridge-create"
	case "ARI external media creation failed":
		return "external-media-create"
	case "ARI RTP address not local":
		return "media-address-nonloopback"
	case "ARI RTP port unavailable":
		return "media-port-invalid"
	case "ARI variable unavailable", "ARI variable invalid":
		return "media-variable"
	case "ARI media bridge attachment failed":
		return "media-attach"
	case "ARI local target creation failed":
		return "target-originate"
	case "ARI target bridge attachment failed", "ARI target did not enter Stasis":
		return "target-attach"
	case "ARI local target dialing failed":
		return "target-dial"
	case "ARI target did not join bridge", "ARI target bridge membership unavailable":
		return "target-membership"
	case "ARI owned resource cleanup incomplete", "ARI failure and owned cleanup incomplete":
		return "owned-cleanup"
	case "ARI Stasis subscription unavailable":
		return "stasis-subscribe"
	case "ARI Stasis subscription lost":
		return "stasis-lost"
	case "browser ARI subscription requires typed admission", "unreviewed browser ARI app",
		"browser ingress cannot originate an ARI target", "browser ARI channel admission refused",
		"browser ARI channel readback unavailable", "browser ARI channel readback refused",
		"browser ARI answer admission refused", "browser ARI answer unavailable",
		"browser ARI nonce changed", "browser ARI nonce unavailable":
		return "browser-admission"
	case "ARI media relay unavailable", "ARI media relay failed", "ARI media relay teardown incomplete":
		return "media-relay"
	default:
		return "other"
	}
}

type Config struct {
	// BaseURL must be http://127.0.0.1:<port>, with no path or userinfo.
	BaseURL  string
	Username string
	Password string
	Timeout  time.Duration
	Target   Target
}

type Client struct {
	base     string
	user     string
	pass     string
	app      string
	endpoint string
	http     *http.Client
	timeout  time.Duration
	mediaMu  sync.Mutex
	mediaIDs map[string]struct{} // only local ExternalMedia IDs, never caller identifiers
}

// wsHandshakeConn caps bytes read while parsing an untrusted HTTP upgrade.
// gobwas/ws enforces the RFC handshake but its readLine can grow without a
// total limit; release the cap only after the upgrade has been validated.
type wsHandshakeConn struct {
	net.Conn
	mu        sync.Mutex
	remaining int64
	upgraded  bool
}

func (c *wsHandshakeConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.upgraded {
		if c.remaining == 0 {
			return 0, errors.New("ARI upgrade header too large")
		}
		if int64(len(p)) > c.remaining {
			p = p[:int(c.remaining)]
		}
	}
	n, err := c.Conn.Read(p)
	if !c.upgraded {
		c.remaining -= int64(n)
	}
	return n, err
}

func (c *wsHandshakeConn) acceptUpgrade() {
	c.mu.Lock()
	c.upgraded = true
	c.mu.Unlock()
}

func New(c Config) (*Client, error) {
	app, target := appName, endpoint
	switch c.Target {
	case LabEcho:
	case ATADesk:
		// Only the future, separately provisioned vgw-owned dialplan
		// context can make this fixed Local leg reach an ATA handset.
		app, target = deskApp, deskEndpoint
	case BrowserIngress:
		app, target = browserApp, ""
	default:
		return nil, errors.New("unreviewed ARI destination")
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" ||
		u.User != nil || u.Opaque != "" || u.Path != "" ||
		u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		len(c.Username) == 0 || len(c.Username) > 64 ||
		len(c.Password) == 0 || len(c.Password) > 256 ||
		c.Timeout < 100*time.Millisecond || c.Timeout > 5*time.Second {
		return nil, errors.New("invalid local ARI configuration")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("invalid local ARI port")
	}
	for _, b := range []byte(c.Username) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '-' || b == '_') {
			return nil, errors.New("invalid local ARI user")
		}
	}
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, MaxConnsPerHost: 2,
		DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
			if target != address || network != "tcp" {
				return nil, errors.New("ARI target denied")
			}
			return (&net.Dialer{Timeout: c.Timeout}).DialContext(ctx, "tcp4", address)
		},
		ResponseHeaderTimeout: c.Timeout,
	}
	return &Client{
		base: "http://" + address, user: c.Username, pass: c.Password,
		app: app, endpoint: target,
		timeout: c.Timeout,
		http: &http.Client{Timeout: c.Timeout, Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		mediaIDs: make(map[string]struct{}),
	}, nil
}

func (c *Client) request(ctx context.Context, method, path string, q url.Values) (int, []byte, error) {
	u := c.base + "/ari" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return 0, nil, errors.New("ARI request unavailable")
	}
	req.SetBasicAuth(c.user, c.pass)
	res, err := c.http.Do(req)
	if err != nil {
		return 0, nil, errors.New("ARI request failed")
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 4097))
	if err != nil || len(body) > 4096 {
		return 0, nil, errors.New("ARI response too large or unreadable")
	}
	if res.StatusCode == http.StatusOK || res.StatusCode == http.StatusCreated {
		contentType := res.Header.Get("Content-Type")
		if len(contentType) > 128 || len(body) == 0 {
			return 0, nil, errors.New("ARI JSON response invalid")
		}
		mediaType, _, parseErr := mime.ParseMediaType(contentType)
		if parseErr != nil || mediaType != "application/json" {
			return 0, nil, errors.New("ARI JSON response invalid")
		}
	}
	return res.StatusCode, body, nil
}

// Subscribe registers the one fixed Stasis application before any channels are
// created. Without an active ARI events socket Asterisk can discard new media
// channels before their RTP port is read. The transport still pins all traffic
// to IPv4 loopback; credentials appear only in the Basic Authorization header.
// A disconnected subscription fails closed and never automatically redials.
func (c *Client) Subscribe(ctx context.Context) (<-chan error, error) {
	if c.app == browserApp {
		return nil, errors.New("browser ARI subscription requires typed admission")
	}
	return c.subscribe(ctx, nil)
}

// SubscribeBrowser listens only to the fixed owned Stasis app. At most one
// validated Asterisk channel ID is buffered; further inbound calls fail
// closed instead of selecting an arbitrary provider destination. Buffered
// IDs are provisional: the caller must check gone, read the ARI channel
// back and consume one-use approval BEFORE any provider INVITE. This
// subscription alone is not a call admission or call approval.
func (c *Client) SubscribeBrowser(ctx context.Context) (<-chan BrowserStart, <-chan error, error) {
	if c.app != browserApp {
		return nil, nil, errors.New("unreviewed browser ARI app")
	}
	events := make(chan BrowserStart, 1)
	gone, err := c.subscribe(ctx, events)
	if err != nil {
		return nil, nil, err
	}
	return events, gone, nil
}

// VerifyBrowserChannel reads a provisional Stasis ID back from Asterisk
// over the authenticated loopback ARI boundary. The channel must still
// belong to the owned WebRTC context, and no caller-controlled URI is
// accepted. An event alone is never outbound call authorization.
func (c *Client) VerifyBrowserChannel(ctx context.Context, start BrowserStart) error {
	_, err := c.ReadBrowserDial(ctx, start)
	return err
}

// BrowserChannelClass distinguishes a definite 404/hangup from an
// unavailable ARI readback. A timeout is NEVER taken as proof that the
// caller hung up or that a provider BYE has completed.
func (c *Client) BrowserChannelClass(ctx context.Context, start BrowserStart) (string, error) {
	if c.app != browserApp || !validChannelID(start.ChannelID) ||
		(start.Nonce != "" && !browserNonce.MatchString(start.Nonce)) {
		return "", errors.New("browser ARI channel admission refused")
	}
	code, body, err := c.request(ctx, http.MethodGet, "/channels/"+url.PathEscape(start.ChannelID), nil)
	if err != nil {
		return "", errors.New("browser ARI channel readback unavailable")
	}
	if code == http.StatusNotFound {
		return "gone", nil
	}
	var channel browserChannel
	if code != http.StatusOK || json.Unmarshal(body, &channel) != nil || channel.ID != start.ChannelID ||
		!validBrowserChannel(channel) || !activeBrowserChannel(channel) {
		return "", errors.New("browser ARI channel readback refused")
	}
	if start.Nonce != "" {
		current, err := c.variable(ctx, start.ChannelID, "PJSIP_HEADER(read,X-VGW-Nonce)")
		if err != nil || current != start.Nonce {
			return "", errors.New("browser ARI nonce changed")
		}
	}
	return "present", nil
}

// AnswerBrowser makes a SINGLE owned ARI answer after the provider has
// answered and its SDP/PCMA has been verified. It must still be the same
// browser channel; neither an event nor SDP chooses the ARI target.
func (c *Client) AnswerBrowser(ctx context.Context, start BrowserStart) error {
	if c.VerifyBrowserChannel(ctx, start) != nil {
		return errors.New("browser ARI answer admission refused")
	}
	code, _, err := c.request(ctx, http.MethodPost,
		"/channels/"+url.PathEscape(start.ChannelID)+"/answer", nil)
	if err != nil || !good(code) {
		return errors.New("browser ARI answer unavailable")
	}
	return nil
}

// ReadBrowserDial resolves only an explicitly routed Eventphone extension
// after Asterisk readback. A caller's raw SIP URI/To header is never used.
// The future authenticated softphone and one-attempt journal must still
// authorize and bound the call before invoking the provider connector.
func (c *Client) ReadBrowserDial(ctx context.Context, start BrowserStart) (BrowserDial, error) {
	var empty BrowserDial
	if c.app != browserApp || !validChannelID(start.ChannelID) ||
		(start.Nonce != "" && !browserNonce.MatchString(start.Nonce)) {
		return empty, errors.New("browser ARI channel admission refused")
	}
	code, body, err := c.request(ctx, http.MethodGet, "/channels/"+url.PathEscape(start.ChannelID), nil)
	if err != nil || code != http.StatusOK {
		return empty, errors.New("browser ARI channel readback unavailable")
	}
	var channel browserChannel
	if json.Unmarshal(body, &channel) != nil || channel.ID != start.ChannelID ||
		!validBrowserChannel(channel) || !activeBrowserChannel(channel) {
		return empty, errors.New("browser ARI channel readback refused")
	}
	nonce, err := c.variable(ctx, start.ChannelID, "PJSIP_HEADER(read,X-VGW-Nonce)")
	if err != nil || !browserNonce.MatchString(nonce) ||
		(start.Nonce != "" && nonce != start.Nonce) {
		return empty, errors.New("browser ARI nonce unavailable")
	}
	return BrowserDial{ChannelID: start.ChannelID, Destination: channel.Dialplan.Exten[len("e-"):],
		Nonce: nonce}, nil
}

func (c *Client) subscribe(ctx context.Context, events chan<- BrowserStart) (<-chan error, error) {
	address := c.base[len("http://"):]
	credentials := base64.StdEncoding.EncodeToString([]byte(c.user + ":" + c.pass))
	var limited *wsHandshakeConn
	dialer := ws.Dialer{
		Timeout: c.timeout,
		Header:  ws.HandshakeHeaderHTTP(http.Header{"Authorization": {"Basic " + credentials}}),
		NetDial: func(ctx context.Context, network, target string) (net.Conn, error) {
			if network != "tcp" || target != address {
				return nil, errors.New("ARI target denied")
			}
			raw, err := (&net.Dialer{Timeout: c.timeout}).DialContext(ctx, "tcp4", address)
			if err != nil {
				return nil, err
			}
			limited = &wsHandshakeConn{Conn: raw, remaining: 4096}
			return limited, nil
		},
	}
	conn, buffered, _, err := dialer.Dial(ctx, "ws://"+address+"/ari/events?app="+c.app)
	if err != nil {
		return nil, errors.New("ARI Stasis subscription unavailable")
	}
	limited.acceptUpgrade()
	var source io.Reader = conn
	if buffered != nil {
		source = buffered // retain any WebSocket data read ahead during upgrade
	}
	rw := struct {
		io.Reader
		io.Writer
	}{source, conn}
	gone := make(chan error, 1)
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	go func() {
		// An owned browser subscription emits only typed, bounded local
		// channel IDs; existing lab subscriptions still discard events.
		_ = readStasisEventsWithOwnedMedia(rw, events, c.ownsMediaID, c.untrackMediaID)
		_ = conn.Close()
		if buffered != nil {
			ws.PutReader(buffered)
		}
		if ctx.Err() == nil {
			gone <- errors.New("ARI Stasis subscription lost")
		}
		if events != nil {
			close(events)
		}
		close(gone)
	}()
	return gone, nil
}

func readStasisEvents(rw io.ReadWriter) error {
	return readStasisEventsTo(rw, nil)
}

func readStasisEventsTo(rw io.ReadWriter, events chan<- BrowserStart) error {
	return readStasisEventsWithOwnedMedia(rw, events, nil, nil)
}

var localMediaID = regexp.MustCompile(`^m-[a-f0-9]{32}$`)

func (c *Client) trackMediaID(id string) error {
	if c == nil || c.app != browserApp || !localMediaID.MatchString(id) {
		return errors.New("owned browser media ID unavailable")
	}
	c.mediaMu.Lock()
	defer c.mediaMu.Unlock()
	if len(c.mediaIDs) != 0 {
		return errors.New("second browser media ID refused")
	}
	c.mediaIDs[id] = struct{}{}
	return nil
}

func (c *Client) ownsMediaID(id string) bool {
	if c == nil || c.app != browserApp {
		return false
	}
	c.mediaMu.Lock()
	defer c.mediaMu.Unlock()
	_, owned := c.mediaIDs[id]
	return owned
}

func (c *Client) untrackMediaID(id string) {
	if c == nil || c.app != browserApp {
		return
	}
	c.mediaMu.Lock()
	delete(c.mediaIDs, id)
	c.mediaMu.Unlock()
}

// An ARI ExternalMedia channel enters the SAME fixed Stasis application as
// the browser. Ignore only the unpredictable, locally registered media ID
// AND Asterisk's UnicastRTP leg; every other second StasisStart still fails
// closed. No remote/browser-supplied channel ID enters the registry.
func ownedExternalMediaEvent(raw []byte, kind string, owned func(string) bool) (string, bool) {
	if owned == nil {
		return "", false
	}
	var event struct {
		Type        string `json:"type"`
		Application string `json:"application"`
		Channel     struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"channel"`
	}
	if json.Unmarshal(raw, &event) != nil || event.Type != kind ||
		event.Application != browserApp || !strings.HasPrefix(event.Channel.Name, "UnicastRTP/") ||
		!owned(event.Channel.ID) {
		return "", false
	}
	return event.Channel.ID, true
}

func readStasisEventsWithOwnedMedia(rw io.ReadWriter, events chan<- BrowserStart,
	owned func(string) bool, released func(string)) error {
	reader := wsutil.NewClientSideReader(rw)
	reader.MaxFrameSize = 4096
	var total int64
	var frames int
	control := func(op ws.OpCode, source io.Reader) error {
		payload, err := io.ReadAll(io.LimitReader(source, 126))
		if err != nil || len(payload) > 125 {
			return errors.New("ARI Stasis control frame invalid")
		}
		total += int64(len(payload))
		if total > 65536 {
			return errors.New("ARI Stasis control frame invalid")
		}
		if op == ws.OpPing {
			return wsutil.WriteClientMessage(rw, ws.OpPong, payload)
		}
		if op == ws.OpClose {
			return errors.New("ARI Stasis socket closed")
		}
		if op != ws.OpPong {
			return errors.New("ARI Stasis control frame invalid")
		}
		return nil
	}
	reader.OnIntermediate = func(header ws.Header, body io.Reader) error {
		frames++
		if frames > 1024 {
			return errors.New("ARI Stasis frame invalid")
		}
		return control(header.OpCode, body)
	}
	for {
		header, err := reader.NextFrame()
		if err != nil {
			return err
		}
		frames++
		if frames > 1024 {
			return errors.New("ARI Stasis frame invalid")
		}
		if header.OpCode.IsControl() {
			if err := control(header.OpCode, reader); err != nil {
				return err
			}
			continue
		}
		if header.OpCode != ws.OpText && header.OpCode != ws.OpBinary &&
			header.OpCode != ws.OpContinuation {
			return errors.New("ARI Stasis frame invalid")
		}
		if events == nil {
			n, err := io.Copy(io.Discard, reader)
			total += n
			if err != nil || total > 65536 {
				return errors.New("ARI Stasis frame invalid")
			}
			continue
		}
		if header.OpCode != ws.OpText {
			return errors.New("browser Stasis event framing refused")
		}
		data, err := io.ReadAll(io.LimitReader(reader, 4097))
		total += int64(len(data))
		if err != nil || len(data) > 4096 || total > 65536 {
			return errors.New("browser Stasis event invalid")
		}
		var eventType struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(data, &eventType) != nil {
			return errors.New("browser Stasis event invalid")
		}
		if eventType.Type == "StasisEnd" && released != nil {
			if id, valid := ownedExternalMediaEvent(data, "StasisEnd", owned); valid {
				released(id) // exact ended local media, never a browser caller
			}
		}
		if eventType.Type != "StasisStart" {
			continue // unrelated Stasis lifecycle never selects a target
		}
		if _, valid := ownedExternalMediaEvent(data, "StasisStart", owned); valid {
			continue // locally generated RTP leg, never browser/provider admission
		}
		start, err := ParseBrowserStart(data)
		if err != nil {
			return errors.New("browser Stasis channel refused")
		}
		select {
		case events <- start:
		default:
			return errors.New("second browser channel refused")
		}
	}
}

func good(code int) bool {
	return code == http.StatusOK || code == http.StatusCreated || code == http.StatusNoContent
}

func localCallID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := range id {
		if !(id[i] >= '0' && id[i] <= '9' || id[i] >= 'a' && id[i] <= 'f') {
			return false
		}
	}
	return true
}

type Session struct {
	client *Client
	bridge string
	media  string
	target string
	// These IDs are allocated locally. Attempted POSTs may have succeeded even
	// when a response was lost, so rollback only these owned, opaque IDs.
	bridgeAttempted bool
	mediaAttempted  bool
	targetAttempted bool
	once            sync.Once
	cleanupErr      error
	offeredPort     int // gateway-owned ExternalMedia destination, never provider SDP
	// LocalPort is reported by Asterisk, not guessed from the offered host.
	LocalPort int
}

// Start creates a bridge, a PCMA external-media channel and the one fixed
// target selected at construction. No SIP/provider input can choose the leg;
// a non-422 error never retries origination or call delivery.
// media must be a gateway-owned IPv4 loopback UDP socket held for this call.
func (c *Client) Start(ctx context.Context, callID string, media *net.UDPConn) (_ *Session, err error) {
	if c.app == browserApp {
		return nil, errors.New("browser ingress cannot originate an ARI target")
	}
	mediaPort, e := ownedMediaPort(media)
	if !localCallID(callID) || e != nil {
		return nil, errors.New("invalid local call ID or media socket")
	}
	var raw [16]byte
	if _, e := rand.Read(raw[:]); e != nil {
		return nil, errors.New("ARI resource ID unavailable")
	}
	resourceID := hex.EncodeToString(raw[:]) // independent of canonical call ID
	s := &Session{client: c, bridge: "b-" + resourceID, media: "m-" + resourceID,
		target: "t-" + resourceID, offeredPort: mediaPort}
	defer func() {
		if err != nil {
			if s.Close() != nil {
				err = errors.New("ARI failure and owned cleanup incomplete")
			}
		}
	}()
	s.bridgeAttempted = true
	code, body, e := c.request(ctx, http.MethodPost, "/bridges/"+s.bridge, url.Values{"type": {"mixing"}})
	if code == http.StatusConflict {
		s.bridgeAttempted = false // not ours: never DELETE on ID collision
	}
	if e != nil || !good(code) || !responseID(body, s.bridge) {
		return nil, errors.New("ARI bridge creation failed")
	}
	s.mediaAttempted = true
	code, body, e = c.request(ctx, http.MethodPost, "/channels/externalMedia", url.Values{
		"app": {c.app}, "external_host": {net.JoinHostPort("127.0.0.1", strconv.Itoa(mediaPort))},
		"format": {"alaw"}, "encapsulation": {"rtp"}, "transport": {"udp"},
		"connection_type": {"client"}, "channelId": {s.media},
	})
	if code == http.StatusConflict {
		s.mediaAttempted = false
	}
	if e != nil || !good(code) || !responseID(body, s.media) {
		return nil, errors.New("ARI external media creation failed")
	}
	address, e := c.variable(ctx, s.media, "UNICASTRTP_LOCAL_ADDRESS")
	if e != nil || address != "127.0.0.1" {
		return nil, errors.New("ARI RTP address not local")
	}
	portText, e := c.variable(ctx, s.media, "UNICASTRTP_LOCAL_PORT")
	port, parseErr := strconv.Atoi(portText)
	if e != nil || parseErr != nil || port < 1 || port > 65535 {
		return nil, errors.New("ARI RTP port unavailable")
	}
	s.LocalPort = port
	code, _, e = c.request(ctx, http.MethodPost, "/bridges/"+s.bridge+"/addChannel", url.Values{"channel": {s.media}})
	if e != nil || !good(code) {
		return nil, errors.New("ARI media bridge attachment failed")
	}
	s.targetAttempted = true
	// Create in Stasis first, before dialing. Originate-first can return
	// optimistic addChannel 204 without ever imparting its Local leg.
	code, body, e = c.request(ctx, http.MethodPost, "/channels/create", url.Values{
		"endpoint": {c.endpoint}, "app": {c.app}, "channelId": {s.target}, "formats": {"alaw"},
	})
	if code == http.StatusConflict {
		s.targetAttempted = false
	}
	if e != nil || !good(code) || !responseID(body, s.target) {
		return nil, errors.New("ARI local target creation failed")
	}
	// 422 means the fixed Local/ channel has not entered Stasis yet. Retry
	// only this non-side-effecting bridge add under a bounded deadline.
	ready, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	for {
		code, _, e = c.request(ready, http.MethodPost, "/bridges/"+s.bridge+"/addChannel", url.Values{"channel": {s.target}})
		if e == nil && good(code) {
			break
		}
		if e != nil || code != http.StatusUnprocessableEntity {
			return nil, errors.New("ARI target bridge attachment failed")
		}
		select {
		case <-ready.Done():
			return nil, errors.New("ARI target did not enter Stasis")
		case <-time.After(50 * time.Millisecond):
		}
	}
	// Read-only occupancy must be verified before making the side-effecting
	// dial request. A failed attach cannot be fixed by replaying origination.
	for {
		membership, readErr := s.BridgeMemberClass(ready)
		if readErr != nil {
			return nil, errors.New("ARI target bridge membership unavailable")
		}
		if membership == "both" {
			break
		}
		if membership != "media-only" {
			return nil, errors.New("ARI target did not join bridge")
		}
		select {
		case <-ready.Done():
			return nil, errors.New("ARI target did not join bridge")
		case <-time.After(50 * time.Millisecond):
		}
	}
	code, _, e = c.request(ready, http.MethodPost, "/channels/"+s.target+"/dial", nil)
	if e != nil || !good(code) {
		return nil, errors.New("ARI local target dialing failed")
	}
	// Asterisk 20.x can return 204 for a target add even when the Local
	// channel never occupies this bridge. Only poll the owned, read-only
	// bridge state: never replay origination or addChannel on ambiguity.
	for {
		membership, readErr := s.BridgeMemberClass(ready)
		if readErr != nil {
			return nil, errors.New("ARI target bridge membership unavailable")
		}
		if membership == "both" {
			return s, nil
		}
		if membership != "media-only" {
			return nil, errors.New("ARI target did not join bridge")
		}
		select {
		case <-ready.Done():
			return nil, errors.New("ARI target did not join bridge")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// AttachBrowser creates only gateway-owned bridge/ExternalMedia resources
// and joins an ALREADY existing browser channel after authenticated ARI
// readback. It never originates, dials or deletes the caller's channel.
// The caller must keep the owned Stasis subscription alive and independently
// consume one transient BYOK reservation before any provider INVITE.
func (c *Client) AttachBrowser(ctx context.Context, start BrowserStart, media *net.UDPConn) (_ *Session, err error) {
	if c.app != browserApp || c.VerifyBrowserChannel(ctx, start) != nil {
		return nil, errors.New("browser ARI admission unavailable")
	}
	mediaPort, e := ownedMediaPort(media)
	if e != nil {
		return nil, errors.New("invalid browser ARI media socket")
	}
	var raw [16]byte
	if _, e := rand.Read(raw[:]); e != nil {
		return nil, errors.New("browser ARI resource ID unavailable")
	}
	id := hex.EncodeToString(raw[:])
	s := &Session{client: c, bridge: "b-" + id, media: "m-" + id,
		target: start.ChannelID, offeredPort: mediaPort}
	if e := c.trackMediaID(s.media); e != nil {
		return nil, errors.New("browser ARI media identity unavailable")
	}
	defer func() {
		if err != nil && s.Close() != nil {
			err = errors.New("browser ARI failure and owned cleanup incomplete")
		}
	}()
	s.bridgeAttempted = true
	code, body, e := c.request(ctx, http.MethodPost, "/bridges/"+s.bridge, url.Values{"type": {"mixing"}})
	if code == http.StatusConflict {
		s.bridgeAttempted = false
	}
	if e != nil || !good(code) || !responseID(body, s.bridge) {
		return nil, errors.New("browser ARI bridge creation failed")
	}
	s.mediaAttempted = true
	code, body, e = c.request(ctx, http.MethodPost, "/channels/externalMedia", url.Values{
		"app": {c.app}, "external_host": {net.JoinHostPort("127.0.0.1", strconv.Itoa(mediaPort))},
		"format": {"alaw"}, "encapsulation": {"rtp"}, "transport": {"udp"},
		"connection_type": {"client"}, "channelId": {s.media},
	})
	if code == http.StatusConflict {
		s.mediaAttempted = false
	}
	if e != nil || !good(code) || !responseID(body, s.media) {
		return nil, errors.New("browser ARI external media creation failed")
	}
	address, e := c.variable(ctx, s.media, "UNICASTRTP_LOCAL_ADDRESS")
	if e != nil || address != "127.0.0.1" {
		return nil, errors.New("browser ARI RTP address unavailable")
	}
	portText, e := c.variable(ctx, s.media, "UNICASTRTP_LOCAL_PORT")
	port, parseErr := strconv.Atoi(portText)
	if e != nil || parseErr != nil || port < 1 || port > 65535 {
		return nil, errors.New("browser ARI RTP port unavailable")
	}
	s.LocalPort = port
	code, _, e = c.request(ctx, http.MethodPost, "/bridges/"+s.bridge+"/addChannel", url.Values{"channel": {s.media}})
	if e != nil || !good(code) {
		return nil, errors.New("browser ARI media bridge attachment failed")
	}
	ready, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	for {
		// 422 is only a bounded wait for the caller's existing Stasis
		// leg to become bridge-ready; NEVER replay an INVITE/originate.
		code, _, e = c.request(ready, http.MethodPost, "/bridges/"+s.bridge+"/addChannel",
			url.Values{"channel": {s.target}})
		if e == nil && good(code) {
			break
		}
		if e != nil || code != http.StatusUnprocessableEntity {
			return nil, errors.New("browser ARI channel bridge attachment failed")
		}
		select {
		case <-ready.Done():
			return nil, errors.New("browser ARI caller not bridge-ready")
		case <-time.After(50 * time.Millisecond):
		}
	}
	for {
		membership, readErr := s.BridgeMemberClass(ready)
		if readErr != nil || membership == "target-only" || membership == "none" {
			return nil, errors.New("browser ARI bridge membership unavailable")
		}
		if membership == "both" {
			return s, nil
		}
		select {
		case <-ready.Done():
			return nil, errors.New("browser ARI bridge membership unavailable")
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func ownedMediaPort(conn *net.UDPConn) (int, error) {
	if conn == nil {
		return 0, errors.New("missing local media socket")
	}
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP.String() != "127.0.0.1" || addr.Port < 1 || addr.Port > 65535 {
		return 0, errors.New("media socket must bind IPv4 loopback")
	}
	return addr.Port, nil
}

func responseID(body []byte, want string) bool {
	var v struct {
		ID string `json:"id"`
	}
	return json.Unmarshal(body, &v) == nil && v.ID == want
}

func (c *Client) variable(ctx context.Context, channel, name string) (string, error) {
	code, body, err := c.request(ctx, http.MethodGet, "/channels/"+channel+"/variable", url.Values{"variable": {name}})
	if err != nil || code != http.StatusOK {
		return "", errors.New("ARI variable unavailable")
	}
	var v struct {
		Value string `json:"value"`
	}
	if json.Unmarshal(body, &v) != nil || len(v.Value) > 64 {
		return "", errors.New("ARI variable invalid")
	}
	return v.Value, nil
}

// BridgeMemberClass is a read-only diagnostic of this session's locally
// generated resource IDs. Neither channel IDs nor remote JSON are logged.
func (s *Session) BridgeMemberClass(ctx context.Context) (string, error) {
	code, body, err := s.client.request(ctx, http.MethodGet, "/bridges/"+s.bridge, nil)
	if err != nil || code != http.StatusOK {
		return "", errors.New("ARI bridge membership unavailable")
	}
	var reply struct {
		ID       string   `json:"id"`
		Channels []string `json:"channels"`
	}
	if json.Unmarshal(body, &reply) != nil || reply.ID != s.bridge || len(reply.Channels) > 2 {
		return "", errors.New("ARI bridge membership invalid")
	}
	media, target := false, false
	for _, id := range reply.Channels {
		switch id {
		case s.media:
			if media {
				return "", errors.New("ARI bridge membership invalid")
			}
			media = true
		case s.target:
			if target {
				return "", errors.New("ARI bridge membership invalid")
			}
			target = true
		default:
			return "", errors.New("ARI bridge membership invalid")
		}
	}
	switch {
	case media && target:
		return "both", nil
	case media:
		return "media-only", nil
	case target:
		return "target-only", nil
	default:
		return "none", nil
	}
}

// TargetStatusClass reads only the fixed Local channel owned by this ARI
// session. Callers receive a small enum, never untrusted channel metadata.
func (s *Session) TargetStatusClass(ctx context.Context) (string, error) {
	code, body, err := s.client.request(ctx, http.MethodGet, "/channels/"+s.target, nil)
	if err != nil || code != http.StatusOK {
		return "", errors.New("ARI local target status unavailable")
	}
	var reply struct {
		ID       string `json:"id"`
		State    string `json:"state"`
		Dialplan struct {
			AppName string `json:"app_name"`
		} `json:"dialplan"`
	}
	if json.Unmarshal(body, &reply) != nil || reply.ID != s.target ||
		(reply.State != "Up" && reply.State != "Down") || len(reply.Dialplan.AppName) > 64 {
		return "", errors.New("ARI local target status invalid")
	}
	state := "down"
	if reply.State == "Up" {
		state = "up"
	}
	app := "other"
	if reply.Dialplan.AppName == "Stasis" {
		app = "stasis"
	}
	return state + "-" + app, nil
}

// Close is idempotent and deletes only this session's locally generated IDs.
// A missing resource (404) is already cleaned; other failures are reported
// without exposing remote response text, never automatically retried.
func (s *Session) Close() error {
	s.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*s.client.timeout)
		defer cancel()
		for _, entry := range []struct {
			attempted bool
			path      string
		}{
			{s.targetAttempted, "/channels/" + s.target},
			{s.mediaAttempted, "/channels/" + s.media},
			{s.bridgeAttempted, "/bridges/" + s.bridge},
		} {
			if !entry.attempted {
				continue
			}
			code, _, err := s.client.request(ctx, http.MethodDelete, entry.path, nil)
			if err != nil || (!good(code) && code != http.StatusNotFound) {
				s.cleanupErr = errors.New("ARI owned resource cleanup incomplete")
			}
		}
	})
	return s.cleanupErr
}

func (c *Client) Close() { c.http.CloseIdleConnections() }

// Run consumes only locally generated M2 events. It starts one fixed Asterisk
// lab leg after a SIP dialog is ACKed; it cannot originate to a SIP-supplied
// destination. On ARI error it returns and cleans up rather than redialing.
func Run(ctx context.Context, events <-chan calls.Event, c *Client, media *net.UDPConn) error {
	return run(ctx, events, c, media, Frames{})
}

// RunWithMedia uses two independently owned media sessions. The SIP call
// retains Diago's RTP socket; this controller exclusively owns the separate
// Asterisk ExternalMedia socket, with fresh outgoing RTP identifiers.
func RunWithMedia(ctx context.Context, events <-chan calls.Event, c *Client,
	media *net.UDPConn, frames Frames) error {
	if frames.FromSIP == nil || frames.ToSIP == nil {
		return errors.New("ARI media relay unavailable")
	}
	return run(ctx, events, c, media, frames)
}

func run(ctx context.Context, events <-chan calls.Event, c *Client, media *net.UDPConn, frames Frames) (result error) {
	if events == nil || c == nil || media == nil {
		return errors.New("invalid ARI event connection")
	}
	if _, err := ownedMediaPort(media); err != nil {
		return err
	}
	var active *Session
	var worker *relay
	var workerErrors <-chan error
	var current string
	defer func() {
		if err := worker.stop(); err != nil {
			result = err
		}
		if active != nil {
			if err := active.Close(); err != nil {
				result = err
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-workerErrors:
			return err
		case e, ok := <-events:
			if !ok {
				return nil
			}
			if e.Destination != calls.Desk || !localCallID(e.ID) {
				return errors.New("invalid local event")
			}
			switch e.Kind {
			case calls.Incoming:
				if current != "" {
					return errors.New("ARI one-call limit")
				}
				current = e.ID
			case calls.Ringing:
				if current != e.ID {
					return errors.New("ARI event mismatch")
				}
			case calls.Answered:
				if current != e.ID || active != nil {
					return errors.New("ARI event mismatch or replay")
				}
				var err error
				active, err = c.Start(ctx, e.ID, media)
				if err != nil {
					return err
				}
				if frames.FromSIP != nil {
					worker, err = startRelay(ctx, e.ID, media, active.LocalPort, frames)
					if err != nil {
						return err
					}
					workerErrors = worker.errs
				}
			case calls.Ended:
				if current != e.ID {
					return errors.New("ARI event mismatch")
				}
				if active != nil {
					if err := worker.stop(); err != nil {
						return err
					}
					worker, workerErrors = nil, nil
					err := active.Close()
					active = nil
					if err != nil {
						return err
					}
				}
				current = ""
			default:
				return errors.New("invalid local lifecycle")
			}
		}
	}
}
