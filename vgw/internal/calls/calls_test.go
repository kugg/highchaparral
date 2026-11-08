package calls

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"example.com/ata/voip-gateway/internal/safesip"
	"github.com/emiago/diago"
	"github.com/emiago/diago/media"
	"github.com/emiago/diago/media/sdp"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

func start(t *testing.T, ready <-chan struct{}, offerTimeout, maxCall time.Duration) (*Service, <-chan Event, context.Context) {
	t.Helper()
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()
	m, err := New(Config{Port: port, DialedUser: "desk", Destination: Desk,
		Ready: ready, OfferTimeout: min(offerTimeout, maxCall),
		ACKTimeout: min(250*time.Millisecond, maxCall/2), MaxCall: maxCall})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := m.Start(ctx); err != nil {
		cancel()
		m.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); m.Close() })
	return m, m.Events(), ctx
}

func peer(t *testing.T) *diago.Diago {
	t.Helper()
	ua, err := sipgo.NewUA(sipgo.WithUserAgentTransportLayerOptions(
		sip.WithTransportLayerLogger(safesip.Logger)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ua.Close() })
	d := diago.NewDiago(ua,
		diago.WithTransport(diago.Transport{Transport: "udp", BindHost: "127.0.0.1", BindPort: 0}),
		diago.WithMediaConfig(diago.MediaConfig{Codecs: []media.Codec{media.CodecAudioAlaw}}),
		diago.WithLogger(safesip.Logger))
	// This peer only originates calls. Starting its unused UAS listener races
	// Diago readiness against sipgo's registration of that socket for UAC reuse.
	return d
}

func nextEvent(t *testing.T, sink <-chan Event, want Kind) Event {
	t.Helper()
	select {
	case e := <-sink:
		if e.Kind != want || e.Destination != Desk ||
			!regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(e.ID) {
			t.Fatalf("unexpected sanitized event kind/destination/ID: %d/%d", e.Kind, e.Destination)
		}
		return e
	case <-time.After(4 * time.Second):
		t.Fatalf("no event %d", want)
		return Event{}
	}
}

func invite(t *testing.T, d *diago.Diago, ctx context.Context, port int, user string) *diago.DialogClientSession {
	t.Helper()
	dialog, err := d.Invite(ctx, sip.Uri{User: user, Host: "127.0.0.1", Port: port}, diago.InviteOptions{})
	if err != nil {
		var rejected *sipgo.ErrDialogResponse
		switch {
		case errors.As(err, &rejected) && rejected.Res != nil:
			t.Fatalf("local INVITE rejected with SIP status %d", rejected.Res.StatusCode)
		case errors.Is(err, syscall.EADDRINUSE):
			t.Fatal("local INVITE socket bind collided")
		case errors.Is(err, sip.ErrTransactionTransport):
			t.Fatal("local INVITE transport failed")
		case errors.Is(err, context.DeadlineExceeded), errors.Is(err, sip.ErrTransactionTimeout):
			t.Fatal("local INVITE timed out")
		default:
			t.Fatalf("local INVITE failed (%T)", err) // never print SIP/SDP or a remote response
		}
	}
	t.Cleanup(func() { _ = dialog.Close() })
	return dialog
}

func awaitIdle(t *testing.T, m *Service) {
	t.Helper()
	deadline := time.After(time.Second)
	for m.active.Load() {
		select {
		case <-deadline:
			t.Fatal("admission slot stayed occupied")
		case <-time.After(time.Millisecond):
		}
	}
}

func TestNormalCallAndBye(t *testing.T) {
	m, sink, ctx := start(t, nil, time.Second, 2*time.Second)
	d := peer(t)
	callCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	dialog := invite(t, d, callCtx, m.config.Port, "desk")
	a, b, c := nextEvent(t, sink, Incoming), nextEvent(t, sink, Ringing), nextEvent(t, sink, Answered)
	if a.ID != b.ID || b.ID != c.ID || a.ID == dialog.InviteRequest.CallID().Value() {
		t.Fatal("local call ID changed or copied SIP identifier")
	}
	if err := dialog.Hangup(callCtx); err != nil {
		t.Fatal("local BYE failed")
	}
	e := nextEvent(t, sink, Ended)
	if e.ID != a.ID {
		t.Fatal("end event has wrong local ID")
	}
	awaitIdle(t, m)
}

func TestBusyAndWrongDestination(t *testing.T) {
	gate := make(chan struct{})
	m, sink, ctx := start(t, gate, 2*time.Second, 2*time.Second)
	d := peer(t)
	callCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	first, err := d.NewDialog(sip.Uri{User: "desk", Host: "127.0.0.1", Port: m.config.Port}, diago.NewDialogOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	firstDone := make(chan error, 1)
	go func() { firstDone <- first.Invite(callCtx, diago.InviteClientOptions{}) }()
	nextEvent(t, sink, Incoming)
	nextEvent(t, sink, Ringing)
	for _, tc := range []struct {
		user string
		code int
	}{{"desk", sip.StatusBusyHere}, {"other", sip.StatusNotFound}} {
		_, err := d.Invite(callCtx, sip.Uri{User: tc.user, Host: "127.0.0.1", Port: m.config.Port}, diago.InviteOptions{})
		var rejected *sipgo.ErrDialogResponse
		if !errors.As(err, &rejected) || rejected.Res.StatusCode != tc.code {
			t.Fatalf("expected SIP %d for admitted target policy", tc.code)
		}
	}
	close(gate)
	if err := <-firstDone; err != nil {
		t.Fatal("initial INVITE failed")
	}
	if err := first.Ack(callCtx); err != nil {
		t.Fatal("ACK failed")
	}
	nextEvent(t, sink, Answered)
	if err := first.Hangup(callCtx); err != nil {
		t.Fatal("BYE failed")
	}
	nextEvent(t, sink, Ended)
	awaitIdle(t, m)
}

func TestCancelBeforeAnswer(t *testing.T) {
	gate := make(chan struct{})
	m, sink, ctx := start(t, gate, 2*time.Second, 2*time.Second)
	d := peer(t)
	callCtx, cancelCall := context.WithTimeout(ctx, 4*time.Second)
	defer cancelCall()
	dialog, err := d.NewDialog(sip.Uri{User: "desk", Host: "127.0.0.1", Port: m.config.Port}, diago.NewDialogOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer dialog.Close()
	gotRinging := make(chan struct{}, 1)
	done := make(chan error, 1)
	inviteCtx, cancelInvite := context.WithCancel(callCtx)
	go func() {
		done <- dialog.Invite(inviteCtx, diago.InviteClientOptions{OnResponse: func(res *sip.Response) error {
			if res.StatusCode == sip.StatusRinging {
				select {
				case gotRinging <- struct{}{}:
				default:
				}
			}
			return nil
		}})
	}()
	nextEvent(t, sink, Incoming)
	nextEvent(t, sink, Ringing)
	select {
	case <-gotRinging:
	case <-callCtx.Done():
		t.Fatal("no provisional ringing before CANCEL")
	}
	cancelInvite() // sipgo sends correlated CANCEL and handles 487
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("CANCEL did not end INVITE")
	}
	nextEvent(t, sink, Ended)
	awaitIdle(t, m)
}

func TestOfferTimeout(t *testing.T) {
	gate := make(chan struct{})
	m, sink, ctx := start(t, gate, 80*time.Millisecond, time.Second)
	d := peer(t)
	callCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	_, err := d.Invite(callCtx, sip.Uri{User: "desk", Host: "127.0.0.1", Port: m.config.Port}, diago.InviteOptions{})
	var rejected *sipgo.ErrDialogResponse
	if !errors.As(err, &rejected) || rejected.Res.StatusCode != sip.StatusRequestTimeout {
		t.Fatal("no bounded offer timeout")
	}
	nextEvent(t, sink, Incoming)
	nextEvent(t, sink, Ringing)
	nextEvent(t, sink, Ended)
	awaitIdle(t, m)
}

func TestCallDurationAndUnsupportedMethods(t *testing.T) {
	m, sink, ctx := start(t, nil, time.Second, 120*time.Millisecond)
	d := peer(t)
	callCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	dialog := invite(t, d, callCtx, m.config.Port, "desk")
	nextEvent(t, sink, Incoming)
	nextEvent(t, sink, Ringing)
	nextEvent(t, sink, Answered)
	for _, method := range []sip.RequestMethod{sip.INVITE, sip.REFER, sip.INFO, sip.UPDATE} {
		req := sip.NewRequest(method, dialog.RemoteContact().Address)
		res, err := dialog.Do(callCtx, req)
		if err != nil || (res.StatusCode != sip.StatusNotAcceptableHere && res.StatusCode != sip.StatusMethodNotAllowed) {
			t.Fatalf("unsupported method %s not rejected", method)
		}
	}
	select {
	case <-dialog.Context().Done():
	case <-callCtx.Done():
		t.Fatal("call timeout did not terminate dialog")
	}
	nextEvent(t, sink, Ended)
	awaitIdle(t, m)
}

func TestInvalidPolicy(t *testing.T) {
	for _, c := range []Config{
		{},
		{Port: 5060, DialedUser: "other@host", Destination: Desk, OfferTimeout: time.Second, ACKTimeout: time.Second, MaxCall: time.Second},
		{Port: 5060, DialedUser: "desk", Destination: 2, OfferTimeout: time.Second, ACKTimeout: time.Second, MaxCall: time.Second},
		{Port: 5060, DialedUser: "desk", Destination: Desk, OfferTimeout: time.Second, MaxCall: time.Second},
		{Port: 5060, DialedUser: "desk", Destination: Desk, OfferTimeout: time.Second, ACKTimeout: 10 * time.Millisecond, MaxCall: time.Second},
		{Port: 5060, DialedUser: "desk", Destination: Desk, OfferTimeout: time.Second, ACKTimeout: 11 * time.Second, MaxCall: time.Minute},
		{Port: 5060, DialedUser: "desk", Destination: Desk, OfferTimeout: time.Second, ACKTimeout: 2 * time.Second, MaxCall: time.Second},
	} {
		if _, err := New(c); err == nil {
			t.Fatal("invalid policy accepted")
		}
	}
}

func TestACKTimeoutConfigBoundaries(t *testing.T) {
	for _, d := range []time.Duration{25 * time.Millisecond, 50 * time.Millisecond, time.Second, 10 * time.Second} {
		s, err := New(Config{Port: 5060, DialedUser: "desk", Destination: Desk,
			OfferTimeout: time.Second, ACKTimeout: d, MaxCall: time.Minute})
		if err != nil {
			t.Fatal("valid ACK timeout rejected")
		}
		s.Close()
	}
}

func TestACKJustBeforeDeadlineKeepsCallAlive(t *testing.T) {
	m, events, ctx := start(t, nil, 500*time.Millisecond, 500*time.Millisecond)
	d := peer(t)
	callCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	dialog, err := d.NewDialog(sip.Uri{User: "desk", Host: "127.0.0.1", Port: m.config.Port}, diago.NewDialogOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer dialog.Close()
	if err := dialog.Invite(callCtx, diago.InviteClientOptions{}); err != nil {
		t.Fatal("pre-ACK invite failed")
	}
	nextEvent(t, events, Incoming)
	nextEvent(t, events, Ringing)
	// The configured ACK deadline is 250ms; send ACK well within it.
	select {
	case <-time.After(60 * time.Millisecond):
	case <-callCtx.Done():
		t.Fatal("call context ended before ACK")
	}
	if err := dialog.Ack(callCtx); err != nil {
		t.Fatal("timely ACK failed")
	}
	nextEvent(t, events, Answered)
	if m.failed.Load() {
		t.Fatal("timely ACK caused fail-closed state")
	}
	if err := dialog.Hangup(callCtx); err != nil {
		t.Fatal("BYE after ACK failed")
	}
	nextEvent(t, events, Ended)
	awaitIdle(t, m)
}

func TestInboundTargetCannotChangeURIOrInject(t *testing.T) {
	for _, user := range []string{"a", strings.Repeat("a", 64), "alice_01"} {
		s := &Service{config: Config{DialedUser: user, Port: 5070}}
		req := sip.NewRequest(sip.INVITE, sip.Uri{User: user, Host: "127.0.0.1", Port: 5070})
		if !s.allowedTarget(req) {
			t.Fatal("valid configured local target rejected")
		}
	}
	s := &Service{config: Config{DialedUser: "desk", Port: 5070}}
	for _, tc := range []sip.Uri{
		{User: "other", Host: "127.0.0.1", Port: 5070},
		{User: "álîçë", Host: "127.0.0.1", Port: 5070},
		{User: "bob!@#$", Host: "127.0.0.1", Port: 5070},
		{User: strings.Repeat("a", 65), Host: "127.0.0.1", Port: 5070},
		{User: "' OR '1'='1", Host: "127.0.0.1", Port: 5070},
		{User: "desk", Host: "localhost", Port: 5070},
		{User: "desk", Host: "192.0.2.1", Port: 5070},
		{User: "desk", Host: "127.0.0.1", Port: 9999},
		{User: "desk", Host: "127.0.0.1"},
		{User: "desk", Port: 5070},
		{Host: "127.0.0.1", Port: 5070},
	} {
		if s.allowedTarget(sip.NewRequest(sip.INVITE, tc)) {
			t.Fatal("malformed or misrouted SIP target accepted")
		}
	}
}

func TestUnresponsiveEventConsumerFailsClosed(t *testing.T) {
	m, events, ctx := start(t, nil, time.Second, time.Second)
	d := peer(t)
	callCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	first := invite(t, d, callCtx, m.config.Port, "desk")
	// Invite may return as ACK races with the server's Answered callback.
	// Keep the consumer undrained, but await the third queued transition
	// before BYE so this tests buffer admission rather than ACK/BYE timing.
	for len(events) < 3 {
		select {
		case <-callCtx.Done():
			t.Fatal("first answered event did not arrive")
		case <-time.After(time.Millisecond):
		}
	}
	if err := first.Hangup(callCtx); err != nil {
		t.Fatal("BYE failed")
	}
	awaitIdle(t, m)
	if len(events) != 4 {
		t.Fatal("first call did not deliver four bounded events")
	}
	_, err := d.Invite(callCtx, sip.Uri{User: "desk", Host: "127.0.0.1", Port: m.config.Port}, diago.InviteOptions{})
	var rejected *sipgo.ErrDialogResponse
	if !errors.As(err, &rejected) || rejected.Res.StatusCode != sip.StatusServiceUnavailable {
		t.Fatal("undrained event buffer did not fail admission closed")
	}
	awaitIdle(t, m)
}

// TestACKWatchdogSubprocess runs only as a disposable, local-only test worker.
// Its exit reclaims library goroutines that have no public cancellation API.
func TestACKWatchdogSubprocess(t *testing.T) {
	if os.Getenv("M2_ACK_HELPER") != "1" {
		return
	}
	port, err := strconv.Atoi(os.Getenv("M2_ACK_PORT"))
	if err != nil {
		os.Exit(22)
	}
	s, err := New(Config{Port: port, DialedUser: "desk", Destination: Desk,
		OfferTimeout: 200 * time.Millisecond, ACKTimeout: 70 * time.Millisecond,
		MaxCall: 500 * time.Millisecond})
	if err != nil {
		os.Exit(22)
	}
	if err := s.Start(context.Background()); err != nil {
		os.Exit(22)
	}
	fmt.Fprintln(os.Stdout, "READY")
	if errors.Is(<-s.Failure(), ErrACKTimeout) {
		os.Exit(21)
	}
	os.Exit(22)
}

func TestNoACKDeadlineClosesWorkerSockets(t *testing.T) {
	probe, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.LocalAddr().(*net.UDPAddr).Port
	probe.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestACKWatchdogSubprocess$")
	cmd.Env = append(os.Environ(), "M2_ACK_HELPER=1", fmt.Sprintf("M2_ACK_PORT=%d", port))
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	line, err := bufio.NewReader(pipe).ReadString('\n')
	if err != nil || line != "READY\n" {
		t.Fatal("local worker did not reach SIP readiness")
	}
	d := peer(t)
	dialog, err := d.NewDialog(sip.Uri{User: "desk", Host: "127.0.0.1", Port: port}, diago.NewDialogOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer dialog.Close()
	if err := dialog.Invite(ctx, diago.InviteClientOptions{}); err != nil {
		t.Fatal("no-ACK test INVITE failed")
	}
	sd := sdp.SessionDescription{}
	if err := sdp.Unmarshal(dialog.InviteResponse.Body(), &sd); err != nil {
		t.Fatal("could not inspect synthetic SDP port")
	}
	fields := strings.Fields(sd.Value("m"))
	if len(fields) < 2 {
		t.Fatal("no media port in local answer")
	}
	rtpPort, err := strconv.Atoi(fields[1])
	if err != nil || rtpPort < 1 || rtpPort > 65535 {
		t.Fatal("invalid synthetic RTP port")
	}
	// Do not ACK. Child must fail closed and exit, freeing kernel sockets.
	err = cmd.Wait()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 21 || ctx.Err() != nil {
		t.Fatal("ACK deadline did not terminate local worker")
	}
	released, err := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal("worker left SIP listening port occupied")
	}
	released.Close()
	rtpReleased, err := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", rtpPort))
	if err != nil {
		t.Fatal("worker left RTP port occupied")
	}
	rtpReleased.Close()
}
