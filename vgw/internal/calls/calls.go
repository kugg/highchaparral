// Package calls is the M2 local-only inbound call boundary. SIP dialog,
// transaction, ACK/CANCEL/BYE and media session ownership stay in Diago/sipgo.
package calls

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"example.com/ata/voip-gateway/internal/loopback"
	"example.com/ata/voip-gateway/internal/safesip"
	"github.com/emiago/diago"
	"github.com/emiago/diago/media"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

type Destination uint8

const Desk Destination = 1

type Kind uint8

const (
	Incoming Kind = iota + 1
	Ringing
	Answered
	Ended
)

// Event never contains a SIP identifier, header, address, SDP or RTP bytes.
type Event struct {
	ID          string
	Destination Destination
	Kind        Kind
}

// Config admits exactly one local SIP user and one typed internal target.
type Config struct {
	Port         int
	DialedUser   string
	Destination  Destination
	OfferTimeout time.Duration
	ACKTimeout   time.Duration
	MaxCall      time.Duration
	// Ready is an optional local answer decision; nil answers immediately.
	// A pending decision is denied after OfferTimeout or on CANCEL.
	Ready <-chan struct{}
	// MediaEnabled exposes only owned PCMA frames to the fixed local lab.
	// The default remains signaling-only; it never enables an outside port.
	MediaEnabled bool
}

type Service struct {
	config    Config
	events    chan Event
	ua        *sipgo.UserAgent
	diago     *diago.Diago
	ctx       context.Context
	active    atomic.Bool
	failed    atomic.Bool
	started   atomic.Bool
	closeOnce sync.Once
	fatal     chan error
	toGateway chan AudioFrame
	toSIP     chan AudioFrame
}

// AudioFrame contains one 20 ms PCMA payload, never SIP/RTP headers,
// addresses or remote SSRC. ID is the locally allocated canonical call ID.
type AudioFrame struct {
	ID      string
	Payload [160]byte
}

// ErrACKTimeout requires a process-level restart: pinned Diago has no API
// to cancel its outstanding 200/ACK wait. Do not reuse this Service.
var ErrACKTimeout = errors.New("local ACK deadline exceeded")
var ErrMediaFailure = errors.New("local media session failed")

func validUser(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' ||
			b >= '0' && b <= '9' || b == '.' || b == '_' || b == '-') {
			return false
		}
	}
	return true
}

// New creates only a numeric IPv4-loopback SIP listener. The caller owns Close.
func New(c Config) (*Service, error) {
	if c.Port < 1 || c.Port > 65535 || c.Destination != Desk ||
		!validUser(c.DialedUser) || c.OfferTimeout <= 0 ||
		c.OfferTimeout > 10*time.Second || c.ACKTimeout < 25*time.Millisecond ||
		c.ACKTimeout > 10*time.Second || c.MaxCall <= 0 ||
		c.MaxCall > time.Minute || c.ACKTimeout > c.MaxCall ||
		c.OfferTimeout > c.MaxCall {
		return nil, errors.New("invalid local call policy")
	}
	quiet := safesip.Logger
	ua, err := sipgo.NewUA(sipgo.WithUserAgentTransportLayerOptions(
		sip.WithTransportLayerLogger(quiet)), sipgo.WithUserAgentTransactionLayerOptions(
		sip.WithTransactionLayerLogger(quiet),
		sip.WithTransactionLayerUnhandledResponseHandler(func(*sip.Response) {})))
	if err != nil {
		return nil, errors.New("cannot initialize local SIP user agent")
	}
	server, err := sipgo.NewServer(ua, sipgo.WithServerLogger(quiet))
	if err != nil {
		_ = ua.Close()
		return nil, errors.New("cannot initialize local SIP server")
	}
	s := &Service{config: c, events: make(chan Event, 4), fatal: make(chan error, 1), ua: ua}
	if c.MediaEnabled {
		s.toGateway = make(chan AudioFrame, 4)
		s.toSIP = make(chan AudioFrame, 4)
	}
	server.OnUpdate(func(req *sip.Request, tx sip.ServerTransaction) {
		_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusMethodNotAllowed, "Method Not Allowed", nil))
	})
	s.diago = diago.NewDiago(ua,
		diago.WithServer(server),
		diago.WithTransport(diago.Transport{Transport: "udp", BindHost: "127.0.0.1", BindPort: c.Port}),
		diago.WithMediaConfig(diago.MediaConfig{Codecs: []media.Codec{media.CodecAudioAlaw}}),
		diago.WithLogger(quiet),
		diago.WithServerRequestMiddleware(s.filter),
	)
	return s, nil
}

// Events is receive-only: a consumer cannot close the producer's channel.
// Every call can generate at most four events; no later call is admitted
// until its entire four-event capacity is available.
func (s *Service) Events() <-chan Event { return s.events }

// Failure reports a fail-closed ACK deadline. The owner must exit/restart
// its process: the pinned library cannot safely cancel its in-flight dialog.
func (s *Service) Failure() <-chan error { return s.fatal }

// MediaToGateway and MediaFromGateway are nonblocking, fixed-capacity local
// frame lanes. Only the call handler owns the actual Diago media session.
func (s *Service) MediaToGateway() <-chan AudioFrame   { return s.toGateway }
func (s *Service) MediaFromGateway() chan<- AudioFrame { return s.toSIP }

func (s *Service) failMedia() {
	s.failed.Store(true)
	select {
	case s.fatal <- ErrMediaFailure:
	default:
	}
}

func (s *Service) pumpAudio(ctx context.Context, d *diago.DialogServerSession, id string) error {
	reader, err := d.AudioReader()
	if err != nil || reader == nil {
		return ErrMediaFailure
	}
	writer, err := d.AudioWriter()
	if err != nil || writer == nil {
		return ErrMediaFailure
	}
	go func() {
		var buf [2048]byte // larger than the pinned Diago RTP read buffer
		for {
			n, err := reader.Read(buf[:])
			if err != nil {
				if ctx.Err() == nil && s.ctx.Err() == nil && !errors.Is(err, io.EOF) {
					s.failMedia()
				}
				return
			}
			if n != 160 || d.RTPPacketReader.PacketHeader.PayloadType != 8 {
				continue // drop malformed or non-PCMA frames; no raw logging
			}
			var frame AudioFrame
			frame.ID = id
			copy(frame.Payload[:], buf[:n])
			select {
			case <-ctx.Done():
				return
			case s.toGateway <- frame:
			default: // bounded jitter: drop rather than block the SIP media reader
			}
		}
	}()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case frame := <-s.toSIP:
				if frame.ID != id || ctx.Err() != nil {
					continue // discard any buffered frame from a previous call
				}
				if n, err := writer.Write(frame.Payload[:]); err != nil || n != 160 {
					if ctx.Err() == nil && s.ctx.Err() == nil {
						s.failMedia()
					}
					return
				}
			}
		}
	}()
	return nil
}

func (s *Service) allowedTarget(req *sip.Request) bool {
	u := req.Recipient
	return validUser(u.User) && u.User == s.config.DialedUser &&
		u.Host == "127.0.0.1" && u.Port == s.config.Port
}

// filter is a narrow pre-dialog policy on requests already parsed by sipgo.
// It does not implement SIP parsing or transaction state.
func (s *Service) filter(next sipgo.RequestHandler) sipgo.RequestHandler {
	return func(req *sip.Request, tx sip.ServerTransaction) {
		code := 0
		switch req.Method {
		case sip.INVITE:
			if s.failed.Load() || len(s.events) > cap(s.events)-4 {
				code = sip.StatusServiceUnavailable
			} else if to := req.To(); to != nil && to.Params.Has("tag") {
				code = sip.StatusNotAcceptableHere // no in-dialog re-INVITE
			} else if !s.allowedTarget(req) {
				code = sip.StatusNotFound
			} else if ct := req.ContentType(); ct == nil || ct.Value() != "application/sdp" ||
				!loopback.AllowOffer(req.Body()) {
				code = sip.StatusNotAcceptableHere
			}
		case sip.ACK, sip.CANCEL, sip.BYE:
			// Diago/sipgo correlate dialogs and transactions.
		default:
			code = sip.StatusMethodNotAllowed // REFER/transfer/INFO/NOTIFY/OPTIONS
		}
		if code != 0 {
			_ = tx.Respond(sip.NewResponseFromRequest(req, code, "Rejected", nil))
			return
		}
		next(req, tx)
	}
}

// emit never waits for an event consumer. An unexpectedly full channel
// fails admission closed rather than holding the SIP transaction or slot.
func (s *Service) emit(e Event) bool {
	select {
	case s.events <- e:
		return true
	default:
		s.failed.Store(true)
		return false
	}
}

func (s *Service) handle(d *diago.DialogServerSession) {
	if s.failed.Load() || len(s.events) > cap(s.events)-4 {
		_ = d.Respond(sip.StatusServiceUnavailable, "Unavailable", nil)
		return
	}
	if !s.active.CompareAndSwap(false, true) {
		_ = d.Respond(sip.StatusBusyHere, "Busy Here", nil)
		return
	}
	defer s.active.Store(false)
	started := time.Now()
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		_ = d.Respond(sip.StatusInternalServerError, "Internal Error", nil)
		return
	}
	id := hex.EncodeToString(raw[:]) // locally allocated; never a SIP Call-ID
	emit := func(kind Kind) bool { return s.emit(Event{ID: id, Destination: Desk, Kind: kind}) }
	if !emit(Incoming) {
		_ = d.Respond(sip.StatusServiceUnavailable, "Unavailable", nil)
		return
	}
	ended := true
	defer func() {
		if ended {
			emit(Ended)
		}
	}()
	if err := d.Trying(); err != nil {
		return
	}
	if err := d.Ringing(); err != nil {
		return
	}
	if !emit(Ringing) {
		_ = d.Respond(sip.StatusServiceUnavailable, "Unavailable", nil)
		return
	}
	if s.config.Ready != nil {
		timer := time.NewTimer(s.config.OfferTimeout)
		defer timer.Stop()
		select {
		case <-d.Context().Done(): // CANCEL or transaction termination
			return
		case <-s.ctx.Done():
			return
		case <-timer.C:
			_ = d.Respond(sip.StatusRequestTimeout, "Request Timeout", nil)
			return
		case <-s.config.Ready:
		}
	}
	if d.Context().Err() != nil || s.ctx.Err() != nil {
		return
	}
	if !time.Now().Before(started.Add(s.config.MaxCall)) {
		_ = d.Respond(sip.StatusRequestTimeout, "Request Timeout", nil)
		return
	}
	// Answer waits for ACK without a caller context. The pinned sipgo
	// retransmission path can outlast MaxCall. A watchdog fails the whole
	// service closed rather than pretending to terminate that transaction.
	ackWait := min(s.config.ACKTimeout, time.Until(started.Add(s.config.MaxCall)))
	ackTimer := time.NewTimer(ackWait)
	defer ackTimer.Stop()
	answer := make(chan error, 1)
	go func() { answer <- d.Answer() }()
	var answerErr error
	select {
	case answerErr = <-answer:
	case <-ackTimer.C:
		// If ACK and timer race, prefer a finished Answer. Otherwise the
		// only safe recovery without a library cancellation API is to
		// stop admitting calls and exit the owning process.
		select {
		case answerErr = <-answer:
		default:
			s.failed.Store(true)
			ended = false // an un-ACKed 200 is not a confirmed ended call
			select {
			case s.fatal <- ErrACKTimeout:
			default:
			}
			return
		}
	case <-s.ctx.Done():
		return
	}
	if answerErr != nil {
		return
	}
	if d.Context().Err() != nil {
		return
	}
	if !emit(Answered) {
		stop, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = d.Hangup(stop)
		return
	}
	if s.config.MediaEnabled {
		mediaCtx, cancel := context.WithCancel(d.Context())
		defer cancel()
		if err := s.pumpAudio(mediaCtx, d, id); err != nil {
			s.failMedia()
			return
		}
	}
	remaining := time.Until(started.Add(s.config.MaxCall))
	if remaining < 0 {
		remaining = 0
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-d.Context().Done(): // library received BYE
		return
	case <-s.ctx.Done():
	case <-timer.C:
	}
	stop, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = d.Hangup(stop)
}

// Start starts only the local listener, waiting until it is ready.
func (s *Service) Start(ctx context.Context) error {
	if !s.started.CompareAndSwap(false, true) {
		return errors.New("local listener already started")
	}
	s.ctx = ctx
	if err := s.diago.ServeBackground(ctx, s.handle); err != nil {
		return errors.New("local listener failed")
	}
	return nil
}

// Close releases the local SIP user agent; callers cancel Start's context first.
func (s *Service) Close() {
	s.closeOnce.Do(func() { _ = s.ua.Close() })
}

// Serve owns only SIP listening. Cancel the context before Close.
func (s *Service) Serve(ctx context.Context) error {
	if !s.started.CompareAndSwap(false, true) {
		return errors.New("local listener already started")
	}
	s.ctx = ctx
	served := make(chan error, 1)
	go func() { served <- s.diago.Serve(ctx, s.handle) }()
	select {
	case err := <-served:
		if err != nil && ctx.Err() == nil {
			slog.Warn("local listener stopped")
			return errors.New("local listener failed")
		}
		return nil
	case err := <-s.fatal:
		return err
	case <-ctx.Done():
		return nil
	}
}
