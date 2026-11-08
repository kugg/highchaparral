// Package loopback is an M0-only SIP/RTP echo demonstration. It has no
// registration, provider or PBX connection.
package loopback

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"

	"github.com/emiago/diago"
	"github.com/emiago/diago/media"
	"github.com/emiago/diago/media/sdp"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

// New creates a library-managed SIP service bound exclusively to IPv4 loopback.
// The returned user agent is owned by the caller and must be closed.
func New(port int) (*diago.Diago, *sipgo.UserAgent, error) {
	if port < 1 || port > 65535 {
		return nil, nil, fmt.Errorf("invalid local SIP port")
	}
	ua, err := sipgo.NewUA()
	if err != nil {
		return nil, nil, err
	}
	d := diago.NewDiago(ua,
		diago.WithTransport(diago.Transport{Transport: "udp", BindHost: "127.0.0.1", BindPort: port}),
		diago.WithMediaConfig(diago.MediaConfig{Codecs: []media.Codec{media.CodecAudioAlaw}}),
	)
	return d, ua, nil
}

// Handle answers one library-managed dialog and echoes encoded audio through
// Diago's RTP reader and writer. BYE/transaction handling belongs to Diago.
func Handle(dialog *diago.DialogServerSession) {
	if !AllowOffer(dialog.InviteRequest.Body()) {
		_ = dialog.Respond(sip.StatusNotAcceptableHere, "Not Acceptable Here", nil)
		return
	}
	if err := dialog.Trying(); err != nil {
		slog.Warn("trying failed")
		return
	}
	dm, err := dialog.Answer(diago.AnswerOptions{})
	if err != nil {
		slog.Warn("answer failed")
		return
	}
	if err := dm.Echo(); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
		// Never log remote SIP headers, SDP, media, or library errors containing them.
		slog.Warn("echo stopped")
	}
}

// AllowOffer is a deliberately narrow local egress guard, not a general SDP
// implementation. Diago still owns SDP parsing, negotiation and RTP.
func AllowOffer(raw []byte) bool {
	if len(raw) == 0 || len(raw) > 2048 || !bytes.HasSuffix(raw, []byte("\r\n")) {
		return false
	}
	lines := bytes.Split(raw[:len(raw)-2], []byte("\r\n"))
	for _, line := range lines {
		if len(line) < 2 || bytes.ContainsAny(line, "\r\n\x00") {
			return false
		}
	}
	sd := sdp.SessionDescription{}
	if err := sdp.Unmarshal(raw, &sd); err != nil {
		return false
	}
	if cs := sd.Values("c"); len(cs) != 1 || cs[0] != "IN IP4 127.0.0.1" {
		return false
	}
	if len(sd.Values("m")) != 1 {
		return false
	}
	fields := strings.Fields(sd.Value("m"))
	if len(fields) != 4 || fields[0] != "audio" || fields[2] != "RTP/AVP" || fields[3] != "8" {
		return false
	}
	port, err := strconv.Atoi(fields[1])
	return err == nil && port > 0 && port <= 65535
}

// Run serves until the context is cancelled; it does not initiate any call.
func Run(ctx context.Context, port int) error {
	d, ua, err := New(port)
	if err != nil {
		return err
	}
	defer ua.Close()
	return d.Serve(ctx, Handle)
}
