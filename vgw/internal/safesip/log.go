// Package safesip installs a process-wide no-packet logging baseline for
// the pinned sipgo version. Import it before creating any SIP user agent.
package safesip

import (
	"io"
	"log/slog"

	"github.com/emiago/diago/media"
	"github.com/emiago/sipgo/sip"
)

var Logger = slog.New(slog.NewTextHandler(io.Discard, nil))

type discardTrace struct{}

func (discardTrace) SIPTraceRead(string, string, string, []byte)  {}
func (discardTrace) SIPTraceWrite(string, string, string, []byte) {}

func init() {
	media.SetDefaultLogger(Logger) // Suppress inbound RTP header/sequence logging.
	sip.SetDefaultLogger(Logger)
	// sipgo's SIPDebug path writes raw Authorization-bearing messages to
	// stderr unless a tracer is installed; loggers alone do not stop it.
	sip.SIPDebugTracer(discardTrace{})
}
