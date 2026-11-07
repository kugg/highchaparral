package asterisk

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

const (
	// This is an OWNED future dialplan entry, never an old ATA/Echo
	// extension or a dynamic SIP/SDP-selected target.
	browserApp     = "eventphone-vgw-browser"
	browserContext = "from-webrtc" // Asterisk reports caller context for owned included e-route.
)

var (
	channelID        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,94}[A-Za-z0-9]$`)
	browserLeg       = regexp.MustCompile(`^PJSIP/webrtc-lan-[A-Fa-f0-9]{1,32}$`)
	browserExtension = regexp.MustCompile(`^e-[0-9]{2,5}$`)
	browserNonce     = regexp.MustCompile(`^[a-f0-9]{32}$`)
)

// BrowserStart initially contains ONLY an Asterisk-generated channel ID;
// it never extracts caller data from Stasis arguments. After an authenticated
// ARI GET, a caller may set expected Nonce to bind subsequent readbacks.
// Admission still requires an authenticated ARI readback, exact BYOK
// nonce/destination reservation and durable call intent before INVITE.
type BrowserStart struct {
	ChannelID string
	Nonce     string // optional verified expectation; NEVER from Stasis args
}

// BrowserDial is a number parsed only from a CURRENT authenticated ARI
// channel readback in the owned provider-dialing context. It is not a
// provider INVITE, a caller credential or a replay authorization.
type BrowserDial struct {
	ChannelID   string
	Destination string
	Nonce       string // matches the bounded BYOK reservation after readback
}

type browserChannel struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	State    string `json:"state"`
	Dialplan struct {
		Context string `json:"context"`
		Exten   string `json:"exten"`
		AppName string `json:"app_name"`
	} `json:"dialplan"`
}

func activeBrowserChannel(channel browserChannel) bool {
	return channel.Dialplan.AppName == "Stasis" &&
		(channel.State == "Down" || channel.State == "Ring" || channel.State == "Up")
}

func validBrowserChannel(channel browserChannel) bool {
	return channel.Dialplan.Context == browserContext &&
		browserExtension.MatchString(channel.Dialplan.Exten) &&
		browserLeg.MatchString(channel.Name) && validChannelID(channel.ID)
}

func validChannelID(id string) bool {
	return channelID.MatchString(id) && !strings.Contains(id, "..")
}

// ParseBrowserStart rejects untrusted ARI event data unless it came through
// the future owned WebRTC context and a single fixed Stasis application.
// It never reflects a remote field into an error or a log.
func ParseBrowserStart(raw []byte) (BrowserStart, error) {
	var empty BrowserStart
	if len(raw) == 0 || len(raw) > 4096 {
		return empty, errors.New("browser channel event unavailable")
	}
	var event struct {
		Type        string         `json:"type"`
		Application string         `json:"application"`
		Args        []string       `json:"args"`
		Channel     browserChannel `json:"channel"`
	}
	if json.Unmarshal(raw, &event) != nil || event.Type != "StasisStart" ||
		event.Application != browserApp || len(event.Args) != 1 || event.Args[0] != "browser-demo" ||
		!validBrowserChannel(event.Channel) {
		return empty, errors.New("browser channel event refused")
	}
	return BrowserStart{ChannelID: event.Channel.ID}, nil
}
