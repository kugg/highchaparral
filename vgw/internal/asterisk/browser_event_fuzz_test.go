package asterisk

import (
	"regexp"
	"strings"
	"testing"
)

// oracleChannelID is deliberately independent of the production validator so
// a regression in validChannelID is caught rather than mirrored.
var oracleChannelID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,94}[A-Za-z0-9]$`)

const fuzzValidBrowserEvent = `{"type":"StasisStart","application":"eventphone-vgw-browser","args":["browser-demo"],` +
	`"channel":{"id":"abc-00000001","name":"PJSIP/webrtc-lan-DEADBEEF","state":"Down",` +
	`"dialplan":{"context":"from-webrtc","exten":"e-555","app_name":"Stasis"}}}`

// FuzzBrowserStartParse fuzzes untrusted ARI/SIP browser-start events and
// the owned handoff classification boundary: missing, nil, malformed and
// contradictory events or headers, seeded with historical failure shapes
// such as absent content metadata. Invariants: no panic for an untrusted
// shape; malformed or incomplete events cannot advance call state;
// ambiguous events fail closed; error categories stay bounded and never
// contain raw protocol data.
func FuzzBrowserStartParse(f *testing.F) {
	f.Add([]byte(fuzzValidBrowserEvent))
	f.Add([]byte(`{"type":"StasisStart","application":"other-app","args":["browser-demo"],"channel":{}}`))
	f.Add([]byte(`{"type":"StasisStart","application":"eventphone-vgw-browser","args":[],"channel":{}}`))
	f.Add([]byte(`{"type":"StasisStart","application":"eventphone-vgw-browser","args":["browser-demo"]}`))
	f.Add([]byte(`{"type":"StasisStart","application":"eventphone-vgw-browser","args":["browser-demo"],` +
		`"channel":{"id":"abc-00000001","name":"PJSIP/other-DEADBEEF","state":"Down",` +
		`"dialplan":{"context":"from-webrtc","exten":"e-555","app_name":"Stasis"}}}`))
	f.Add([]byte(`{"type":"StasisStart","application":"eventphone-vgw-browser","args":["browser-demo"],` +
		`"channel":{"id":"abc..00000001","name":"PJSIP/webrtc-lan-DEADBEEF","state":"Down",` +
		`"dialplan":{"context":"from-webrtc","exten":"e-555","app_name":"Stasis"}}}`))
	f.Add([]byte(`{"type":"ChannelDestroyed"}`))
	f.Add([]byte(`{`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4096 {
			t.Skip()
		}
		start, err := ParseBrowserStart(raw)
		again, errAgain := ParseBrowserStart(raw)
		if (err == nil) != (errAgain == nil) || (err == nil && start != again) {
			t.Fatal("browser event parsing is not deterministic")
		}
		if err != nil {
			if err.Error() != "browser channel event unavailable" &&
				err.Error() != "browser channel event refused" {
				t.Fatal("browser event parser leaked an unreviewed error category")
			}
			return
		}
		if !oracleChannelID.MatchString(start.ChannelID) || strings.Contains(start.ChannelID, "..") {
			t.Fatal("browser start accepted an invalid channel identity")
		}
	})
}
