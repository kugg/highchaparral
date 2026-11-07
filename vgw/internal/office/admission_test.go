package office

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/emiago/sipgo/sip"
)

const syntheticSDP = "v=0\r\no=- 1 1 IN IP4 203.0.113.8\r\ns=office-synthetic\r\nc=IN IP4 203.0.113.8\r\nt=0 0\r\nm=audio 20000 RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\n"

func syntheticInvite(t *testing.T, uriUser, toUser, transport, body string) *sip.Request {
	t.Helper()
	wire := fmt.Sprintf("INVITE sip:%s@192.0.2.12 SIP/2.0\r\nVia: SIP/2.0/%s provider.invalid:5061;branch=z9hG4bKsynthetic\r\nFrom: <sip:peer@provider.invalid>;tag=untrusted\r\nTo: <sip:%s@192.0.2.12>\r\nCall-ID: synthetic@provider.invalid\r\nCSeq: 1 INVITE\r\nMax-Forwards: 70\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s",
		uriUser, transport, toUser, len(body), body)
	parsed, err := sip.NewParser().ParseSIP([]byte(wire))
	request, ok := parsed.(*sip.Request)
	if err != nil || !ok {
		t.Fatal("synthetic SIP request parser unavailable")
	}
	return request
}

func newSyntheticAdmission(t *testing.T) *Admission {
	t.Helper()
	policy, ok := NewAdmission("1234", "192.0.2.12", []net.IP{net.ParseIP("203.0.113.8")})
	if !ok {
		t.Fatal("fixed synthetic policy refused")
	}
	return policy
}

func TestOfficeAdmissionRequiresRegistrationAndDefiniteCleanup(t *testing.T) {
	policy := newSyntheticAdmission(t)
	request := syntheticInvite(t, "1234", "1234", "TLS", syntheticSDP)
	if policy.Admit(request) != Reject {
		t.Fatal("pre-registration INVITE admitted")
	}
	policy.Registered()
	if policy.Admit(request) != Admit || policy.Admit(request) != Busy {
		t.Fatal("the exact office INVITE did not consume one slot")
	}
	if policy.Finish(false) || policy.Admit(request) != Busy {
		t.Fatal("ambiguous teardown released the only call slot")
	}
	if !policy.Finish(true) || policy.Finish(true) {
		t.Fatal("definite cleanup did not release exactly one slot")
	}
	policy.LostRegistration()
	if policy.Admit(request) != Reject {
		t.Fatal("provider registration loss allowed another call")
	}
}

func TestOfficeAdmissionRejectsUntrustedSIPAndSDPWithoutConsumingSlot(t *testing.T) {
	policy := newSyntheticAdmission(t)
	policy.Registered()
	for _, tc := range []struct {
		name, uri, to, transport, body string
	}{
		{"wrong URI", "9999", "1234", "TLS", syntheticSDP},
		{"wrong To", "1234", "9999", "TLS", syntheticSDP},
		{"no TLS", "1234", "1234", "UDP", syntheticSDP},
		{"wrong media source", "1234", "1234", "TLS", strings.ReplaceAll(syntheticSDP, "c=IN IP4 203.0.113.8", "c=IN IP4 10.47.11.94")},
		{"second media source", "1234", "1234", "TLS", syntheticSDP + "c=IN IP4 203.0.113.8\r\n"},
		{"wrong codec", "1234", "1234", "TLS", strings.ReplaceAll(syntheticSDP, "RTP/AVP 8", "RTP/AVP 0")},
		{"extra codec", "1234", "1234", "TLS", strings.ReplaceAll(syntheticSDP, "RTP/AVP 8", "RTP/AVP 8 0")},
		{"injected attribute", "1234", "1234", "TLS", syntheticSDP + "a=x-sql-template:UNTRUSTED\r\n"},
		{"embedded LF", "1234", "1234", "TLS", syntheticSDP + "a=sendrecv\nX=Injected\r\n"},
		{"duplicated version", "1234", "1234", "TLS", syntheticSDP + "v=0\r\n"},
		{"no SDP", "1234", "1234", "TLS", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if policy.Admit(syntheticInvite(t, tc.uri, tc.to, tc.transport, tc.body)) != Reject {
				t.Fatal("untrusted office SIP/SDP admitted")
			}
		})
	}
	if policy.Admit(syntheticInvite(t, "1234", "1234", "TLS", syntheticSDP)) != Admit {
		t.Fatal("invalid input consumed the only call slot")
	}
}

func TestOfficeAdmissionConstructorForbidsUnpinnedOrPrivateMedia(t *testing.T) {
	for _, tc := range []struct {
		extension, contact, media string
	}{
		{"12;3", "192.0.2.12", "203.0.113.8"},
		{"12345", "192.0.2.12", "203.0.113.8"},
		{"1234", "127.0.0.1", "203.0.113.8"},
		{"1234", "192.0.2.12", "10.47.11.94"},
		{"1234", "192.0.2.12", "127.0.0.1"},
	} {
		if _, ok := NewAdmission(tc.extension, tc.contact, []net.IP{net.ParseIP(tc.media)}); ok {
			t.Fatal("unreviewed office destination or media source accepted")
		}
	}
}
