package office

// Admission is the fail-closed ingress boundary for a *future* persistent
// office INVITE service. It never logs or reflects SIP/SDP fields, cannot
// establish a call, and does not authorize a public listener. Its owner
// must attach it only to the CA/hostname-verified REGISTER TLS flow and
// fsync a call journal before turning an admitted INVITE into media/ARI.

import (
	"bytes"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/emiago/sipgo/sip"
)

type Decision uint8

const (
	Reject Decision = iota
	Busy
	Admit
)

type Admission struct {
	extension string
	contact   string
	media     []net.IP
	active    atomic.Bool
	ready     atomic.Bool
	// Synthetic provider-free tests alone may use loopback on both ends.
	allowLoopback bool
}

var fourDigits = regexp.MustCompile(`^[0-9]{4}$`)

func NewAdmission(extension, contactIPv4 string, mediaIPs []net.IP) (*Admission, bool) {
	return newAdmission(extension, contactIPv4, mediaIPs, false)
}

func newAdmission(extension, contactIPv4 string, mediaIPs []net.IP, synthetic bool) (*Admission, bool) {
	contact := net.ParseIP(contactIPv4)
	if !fourDigits.MatchString(extension) || contact == nil || contact.To4() == nil ||
		contact.IsUnspecified() || contact.IsMulticast() || (!synthetic && contact.IsLoopback()) ||
		len(mediaIPs) == 0 || len(mediaIPs) > 4 {
		return nil, false
	}
	result := &Admission{extension: extension, contact: contact.To4().String(), allowLoopback: synthetic}
	for _, address := range mediaIPs {
		if address == nil || address.To4() == nil || address.IsUnspecified() || address.IsMulticast() ||
			(!synthetic && (address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast())) {
			return nil, false
		}
		result.media = append(result.media, append(net.IP(nil), address.To4()...))
	}
	return result, true
}

// Registered is called only after a successful REGISTER response, never
// merely after writing a request or receiving a Digest challenge.
func (a *Admission) Registered() {
	if a != nil {
		a.ready.Store(true)
	}
}

func (a *Admission) LostRegistration() {
	if a != nil {
		a.ready.Store(false)
	}
}

// Finish releases the slot ONLY after a definite dialog teardown and
// owned media/ARI cleanup. false leaves it blocked pending manual review.
// A process restart also requires an independent durable journal check.
func (a *Admission) Finish(settled bool) bool {
	return a != nil && settled && a.active.CompareAndSwap(true, false)
}

func (a *Admission) Admit(req *sip.Request) Decision {
	if a == nil || req == nil || !a.ready.Load() {
		return Reject
	}
	to := req.To()
	contentType := req.ContentType()
	if req.Method != sip.INVITE || !strings.EqualFold(req.Transport(), "tls") ||
		(req.Recipient.Scheme != "sip" && req.Recipient.Scheme != "sips") ||
		req.Recipient.User != a.extension || req.Recipient.Host != a.contact ||
		to == nil || to.Address.User != a.extension ||
		contentType == nil || contentType.Value() != "application/sdp" ||
		!a.validSDP(req.Body()) {
		return Reject
	}
	if !a.active.CompareAndSwap(false, true) {
		return Busy
	}
	return Admit
}

func (a *Admission) validSDP(raw []byte) bool {
	if len(raw) < 40 || len(raw) > 2048 || !bytes.HasSuffix(raw, []byte("\r\n")) ||
		bytes.IndexByte(raw, 0) >= 0 {
		return false
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\r\n"), "\r\n")
	if len(lines) < 6 || len(lines) > 32 {
		return false
	}
	var v, origin, session, timing, connection, media, rtpmap int
	for index, line := range lines {
		if len(line) < 3 || len(line) > 160 || strings.ContainsAny(line, "\r\n\x00") {
			return false
		}
		for i := 0; i < len(line); i++ {
			if line[i] < 0x20 || line[i] > 0x7e {
				return false
			}
		}
		switch {
		case line == "v=0":
			if index != 0 {
				return false
			}
			v++
		case strings.HasPrefix(line, "o="):
			// The origin is never used as a media source or logged.
			if index != 1 {
				return false
			}
			origin++
		case strings.HasPrefix(line, "s="):
			if index != 2 {
				return false
			}
			session++
		case line == "t=0 0":
			if index != 4 {
				return false
			}
			timing++
		case strings.HasPrefix(line, "c="):
			if index != 3 {
				return false
			}
			fields := strings.Fields(strings.TrimPrefix(line, "c="))
			if len(fields) != 3 || fields[0] != "IN" || fields[1] != "IP4" {
				return false
			}
			ip := net.ParseIP(fields[2])
			if ip == nil || ip.To4() == nil {
				return false
			}
			allowed := false
			for _, expected := range a.media {
				allowed = allowed || ip.Equal(expected)
			}
			if !allowed {
				return false
			}
			connection++
		case strings.HasPrefix(line, "m="):
			if index != 5 {
				return false
			}
			fields := strings.Fields(strings.TrimPrefix(line, "m="))
			if len(fields) != 4 || fields[0] != "audio" || fields[2] != "RTP/AVP" || fields[3] != "8" {
				return false
			}
			port, err := strconv.Atoi(fields[1])
			if err != nil || port < 1024 || port > 65535 || strconv.Itoa(port) != fields[1] {
				return false
			}
			media++
		case line == "a=rtpmap:8 PCMA/8000":
			if index < 6 {
				return false
			}
			rtpmap++
		case line == "a=sendrecv" || line == "a=ptime:20":
			if index < 6 {
				return false
			}
		default:
			return false
		}
	}
	return v == 1 && origin == 1 && session == 1 && timing == 1 &&
		connection == 1 && media == 1 && rtpmap <= 1
}
