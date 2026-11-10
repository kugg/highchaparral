# Ports and gates: isolated twin versus later provider test

## Already used in the local twin (no WAN exposure)

| Listener | Protocol/address | Purpose |
|---|---|---|
| Go lab SIP | guest `127.0.0.1:5080/udp` | One synthetic SIP caller inside QEMU |
| Guest Asterisk ARI | guest `127.0.0.1:8088/tcp` | Basic-authenticated local REST/WebSocket |
| Asterisk RTP pool | guest `18000–18032/udp` | Guest-only, configured in its private rtp.conf |
| Go/Asterisk ExternalMedia | ephemeral guest `127.0.0.1/udp` | Separately bound per call; assigned ARI port read back |
| QEMU SSH forward | host `127.0.0.1:2234/tcp` | Existing pinned guest administration only |

The guest is IPv4-only QEMU user networking on 10.88.77.0/24. There is
**no host WAN-forwarded SIP, ARI or RTP port**; no host route, interface,
DNS, firewall or VPN change is needed for guest control, two-way synthetic
PCMA audio, or the clean-reboot repeat. The private home-directory ARI
configuration and SSH identity do not belong in this public repository.

## Later Eventphone/production gate (not configured by this lab)

- An **attended standalone Mac one-shot client**, separate from the
  gateway, verified outbound TLS/CA/hostname and authenticated REGISTER
  to `hg.eventphone.de:5061`. An initial operator-approved in-network
  INVITE returned 404; one separately authorized game call was answered
  and return PCMA arrived from the SDP-advertised source. Its BYE was
  **unconfirmed**, despite Unregister succeeding. Both owner-only
  one-use stages remain spent; that game's teardown is still ambiguous.
  A distinct, subsequently approved automated Network Announcement
  one-shot on 2026-10-25 returned fixed `pass` evidence: REGISTER,
  answered INVITE, PCMA from the SDP source, library BYE and Unregister.
  Its independent owner-only stage is also spent and cannot be replayed.
  No call audio was captured or transcribed. See
  [the final evidence boundaries](eventphone-call-evidence.md).
- Provider RTP ports, inbound SIP connection reuse, NAT traversal and
  source addresses for a **deployed gateway** remain untested. One
  standalone client received RTP, but a fixed host/WAN UDP range is
  still not established here.
  Merely forwarding 18000–18032 from the internet would expose the
  wrong system: those are **guest Asterisk lab-only** RTP ports.
- The current Go lab listener/ARI adapter explicitly accept numeric
  loopback addresses and cannot be made into a trusted provider-facing
  service by opening a firewall port. Office WAN is shared; WireGuard is
  shared fleet administration, not an application trust boundary.
- Remaining release controls: verified real-provider TLS/auth and
  codec/media-source policy **through the integrated gateway**, a clean
  integrated BYE (the old game BYE remains ambiguous despite the separate
  announcement success), in-process missing-ACK cancellation, owned
  ARI orphan recovery on failed DELETE, and separate Asterisk/WebRTC
  DTLS-enabled OpenSSL parity where browser service is required. Do not
  place credentials in logs, code, mock fixtures or external reviews.

Any later port change needs separate review and authorization under
`/Users/user/devel/ata/AGENTS.md` before touching host or APU networking.
Synthetic guest pass is useful evidence, not production deployment approval.
