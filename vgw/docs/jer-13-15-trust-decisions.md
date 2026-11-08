# JER-13/14/15: transport and browser trust evidence

## JER-15 — Eventphone authenticated SRTP/key negotiation

**Unresolved.** The development-account one-use vgw test proved a
CA/hostname-verified SIP/TLS REGISTER and confirmed Unregister. Earlier
separate provider tests returned PCMA RTP under the client's ordinary
RTP/AVP offer; that is **not** evidence of authenticated SRTP. No
Eventphone SDES `a=crypto`, DTLS-SRTP fingerprint/setup, SRTP profile,
certificate-binding policy or authenticated media result has been
verified. The browser's Asterisk DTLS-SRTP leg says nothing about the
Eventphone leg. The current office admission fixture permits only
provider-free RTP/AVP 8 for a synthetic test; it cannot choose a
production media-security profile. A later provider-free fixture also
echoed one synthetic PCMA RTP frame on loopback; that adds no SRTP or
real-provider capability evidence. Obtain reviewed provider capability
evidence and verify the exact offer/answer, negotiated keys and media
peer before selecting SDES, DTLS-SRTP or another scheme. Do not infer
support from SIP/TLS, or silently downgrade if authenticated media is a
requirement. Source: `docs/tls-trust.md`,
`deploy/ansible/OFFICE-EPVPN-DESIGN.md`, and the sanitized provider
one-shot and office test results.

## JER-14 — browser principal for BYOK reservations

**No separate authenticated browser login/session is established by the
current browser path.** The APU guest PJSIP identity has no per-user
password and LAN/WireGuard are shared. The reviewed same-origin HTTPS
CGI→owner-only Unix socket checks Host/Origin, size and request shape;
Go binds a short-lived nonce, destination and ARI channel readback to
the provider credential entered per call. These prevent arbitrary
unreserved provider calls under the stated BYOK policy, but origin,
`X-VGW-Client`, a nonce, WireGuard membership and a SIP guest channel
alone do **not** identify an authenticated human/browser session.
If reservations need a trusted browser identity beyond each caller's
Eventphone Digest credential, use a server-side authenticated HTTPS
session or a separately authenticated reverse proxy principal, bound
server-side to the one-use nonce/target with expiry. Reject client-
supplied `X-Forwarded-*` identity unless the trusted proxy first strips
it and supplies its own authenticated assertion. No such principal is
verified as deployed here. This browser BYOK question is independent
of Noll's dedicated SPA112/office extension. Source:
`deploy/ansible/SECURITY-VGW-BROWSER-INBOUND.md`,
`deploy/ansible/SECURITY-VGW-SOFTPHONE.md`,
`deploy/ansible/VGW-WEBRTC-EVENTPHONE-NEXT.md`.

## JER-13 — authenticated ARI TLS/WSS or local boundary

**Capability differs by target.** On the live OpenWrt APU, the
installed ARI account returned authenticated 200/empty channels and
wrong-password 401 over numeric loopback HTTP and certificate-pinned
HTTPS:8089. A WebRTC WSS listener shares that HTTPS binding; a
separately authenticated **ARI WebSocket/WSS event subscription** was
not established by those REST results. The current Go ARI client
deliberately pins HTTP to IPv4 `127.0.0.1`, checks Basic credentials and
refuses arbitrary host/redirect. The new local Debian/x86 twin proved
that exact ARI subscription on isolated loopback in two containers,
not authenticated ARI TLS on Noll. No Noll ARI HTTPS/WSS certificate,
credential ownership, client pin or exposure has been verified.

For colocated Noll containers, keep ARI on a narrowly authenticated
loopback/private local socket or reviewed local proxy with owner-only
credentials until the container network backend and its trust policy
are approved. Direct Noll HTTPS/WSS is an alternative **only after**
reviewed certificate/CA or explicit leaf pin, Basic-auth negative
control, WSS upgrade/auth and renewal/rollback evidence. Shared WAN
or WireGuard reachability is not ARI authorization. Source:
`deploy/ansible/APU-ARI-BOUNDARY.md`,
`deploy/ansible/SECURITY-VGW-BROWSER-INBOUND.md`,
`internal/asterisk/ari.go` and Noll `local-ari-twin.yml` results.
