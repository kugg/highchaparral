# M3: offline media acceptance and deployment gates

This module now has a mock-only PCMA media boundary for `cmd/local-ari-lab`.
The Diago SIP dialog owns its own RTP socket and reads only the admitted
loopback PCMA offer. The ARI controller owns a separate IPv4-loopback UDP
socket and packetizes new RTP with independent SSRC, sequence and timestamp.
Only one 160-byte encoded audio frame and a locally allocated call ID cross
the bounded four-frame queues. An old call ID, unsupported payload type,
malformed datagram, wrong source/port, replay or implausible sequence jump
is dropped without relaying raw RTP metadata or logging a packet. Neither
the mock nor this command opens a public listener.

Run from `webrtc/gateway/voip-gateway/` without opening a port:

```sh
go test -count=1 ./...
go test -race -count=1 ./...
go test -fuzz='^FuzzOwnedPCMAReturnPacket$' -fuzztime=3s -parallel=2 ./internal/asterisk
go vet ./...
go mod verify
```

`internal/asterisk` tests use an authenticated loopback ARI HTTP/WebSocket
mock, a separate mock Asterisk UDP RTP socket and a real local Diago SIP
peer. They check a matched synthetic frame in **both directions**, a fresh
RTP identifier, fixed-PCMA and source checks, no false return on a silent
peer, replay/sequence rejection, cleanup on BYE and cancellation, failed
ARI DELETE reporting, WebSocket Ping/Pong and bounded upgrade/events. The
disposable `cmd/local-ari-lab` process is exercised end-to-end against
those mocks. A seeded, bounded RTP fuzz target checks malformed/untrusted
packets cannot panic, bypass the source-port guard or be replayed. A
previously timing-sensitive M2 event-buffer test now waits
for the queued Answered transition before a deliberately fast BYE without
draining the queue; it still tests admission failure with four events.

## What must pass before production

1. **Real Asterisk in isolated guest: PASSED synthetic media.** Historic
   originate-first ARI Local never joined the bridge despite 204, so
   five bounded attempts returned no RTP; old evidence is retained.
   Create the Down Local channel in Stasis, join both locally owned IDs,
   verify membership, dial and verify again. One separately pinned
   `asterisk-bridge-holding` IPK was added only to the guest; its
   owner-only load config survived a clean guest poweroff and restart.
   Direct PCMA Echo and a guest-local SIP→Go→real Asterisk→Go→SIP
   synthetic round-trip passed before and after that reboot. This does
   not prove Eventphone RTP, ATA hardware or browser WebRTC.
2. **SIP transaction cleanup:** Pinned Diago still has no reviewed
   cancellable in-process 200/ACK wait; the local executable exits on its
   ACK deadline. Verify an embedding/production process does not retain a
   stuck slot or goroutine after a missing ACK.
3. **Deployment-specific trust and codec:** Validate the real provider's
   authenticated registration, certificate, connection behavior, SDP,
   media source policy and codec before changing loopback-only bindings.
   No provider port or registration was available for these mock tests;
   TLS to a SIP server does not validate/encrypt RTP. Reproduce the
   Asterisk-only DTLS-enabled OpenSSL build before asserting WebRTC parity.
4. **Failed cleanup:** A mock ARI DELETE failure is surfaced, but real
   orphan discovery/recovery after ambiguous ARI delivery needs its own
   reviewed, non-replayable operational stage. Do not automatically
   redial, replay media, or treat a mock pass as live delivery.

Keep tests, guest deployment and live verification separate. This is a
research lab module; these mocks are not production deployment authority.
