# M4 preparation: local-only ARI + External Media

The Asterisk adapter is a narrow **lab** controller, not a SIP proxy.
`internal/asterisk.Client` only accepts an explicit loopback HTTP base URL,
fixed ARI app `eventphone-gateway-lab`, fixed target
`Local/echo@eventphone-gateway-lab`, `alaw` RTP and a gateway-owned IPv4
loopback UDP socket (not a caller-supplied media port). Its HTTP client has
a per-request deadline, never follows redirects, ignores environment
proxies and sends Basic credentials only to the numeric IPv4 loopback
endpoint. `cmd/local-ari-lab` reads the lab ARI username/password from
`GATEWAY_LAB_ARI_USER`/`GATEWAY_LAB_ARI_PASSWORD`, never flags or logs;
environment variables are still visible to privileged local users.

The command establishes a Basic-authenticated, fixed-app ARI events
WebSocket **before** opening its SIP listener. Its loopback-pinned client
validates the WebSocket upgrade/accept proof, discards a bounded volume of
event bytes without logging them, and fails closed without automatically
reconnecting if the subscription disappears. Asterisk otherwise may remove
an External Media channel before its local RTP address can be read.

Call flow verified against a strict loopback mock and an isolated OpenWrt
24.10.8 twin with real Asterisk 20.8.1 for synthetic control and media:

1. An M2 SIP INVITE is answered and ACKed locally, producing a random
   opaque `Answered` event, not an external SIP Call-ID.
2. Create a mixing bridge with a fresh independent cryptographically random
   resource ID, not the SIP Call-ID or event ID.
3. Create an ARI External Media channel using the fixed application, `alaw`,
   `rtp/udp`, and `external_host=127.0.0.1:<port-of-held-media-socket>`.
4. Read `UNICASTRTP_LOCAL_ADDRESS` and `UNICASTRTP_LOCAL_PORT` from the
   *created* External Media channel. Reject a non-loopback address, missing
   value, invalid port or mismatched channel ID.
5. Add media to bridge; create the fixed
   `Local/echo@eventphone-gateway-lab/n` target Down in Stasis, join it
   and read back both owned bridge members **before dialing**. Dial once
   and read back membership again. Only a 422 response for a not-yet-
   Stasis channel is retried under a bounded deadline; ambiguous create
   or dial delivery is never replayed.
6. `Ended` or an error deletes only the locally allocated channel/bridge
   IDs in reverse order. A lost create response still triggers bounded
   best-effort cleanup of those owned IDs; no external ID is deleted.

The opt-in lab now validates and forwards only fixed 160-byte PCMA frames
between two independent RTP sessions. Mock tests prove both directions,
separate RTP identifiers and rejection/teardown behavior. This does not
prove provider audio; real guest synthetic Echo passes separately.
See `m3-media-mock-gate.md`.
In the restricted guest, a subscribed direct Go probe created/removed real
ARI bridge, External Media and fixed Local target. A single synthetic SIP
INVITE/ACK/BYE through the guest-local Go gateway produced a real ARI bridge;
after BYE and gateway shutdown Asterisk reported zero channels/bridges.
The older originate-first implementation established **control only**:
its Local channel never entered the bridge, so RTP could not reach Echo.
With fixed create→bridge→dial and the exact holding IPK, direct RTP and
full synthetic SIP audio pass before/after reboot. Mock tests cover bounded ARI
WebSocket Ping/Pong and two-way RTP; automatic reconnection is intentionally
absent. Real **provider** RTP remains unverified. A mock-driven test
launches the real `cmd/local-ari-lab` binary, completes a separate
Diago SIP INVITE/ACK/BYE, verifies a synthetic frame both ways and checks
owned bridge teardown. The parent
`webrtc/asterisk/README.gateway-lab.md` documents separate, disabled-by-
default config examples. Do not apply them to the deployed WSS/ATA PBX.

**Historical negative prerequisite:** `cmd/ari-media-probe` is a one-shot
guest-only diagnostic using the same ARI target but no SIP peer. It sends
at most 75 synthetic 20 ms PCMA packets from an owned loopback socket and
only accepts a matching reply from Asterisk's assigned loopback port. In
the guest, the final sanitized attempt found an ARI bridge, three Up
channels and an active Echo dialplan application. Kernel UDP counters
showed 75 received, 75 sent, no missing-port or input errors, but the
probe socket received **no reply** because the Local target was absent
from its mixing bridge. Those separately versioned negative attempts
and cleanup evidence remain in the private twin. Later control and media
attempts passed under the corrected source and guest package/config.
Do not replay old attempts or infer provider audio from guest evidence.

From this module:

```sh
go test -v ./internal/asterisk -count=1
go test -race ./internal/asterisk ./internal/calls
go build -o /dev/null ./cmd/local-ari-lab
```
