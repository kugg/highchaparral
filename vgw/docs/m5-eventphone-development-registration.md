# One-use Eventphone development-account registration (2026-11-07)

The operator authorized testing vgw with the ignored ATA-workspace
`webrtc/gateway/eventphone_creds` file. It is an owner-0600 **development**
account for `hg.eventphone.de`, not Noll's dedicated office EPVPN account
or an input to a Docker image. The file was parsed in memory; account,
password, SIP headers and private paths were not printed or exported.

The new `cmd/vgw` development-only flags are `--test-register-check`
(offline shape check), `--test-register-status` (fixed-category local
stage readback), and `--test-register-once` (explicit, one-use outbound
IPv4/verified SIP/TLS REGISTER followed by one bounded Unregister).
Default `vgw` remains no-network dry run. The live mode first fsyncs
`state/vgw-test-register-once-v1/attempt.json` in ignored, owner-0700
state; a second invocation cannot reuse the stage. It sends **no INVITE,
RTP or call** and does not retry at application level. Unsolicited SIP
requests on this test client get a fixed 503 response rather than an
office/ARI handler. Errors and the owner-0600 result contain only
allowlisted categories and booleans. Protocol-level Digest challenge
handling is delegated to the pinned Diago/sipgo registration library.

Evidence:

* Credential-free `cmd/provider-preflight/probe.py --tls-only`: fixed
  `tls-verified`, TLSv1.3; no SIP request or credential.
* `go run ./cmd/vgw --test-register-check`: shape accepted, no network.
  `--test-register-status` initially returned `NO_STAGE`.
* `go test -race ./...`, `go vet ./...`, an amd64/cgo-disabled vgw build
  and `gofmt -d` all passed after fixing an initial test compile error
  (channel type) and a temporary test-stage parent mode failure.
  Synthetic registrar tests proved one 401/Digest challenge, accepted
  REGISTER, one Unregister and no refresh; a 503 response sent no
  automatic application retry or Unregister.
* ONE explicit `go run ./cmd/vgw --test-register-once` returned
  `VGW_TEST_REGISTER_REGISTERED_AND_UNREGISTERED`. Independent readback
  returned the same category. Both private files were mode0600 inside
  owner0700 stage. No new provider call, BYE or RTP was sent.

This is a confirmed development-account REGISTER/Unregister, **not**
proof of a Digest challenge on the live provider, an office-alias
extension, an inbound INVITE, media, a clean BYE on the earlier
ambiguous game call, a call-capable gateway, or a SPA112 handset.
Keep the one-use result immutable; do not re-run the flag, automatically
redial the historical call or rebuild/deploy the old
`noll-vgw:register-only-dev-v1` as if it contained the new source. The
next source gate is a bounded, persistent office INVITE/media/teardown
mode with synthetic tests and a separate owner-entered office identity.

## Provider-free ingress boundary added after the live test

`internal/office/admission.go` now defines an **inert** office-only
INVITE admission policy. It requires a successful registration signal,
one exact four-digit Request-URI and To destination, TLS transport,
the expected local **Request-URI host** IPv4 and an exact allowlist of media-source
IPv4 addresses. SDP is bounded to 2048 bytes, strict printable CRLF
lines, exactly one ordered PCMA/8000 RTP/AVP 8 audio section and no
unreviewed attribute. A second call is busy; an unconfirmed cleanup
leaves the slot blocked rather than auto-redialing. No caller-controlled
header, origin, SDP or error is logged or passed to a template, dialplan
or SQL query. The existing provider-free same-registered-TLS-flow
test now passes an exact synthetic SDP/INVITE through that policy and
dispatches a `diago.DialogServerSession` *without* opening a listener.
The synthetic handler sends 486; the mock provider sends its matching
ACK, which pinned sipgo waits for before `Respond(486)` returns. A
first revision timed out because that ACK was absent; the corrected
fixture passed five targeted race runs and full Go race/vet/amd64
source checks. **This rejected-call fixture does not answer, forward media,
establish an ARI bridge or implement an answered call's teardown.** It has not validated the SIP
Contact header or established that the provider uses that exact
Request-URI host. The in-memory slot also needs
a fsynced per-call journal before a production service can activate it.

## Synthetic answered-dialog and PCMA capability (provider-free)

`internal/office/dialog_flow_test.go` adds a second **loopback-only**
fixture on the same verified, client-initiated TLS REGISTER flow. After
admission it exercises Diago's dialog handler with a synthetic 200/SDP,
matching ACK, one generated 160-byte PCMA/8000 silence RTP frame,
returned payload-type-8 RTP echo from the negotiated local port,
remote BYE with 200, and the media handler exiting after teardown.
Five targeted race repetitions, the full Go race suite, vet, gofmt and
Linux/amd64 vgw build passed. The fake media uses RTP/AVP 8 on 127.0.0.1;
there is **no** Eventphone packet, authenticated SRTP, ARI bridge, real
telephone, real speech or deployed office daemon. This test does not
prove the pinned library rejects spoofed real RTP source/headers or
implements a durable call journal. See the separate JER-15 media
profile gate before choosing production media negotiation.
