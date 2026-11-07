# voip-gateway (`vgw`): provider-neutral gateway source

The maintained module/service identity is **voip-gateway**, abbreviated
`vgw`. Current `cmd/gateway` is still an isolated loopback-only prototype;
new `cmd/vgw` has default DRY RUN, fixed service-path
`--check-config`, and bounded `--serve` that can establish/refresh
**only SIP/TLS REGISTER** to a configured upstream host/port using
normal CA/hostname and exact DER-leaf pin checks. A local synthetic
TLS/digest registrar test exercises it. No INVITE, inbound answer,
media, Contact policy or ambiguous BYE recovery is wired into this
entry point; it is not a full call-capable APU release.
`cmd/local-ari-lab` and its `eventphone-gateway-lab` Stasis context are
historical **twin-only** fixtures whose running guest binary/config is
unchanged. The Eventphone-specific `cmd/provider-one-shot` and
`cmd/provider-preflight` remain attended, one-use historical tests,
**not** the general long-running upstream connector. Never repeat
their old attended call stage during renaming.

The future provider-neutral service config schema is in
`internal/serviceconfig/` and twin `deploy/ansible/`: fixed
`/etc/voip-gateway/config`, package-managed vgw group, local ARI and
provider credentials, validated upstream host/port/TLS name and a
SHA256 DER-leaf cert thumbprint layered on normal CA+hostname checks.
The new registration-only `cmd/vgw` parses this config; the full
provider call bridge and production procd/Ansible apply are not yet
implemented. Do not deploy the M0 prototype, register-only command
or provider-one-shot as an APU gateway service.

## Historical development milestones

This module is the M0 **local** library proof from
`../eventphone_go_gateway_local_plan.md`. It does not connect to Eventphone,
Asterisk or phones. It uses Diago for SIP dialogs, SDP, RTP audio echo and BYE;
sipgo provides the user agent and a separate test SIP client. There is no
custom SIP parser or transaction state machine in this module.

From this directory:

```sh
go run ./cmd/gateway -port 5070
```

The service listens on `127.0.0.1:5070/udp` and advertises only G.711
PCMA/8000. Any negotiated RTP uses the loopback interface. The process serves
until interrupted; `-port` can select a different *loopback* UDP port. The
service is for development only; M1 local mock registration is separate, and
M2–M6 policy, admission, media validation, ARI and real-provider compatibility
have not been tested.
The initial offer must contain one loopback IPv4 media address and one PCMA
audio stream; malformed or non-loopback initial offers are rejected. This
does not enforce a policy on later in-dialog re-INVITEs: use only with trusted
local test clients until those are rejected in M2.

Run the separate library-backed SIP client transcript (`go test -v`):

```sh
go test ./...
go test -v ./internal/loopback -run '^TestInviteAnswerBye$' -count=1
go list -m all
```

The test binds two local SIP user agents, sends an INVITE with a Diago-generated
SDP offer, observes a 200 OK and ACK, then sends BYE and checks its response.
It does not assert that audio echo or Eventphone interoperability works.

M0 local transcript (2026-10-12, `go test -v ./internal/loopback
-run '^TestInviteAnswerBye$' -count=1`):

```text
=== RUN   TestInviteAnswerBye
    service_test.go:68: PASS: loopback INVITE -> 200 OK -> ACK -> BYE
--- PASS: TestInviteAnswerBye
PASS
```

## M1: local mock registration

`internal/registration.Run` is a separate, **local-only** outbound TLS
registration adapter. It uses Diago's `RegisterTransaction.Register`,
`Qualify` and `Unregister`; it never starts a new listening port. Its fixed
network destination is `127.0.0.1` with an explicitly provided port, CA
pool and TLS server name. It has no CLI for real provider credentials.
The in-memory test registrar uses a synthetic credential and a certificate
generated for `localhost` during the test. Run:

```sh
go test -v ./internal/registration -count=1
go test -race ./...
```

The tests exercise 401 digest challenge, refresh, bounded 503 retries,
TLS-connection drop/reconnect, one shutdown unregister, bad credential,
wrong hostname, untrusted/expired certificate, and TLS 1.1 rejection.
See `docs/m1-local-registration.md` for limitations; no real Eventphone
registration or invitation routing is attempted **by this M1 adapter**.
Separate, attended `cmd/provider-preflight`/`cmd/provider-one-shot`
research tested a dedicated account from a host without changing the
gateway: REGISTER succeeded, one call returned 404, a separate answered
game call returned PCMA, but BYE was ambiguous. See
`docs/ports-and-release-gates.md`; do not treat this as provider-gateway
integration or a production deployment pass.

## M2: inbound call-control mock

`cmd/local-inbound` and `internal/calls` run an independent IPv4-loopback
UDP SIP listener with one mapped destination and at most one concurrent
call. `go test -v ./internal/calls -count=1` exercises INVITE, 100/180,
ACK, CANCEL, BYE, busy/wrong-destination rejection, rejected re-INVITE/
REFER/INFO/UPDATE, and answer/call timeouts against a second library peer.
Standalone M2 forwards no media to Asterisk. See `docs/m2-local-calls.md` for the
delivery and configurable fail-closed no-ACK deadline. `docs/tls-trust.md` distinguishes a future
registrar TLS trust/pin decision from SRTP media authentication.

## M3/M4 lab: independently terminated media and Asterisk ARI control

`internal/asterisk` connects only to an explicit `http://127.0.0.1:<port>`
ARI lab. It owns an idempotently cleaned mixing bridge, fixed
`Local/echo@eventphone-gateway-lab/n` target and one `alaw` External Media
channel. It reads Asterisk's actual `UNICASTRTP_LOCAL_ADDRESS` and
`UNICASTRTP_LOCAL_PORT` instead of guessing an RTP port. The event adapter
consumes M2's opaque call ID and fixed destination only; no SIP header,
caller-provided route or raw SDP reaches ARI. For the opt-in loopback lab,
the SIP dialog and the separate Asterisk socket exchange fixed-size PCMA
frames through bounded queues; each outgoing RTP leg has its own identifiers.
The local SIP→mock-ARI/media test and disposable `cmd/local-ari-lab` process
test prove two-way **mock** RTP, source/codec rejection and owned teardown.
The separate isolated OpenWrt twin then verified the same synthetic path
through real Asterisk before and after a clean reboot. This does not assert
provider or physical-device interoperability.
The lab runner reads synthetic/private
ARI test credentials from environment only and refuses non-loopback ARI.

```sh
go test -race -count=1 ./...
go build -o /dev/null ./cmd/local-ari-lab
```

The parent `../..` Asterisk draft directory has isolated
`*.gateway-lab.example` configuration and a testbench checklist. In the
isolated OpenWrt twin, real Asterisk control and synthetic PCMA audio
passed before/after clean reboot with an explicitly pinned holding-bridge
module. Provider registration/media and no-ACK/ARI orphan cleanup remain
separate production gates. See `docs/m3-media-mock-gate.md` and
`docs/m4-ari-lab.md`.

## Co-location plan (no APU deployment)

The current binary is a loopback-only lab, not a provider-facing APU
service. A sanitized read-only APU versus twin inventory found live
WebRTC/PJSIP/`chan_sip` on the APU but ARI/ExternalMedia/holding missing
even as module files. The isolated twin has the inverse enabled service
set: ARI and synthetic Go↔Asterisk audio without the deployed WSS/browser
site or ATA dialplan. Component-repo ownership, guest convergence checks,
explicit package/restart/rollback gates and a future pinned Ansible
controller are described in
`../../../docs/apu-gateway-colocation-plan.md`. Nothing was installed on
the APU for that review.
