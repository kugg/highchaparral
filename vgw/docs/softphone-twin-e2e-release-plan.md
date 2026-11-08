# VGW softphone release test plan: isolated twin end to end

Use this plan for **each candidate revision**, not as a claim that an E2E
run has already passed. It covers the Asterisk-backed browser → VGW
`--serve-byok` → synthetic SIP/TLS provider call. `--serve` is
REGISTER-only. It never authorizes a live Eventphone call, deployment
to an office APU, host network changes, or reuse of a prior attempt.

## Candidate and decision record

Record, in a private redacted result for this release: candidate Git
SHA, source tree/dirty status, Go and Node versions, generated site and
guest binary SHA256s, twin image/package/DTLS fixture pins, test/fixture
revision, test window, owned stage ID, actual commands and their exit
codes. Mark each item **PASS, FAIL or BLOCKED**, with its evidence type:

| Gate | Evidence needed for PASS |
|---|---|
| A. Source and offline tests | Exact candidate, full Go suite and browser/twin tests; failures named, not hidden. |
| B. Isolated guest deployment | Reviewed owned Asterisk, WebRTC/DTLS, HTTPS/CGI, VGW and synthetic-provider fixtures; preflight and rollback stage. |
| C. One synthetic browser-to-provider call | Browser REGISTER and BYOK reservation, Asterisk nonce/channel readback, one synthetic SIP/TLS Digest call, connected browser DTLS/ICE and RTP in both directions, confirmed cleanup. |
| D. Negative controls and rollback | Cross-origin/forged SIP/ARI, busy/replay and injected error refusals; no second provider INVITE; owned stop and restored owned files. |
| E. Production verification | Separate explicitly authorized attended evidence; **not** supplied by any twin run. |

Do not call a release **E2E-verified** unless A–D pass for the *same*
candidate and C has no stubbed provider or browser leg. A scoped test
pass is not an A pass when the full suite fails. Keep an explicit
BLOCKED status and the original failure evidence rather than implying
a mock proved hardware, Eventphone, two-way intelligible speech or
production readiness. A new release requires new pins and an independent
one-use attempt; never recycle an ambiguous stage.

## A. Repeatable source-only checks (can run now)

Read both repositories' AGENTS.md first and inspect Git status/diff.
Run these commands **from the indicated working directory**, using the
exact candidate source; no production credentials, device or VM needed.

From this Go module (`vgw/`):

```sh
git status --short
git rev-parse HEAD
go version
go mod verify
go vet ./...
go run ./cmd/literalcheck --check
go test -race -count=1 -timeout=120s ./...
```

The full suite is the required source gate. The template at
`deploy/ansible/templates/voip-gateway.config.j2` is bundled in this
module and `internal/serviceconfig.TestTwinAnsibleTemplateRendersTheProductionParserContract`
renders it with synthetic values. Require that test to PASS in a
standalone checkout and in `.github/workflows/vgw-standalone.yml`;
do not skip it. If a separate twin checkout uses
the owner-maintained Ansible template, compare the two reviewed
templates and resolve any differences before deploying a fixture.

From `vgw/softphone/` (Node 20+, installed Chrome for both browser cases):

```sh
node --version
npm ci --no-audit --no-fund
npm run build
npm test
```

Require five PASS and **zero skipped** (three policy and two intercepted
Chromium cases). The generated `site/vendor/sip.min.js` and node_modules
are ignored build inputs, not Git or a production credential store.
This page test stubs SIP and intercepts all network; it does not
REGISTER with Asterisk or place a call.

From the separate source-owner OpenWrt twin root (run its offline tests
only after reviewing its own AGENTS.md, status and user edits):

```sh
python3 -B test_twin.py
python3 -B deploy/ansible/test_apu_vgw_byok_cgi.py
python3 -B twin.py --status
```

The CGI test's existing constants describe an APU, not an approved
twin installation. Its socket tests use disposable synthetic peers.
From that twin's `browser-tests/` directory:

```sh
node --test softphone-dial.test.mjs softphone-ui.test.mjs media-evidence.test.mjs
```

These twin tests are separate source-owner fixtures; they do not
exercise the newly packaged public page in a real SIP/WSS call.

### Recorded baseline on 2026-11-08 (not a future release result)

- Tested source commit `776ec4e24e39d5d9310e02706c6b6cc0c0e21f77`
  with Go 1.27.1 on macOS arm64, Node v23.11.0 and npm 10.9.2.
  The source tree was clean before this documentation was added.
- At the **pre-fix public source commit** above, the full Go race
  suite **FAILED** only the absent parent Ansible template test; the
  suite with that one explicit exclusion passed. After adding the
  in-module template and updating its test path locally, the full
  unskipped Go race suite **PASSED** on the modified working tree.
  Record its eventual committed candidate SHA separately. `go vet ./...`,
  `go mod verify`, and literal policy `LITERAL_POLICY_PASS`.
- Public softphone `npm ci`, build, test: **5/5 PASS, zero skipped**.
- Twin `test_twin.py`: **26 PASS**; CGI contract: **4 PASS**; twin
  browser/media policy tests: **13 PASS, zero skipped**.
- Read-only twin status: **stopped**, guest not verified running,
  SSH provisioned, checkpoint `pre-colocated-dtls`. No guest boot,
  new listener, Asterisk call or provider traffic occurred for this
  baseline. E2E gates B–D are **BLOCKED / not run**.

## B. Prepare an isolated guest (not yet supplied by this repository)

The persistent twin is a separate user-owned repository; its current
state and uncommitted source must be inspected afresh. Before **each**
VM/container launch, take read-only IPv4/IPv6 `netstat -rn -f inet`,
`netstat -rn -f inet6`, `scutil --nwi` and Docker/VPN network snapshots;
compare the candidate subnet and all specific routes *numerically*,
not just default routes. Stop on overlap or ownership ambiguity.
Default twin is 10.88.77.0/24 with host-loopback SSH :2234; the
separate smoke profile is 10.88.79.0/24 with :2235. Use QEMU user-mode
`restrict=on`, IPv6 off and only owned loopback forwards. No host route,
interface, DNS, firewall or VPN edits; no bridge, tap, vmnet or
socket-link backend. Inspect `twin.py --status` and existing private
stage first; do not reset its persistent guest disk or overwrite other
agents' work. The existing old `epgateway-twin` Go service is an ARI
lab fixture, **not** the public candidate's BYOK service. Check guest
overlay reserve before staging a new nonroot service.

Review/stage new fixtures with default dry-run, explicit apply and
rollback, fsynced owner-only attempt records and bounded timeouts:

1. **Asterisk WebRTC admission.** The twin uses a `webrtc-lab` SIP
   endpoint, whereas `softphone/site/index.html` accepts only a
   numeric 2–6-digit SIP user and
   `internal/asterisk/browser_event.go` admits only a channel named
   `PJSIP/webrtc-lan-<hex>` in `from-webrtc` for `e-<2–5 digits>`.
   Add a synthetic authenticated endpoint and restricted `e-` →
   `Stasis(eventphone-vgw-browser,browser-demo)` context without
   changing ATA100/Echo999. Prove actual PJSIP endpoint selection,
   channel name, context, extension and readback of the fixed
   `X-VGW-Nonce` header. Merely naming an auth user `180` does not
   prove the resulting channel is `webrtc-lan`.
2. **Same-origin HTTPS and CGI.** Stage the built public page at a
   localhost-only HTTPS origin, plus owned CGI forwarding to VGW's
   private Unix socket. Browser BYOK refuses HTTP even on localhost.
   Pin a short-lived synthetic site/WSS certificate exactly as in the
   twin's `browser-tests/localhost-wss.test.mjs`; no browser-wide TLS
   bypass. The existing twin WSS SSH tunnel forwards host :28489 to
   guest :8089; the public page's default WSS URL is :8089, so supply
   a synthetic-only config for the owned forward. Review any extra
   loopback HTTPS forward and its PID/teardown record. The source-owner
   APU CGI has hardcoded office Host/UID and must **not** be reused
   unchanged as a twin CGI; use an exact synthetic Origin/Host,
   socket owner, size limit and no secret-bearing logs. Keep private
   keys, account values and generated bundle outside Git.
3. **VGW and synthetic provider.** Co-locate a build pinned to this
   release's source with Asterisk: its ARI and ExternalMedia endpoints
   are numeric guest loopback. Stage nonroot `--serve-byok` with
   owner-private BYOK config, runtime/state dirs and a one-use
   journal. `internal/provider/leg.go:89-96,205-210` intentionally
   refuses a loopback/mock hostname, loopback source and private RTP
   peer in production. A local mock cannot work by changing config
   alone. Design a **test-only**, non-production-buildable provider
   connector/allowLoopback seam with exact synthetic TLS/Digest/PCMA
   peer and explicit fixture ownership, while preserving production
   guards. Existing `Bridge.Connector` and same-package
   `internal/provider/leg_test.go` are starting points. Do not map
   the real provider hostname in host DNS, change host routes, or
   loosen the production allowlist. If the test can only inject a
   stub provider, label gate C **BLOCKED** for full provider E2E.

These fixtures and an integrated one-use runner **do not exist yet**;
this section is an implementation checklist, not runnable apply
instructions. Before any stage or test that might carry credentials,
review inbound log/audit/template/SQL/HTTP and SIP error-text sinks,
not just data sent to a provider.

## C. One end-to-end call, once fixtures exist

Record a new one-use attempt before dialing; require no active PBX
channel/bridge and no prior unresolved BYOK journal. The runner must
refuse a second INVITE, automatic retry or ambiguous-call replay.
Use **only** synthetic accounts and a synthetic numeric destination:

1. Load the real built page over exact-trust HTTPS in a disposable
   Chromium profile; verify a secure context, WSS registration and
   a connected peer. A test-only config may enable the Eventphone
   option only for this isolated fixture.
2. Submit one same-origin HTTPS `/cgi-bin/vgw` reservation; expect
   201, a fresh 32-hex nonce and no password in URL, SIP headers,
   browser storage or logs. The browser INVITE is `e-<digits>` with
   `X-VGW-Nonce`, **not** a provider password.
3. Verify authenticated ARI `StasisStart`, current channel GET and
   fresh nonce/extension readback BEFORE the synthetic SIP INVITE.
   Require exactly one Digest REGISTER and provider INVITE, one
   answer with PCMA, and both RTP directions through Asterisk's
   owned ExternalMedia and the *same* browser DTLS/ICE peer. Require
   increasing inbound and outbound audio RTP **packets and bytes**;
   merely opening WSS or seeing an absolute inbound counter fails.
4. Hang up once and classify SIP BYE, Unregister, owned ARI media/
   bridge teardown, zero Asterisk channels/bridges and durable
   journal/slot as settled. On any unknown cleanup outcome, retain
   the blocked attempt and investigate without redialing.

## D. Negative controls and recovery

Refuse forged Origin/Host/Fetch-Site, oversized or control-character
CGI input, wrong nonce, wrong `e-` extension, changed/foreign ARI
channel, concurrent reservation, repeated nonce and SIP/CGI error
text containing synthetic CRLF. Demonstrate zero extra synthetic
provider INVITEs and no untrusted response/secret reflected into DOM,
logs or audit. Test a deliberately ambiguous cleanup separately:
leave the slot blocked, preserve the staged result, and require a
reviewed manual recovery rather than retrying the original call.
Rollback stops only verified owned processes/forwards and restores
only owned files after inode/SHA and concurrent-modification checks.
Compare host IPv4/IPv6 route/NWI snapshots after shutdown; retain
the existing guest disk, stage and audit history.

## Release result

Publish a sanitized summary with candidate revision, fixture SHA,
checks and outcomes, explicit true/stubbed legs, two-direction RTP
evidence, cleanup and unresolved gates. Never publish credentials,
cert private keys, audio/prompt content or raw SIP/SDP/PCAP. No
synthetic pass proves live Eventphone media security, production
deployment or a physical phone. Keep release tests, installation,
and real-device/provider verification as separate decisions.
