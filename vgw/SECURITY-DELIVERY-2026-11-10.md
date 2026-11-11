# Synthetic regression and delivery-source review — 2026-11-10

Scope: this checkout's Asterisk ARI media readiness change, a new
source-only browser/Asterisk/VGW synthetic fixture, and artifact/QEMU/
Noll delivery gates. No host Docker network, QEMU VM, real Eventphone
registration, office device or Noll service was started in this review.

## Code and input boundaries

- `internal/asterisk/ari.go` retries only an owned ExternalMedia bridge
  add after HTTP 422, within the ARI timeout. It never retries a
  transport-ambiguous result, other status, caller SIP or provider call.
  Targeted positive/negative Go tests cover the bound.
- `cmd/regression-browser-ari/` is an explicitly synthetic, fixed-marker
  launcher of the already inventoried `cmd/ari-browser-probe/` caller;
  it never constructs another ARI client. That caller now requires
  exact HTTPS loopback and the owner-provisioned public certificate leaf
  pinned by normal TLS and SHA-256. Admission validates the current
  browser/nonce and an Asterisk-owned ARI bridge.
  Its provider-200 marker is **not** a provider SIP response. Post-close
  polling makes only bounded, read-only local ARI GETs for both channel
  and bridge lists; it rejects invalid/oversized/unknown responses and
  never retries BYE, DELETE, INVITE, audio or a provider transaction.
- `regression/browser_ari/runner.py` accepts only owner-pinned source,
  image IDs and fixed Docker names per new run ID. It fsyncs phase/owner
  before creating a `--internal` bridge and before sending one browser
  GO. Generated synthetic SIP/ARI secrets and short-lived TLS material
  remain in ignored owner-private state. No port is published and the
  temporary NET_ADMIN helper shares only the exact-owned Asterisk
  namespace; it is removed before SIP. Rollback refuses a foreign
  container or an unexpectedly attached bridge. During source review we
  found that the initial browser mount included the entire private stage
  (and synthetic ARI password). Before contributing, changed it to a
  distinct browser-only password/cert directory and a minimal six-field
  intent directory. Source and offline tests assert the intent never
  carries ARI/mock environment fields; no original private stage is
  bind-mounted into the browser container. The nonroot Go container
  mounts only a public synthetic ARI certificate, never its private key;
  it does not send Basic credentials until HTTPS peer verification.
- The browser test reports only fixed categories. It reads untrusted
  SIP/SDP in memory and never reflects it into a command, log, DOM
  template, SQL query or audit message. Go request/response and Docker
  inspection errors are likewise fixed-category only. Generated
  credentials, keys, audio and raw SIP/SDP are absent from source and
  external review material.
- `deploy/pipeline/release.py` hashes a **clean committed** candidate,
  binary, browser assets and source archive; it does not include an
  Eventphone credential. `qemu_stage.py` accepts only an owner-pinned
  private qcow2/SSH identity and QEMU user networking with restricted
  IPv4 and a loopback SSH forward. `promote.py` compares same-artifact
  QEMU evidence and **refuses** a synthetic-only promotion or any Noll
  apply while the production runtime/rollback contract is absent.

## Verification and unresolved gates

The full Go race suite initially failed only the reviewed literal-policy
inventory: a new synthetic command contributed four operational literals.
Its redacted inventory was reviewed, one historical-fixture allowance was
added, and the **full** Go race suite, vet and literal-policy check passed.
After current main introduced the five-caller ARI inventory and HTTPS
peer pin, reworked the synthetic fixture to reuse its existing inventoried
caller instead of altering or bypassing the security test. Reviewed the
new fixed HTTPS/certificate/response bounds in the redacted literal
inventory and updated only the relevant source-policy entries.
The offline Python profile/runner and artifact/QEMU/promotion tests passed,
and the existing five softphone tests passed with no skips. The nested
Linux-only guest-helper module cross-compiled and passed vet on macOS;
its runtime remains for an actual Linux guest/CI run.

This public candidate has **not** yet run the Docker browser E2E test:
the official image matching the current locked Playwright version is not locally available,
and a release artifact requires a committed, clean source tree. The
separate source-owner twin V26 test passed a *similar* local synthetic
call but is not evidence for these public candidate bytes. No suitable
pre-provisioned Debian QEMU qcow2, pinned guest SSH/image bundle or
Noll owner/NIC/provider-identity/rollback contract was supplied. Asterisk
image build dependencies from Debian apt also need a dated package lock
before claiming a byte-reproducible release. Full BYOK reservation,
Eventphone SIP/TLS/Digest, two-direction browser RTP and SPA112 are
still unverified. CI source tests and synthetic QEMU attestation must not
be promoted into a production voice claim.

Pre-PR diff threat-model review confirmed one **open, high-severity
release reproducibility gap**: `regression/browser_ari/Dockerfile.asterisk`
pins the Debian base digest and Asterisk/PJ upstream tarball hashes,
but `apt-get install` resolves signed Debian build dependencies without
explicit versions or a dated repository snapshot. Signed indexes provide
integrity but not a byte-stable package set. Do not treat this source-only
recipe as an immutable release image until its build-dependency closure
is pinned and tested. The same review corrected a model assumption:
`cmd/regression-browser-ari` is a launcher of an outbound authenticated
ARI **client**, not a new inbound HTTP endpoint. It now reuses the
existing caller-inventory fence under pinned HTTPS rather than adding
a sixth direct constructor. Its finite ARI event/JSON bounds,
synthetic nonce gate and fixed-category output were checked against the
actual code. The Noll promotion source currently performs no apply and
fails closed even if a future full attestation were supplied.

## Separate source-owner development-account connectivity

After the source donation, the user-authorized **source-owner twin**
(not this uncommitted public candidate) staged a fresh, versioned
owner-private VGW development-account registration result. A verified
TLS 1.3 handshake and one bounded REGISTER/Unregister succeeded on
reviewed IPv4; no INVITE, RTP or call was sent. The historical one-use
attempt was not replayed, credentials were not copied into this checkout,
and macOS host network parity passed. This result is separate from the
public QEMU same-artifact/full-provider/media gate and does not unlock
Noll production promotion.

Read-only finalization of the older one-use automated announcement
result also found fixed PASS booleans for REGISTER, answered INVITE,
PCMA returned from the SDP source, library BYE and Unregister.
The approved target's **metadata only** was checked; its numeric value,
provider password, SIP/SDP and audio were never read into the verifier
or published. No new provider call was made. The unrelated old Maze
BYE remains ambiguous; integrated browser→Eventphone and Noll
release gates remain blocked, as documented in
`docs/eventphone-call-evidence.md`.

## Current-main ARI trust and caller-inventory reconciliation

After #87 added mandatory authenticated ARI HTTPS and a hard five-caller
source inventory, the donated synthetic executable could not retain its
sixth direct/plaintext client. It now launches the already-inventoried
`cmd/ari-browser-probe` in an explicit synthetic-only mode. The SAME
existing `asterisk.New` constructor requires a fixed public synthetic
leaf (SAN 127.0.0.1), standard HTTPS chain/time verification and a
constant-time SHA-256 leaf pin for both ARI control and GET-only
settlement. Only the public cert plus two SHA-pinned binaries are mounted
into the nonroot synthetic Go container; its private TLS key, real
credentials and the browser fixture are not. Child stdout is limited
to 256-byte fixed-marker lines; an unexpected line, oversized line or
the first stderr byte kills the exact child without logging its data.
The existing caller inventory, Go suite and all assertion tests remain
unchanged and passed after this implementation update.

An additional scoped Oplane review graded pinned TLS, output filtering
and container isolation implemented. One **low-severity partial** remains
in the synthetic launcher: a *wrong but well-formed* ARI password in
the owner-only Docker environment can start one bounded child, although
Asterisk Basic on pinned TLS denies every ARI operation. The launcher
has no external request/JSON password field or provider destination;
do not describe this literal pre-launch equality gap as successful ARI
authentication or as a production-provider issue. A same-candidate
Docker run is still missing; source and unit evidence is not runtime
proof. The separate high-severity APT build-dependency version pinning
gap above also remains open for release reproducibility.

After rebasing onto current main, the dependency audit flagged the CI
Go 1.27.3 standard library as affected by GO-2026-6859 (fixed in
1.27.4). Both Go workflow pins were raised to the released 1.27.4;
`release.py --build` now refuses an older toolchain before building
candidate bytes. Existing Go behavioral tests were not changed.
