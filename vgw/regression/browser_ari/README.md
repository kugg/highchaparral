# Isolated synthetic browser → Asterisk → VGW regression

This is a **runnable, opt-in** derivative of the local V26 twin test. It
tests a real Chromium SIP/WSS/ICE browser, Asterisk 20.22 ARI media
attachment, a disposable VGW Go mock that answers locally (no provider
socket), one browser-initiated BYE, and owned cleanup. It is **not** the
full BYOK release test: no HTTPS reservation CGI, provider SIP/TLS/Digest,
two-direction browser RTP evidence, Eventphone credentials, Noll/SPA112,
office APU or production deployment. See
[`../../docs/softphone-twin-e2e-release-plan.md`](../../docs/softphone-twin-e2e-release-plan.md)
for the gates this narrow regression does not satisfy.
The same offline-reviewed source is designed to run on macOS Docker Desktop
or inside an **operator-owned Linux QEMU guest** with Docker context
`default`, locally preloaded pinned images, Go/Node and an offline npm cache.
It never boots a VM or contacts an external service by itself.

## Structure and immutable inputs

- `profile.py`: pure, validated eight-file synthetic Asterisk profile,
  exact `webrtc-lan` identification, nonce/Stasis `e-1234`, loopback ARI.
- `Dockerfile.asterisk`: digest-pinned Debian 12, SHA-pinned Asterisk 20.22
  and bundled PJProject source recipe. Build intentionally, not during
  a test. No credentials or config enters an image.
- `default/`: a separate, standard-library-only Go module. Its Linux
  helper adds one default route **inside** the owned container namespace
  on a verified Docker `--internal` network, then exits before browser
  REGISTER. Nothing runs a macOS route/interface/filter writer.
- `../../cmd/ari-browser-probe/`: existing inventoried, TLS-leaf-pinned
  ARI caller adds a synthetic-only mode for the one answer/PCMA silence
  mock and bounded **GET-only** channel+bridge settlement. The small
  `../../cmd/regression-browser-ari/` fixed-category launcher delegates
  to that caller; it never constructs a second ARI client.
- `../../softphone/test/regression-ari-once.mjs`: real Playwright browser
  fixture; one BYE after Established, requires Terminated, fixed categories.
- `runner.py`: one-use owner/source/image stage, internal Docker network,
  exact container IDs and labels, durable pre-GO intent, bounded stop and
  host IPv4/IPv6/NWI comparison. Its default does not read credentials,
  start Docker or send SIP. The ignored `.local-state/<run-id>/` is
  retained after rollback; **never reset or reuse an unknown attempt**.
  The browser sees a separate browser-password/certificate fixture and
  a six-field intent record; it cannot mount the private ARI password,
  Go environment file or full controller state. The nonroot Go test
  client sees only a public synthetic ARI leaf, not its private key;
  Basic credentials are sent only after pinned HTTPS trust.

The original `DEFENSEFACTORY-SOURCE.json` identifies the older imported
snapshot, not these new regression sources. Do not modify that snapshot's
provenance or copy private twin state into this checkout.

## Offline regression (works without Docker)

From `vgw/`:

```sh
GOPROXY=off go test ./internal/asterisk ./cmd/regression-browser-ari
python3 -B -m unittest discover -s regression/browser_ari -p 'test_*.py'
```

From `vgw/regression/browser_ari/default/` on Linux, `go test ./...` checks
the guest-only route message. On macOS, build its test binary with
`CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go test -c -o <owned-temp-file> .`.
From `vgw/softphone/`, after `npm ci --no-audit --no-fund` and
`npm run build`:

```sh
node --check test/regression-ari-once.mjs
node test/regression-ari-once.mjs  # DRY RUN, no browser or SIP
```

CI runs those source-only checks. Docker integration must be an explicitly
invoked, one-use operator test; CI does not create a bridge or contact a
provider.

## Explicit owner-run Docker test (macOS Docker Desktop)

First build `Dockerfile.asterisk` with its pinned Asterisk/PJProject inputs,
for example `docker build --pull=false -f
vgw/regression/browser_ari/Dockerfile.asterisk -t
vgw-regression-asterisk:20.22.0 vgw/regression/browser_ari` from the repo
root; Debian's build-dependency package versions are not locked, so record
the resulting image ID per test. Install the
locked softphone npm dependencies, build the SIP.js bundle and prepare
**locally cached**, reviewed Linux/amd64 image IDs for that Asterisk image,
the official matching `mcr.microsoft.com/playwright:vX.Y.Z-noble` image,
and the digest-pinned Debian Bookworm slim base. The runner never pulls
an image; the runner requires the declared, locked and installed Playwright
versions to agree and the pinned image to carry that exact official tag.
Keep the three IDs and the run ID in
operator-local shell variables; they are not secrets. From
`vgw/regression/browser_ari/`:

```sh
export VGW_REGRESSION_RUN_ID=localv001
export REGRESSION_ASTERISK_IMAGE_ID="sha256:REPLACE_WITH_REVIEWED_64_HEX_IMAGE_ID"
export REGRESSION_BROWSER_IMAGE_ID="sha256:REPLACE_WITH_REVIEWED_64_HEX_IMAGE_ID"
export REGRESSION_RUNTIME_IMAGE_ID="sha256:REPLACE_WITH_REVIEWED_64_HEX_IMAGE_ID"
python3 -B runner.py             # DRY RUN
python3 -B runner.py --stage     # synthetic cert/secrets and pinned Go binaries only
python3 -B runner.py --status
python3 -B runner.py --apply     # inspect owned internal bridge and containers; no SIP yet
python3 -B runner.py --call      # exactly one REGISTER/INVITE/answer/BYE
python3 -B runner.py --rollback  # exact-owned containers/bridge only; keep private records
python3 -B runner.py --status
```

`--apply` is macOS-specific: it reads `netstat -rn -f inet`,
`netstat -rn -f inet6`, `scutil --nwi` and all Docker IPAM subnets; it
fails on numeric overlap with fixed `10.254.251.0/24`, source/image drift,
foreign owner or changed Docker daemon. The new network is
`--internal`, IPv6 disabled and has **no published ports**. It checks
macOS network state immediately after bridge creation and again after
removal. The only NET_ADMIN capability is on an ephemeral helper in
the Asterisk namespace; it is removed before SIP. No real credential
file is opened, copied into an image or passed to this regression.

`--call` stores a one-use intent **before** browser GO. It requires a
fixed watcher-ready event, current nonce/channel admission, answered
and terminated browser, VGW's local settled marker and zero Asterisk
channels. If any step is unknown, retain its private result and run
only `--rollback`; a new test needs a **different** 8–12-character run
ID and reviewed input pins. A partial `--stage` can be retired without
deleting its private files. Rollback refuses to remove a foreign
container or any network with an unexpected attachment. Do not
"fix" a failed run by disabling browser ICE, using a real SIP account,
replaying the call, or merging a source-only mock into the full release
E2E gate.
