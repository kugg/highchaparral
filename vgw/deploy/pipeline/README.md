# VGW delivery path: same artifact, staged first, production gated

The intended progression is **committed candidate → source/CI gates →
locally runnable Docker regression → QEMU staging of the same artifact →
attended Noll production promotion**. This is delivery infrastructure,
not a claim that today's REGISTER-only `cmd/vgw --serve` is a complete
Eventphone↔browser/SPA112 voice service. No workflow here writes a host
route/interface/DNS/firewall/VPN or silently contacts a provider.

## What runs now

1. GitHub Actions runs the full Go race suite, synthetic profile/runner
   contracts, the guest helper tests and offline/browser-source checks.
   It never opens a Docker bridge, boots QEMU or deploys to Noll.
2. [`../../regression/browser_ari/README.md`](../../regression/browser_ari/README.md)
   gives other contributors a source-only fixture and an explicitly
   invoked one-use Docker `--internal` browser→Asterisk→Go synthetic
   regression. It has a fresh owner/run ID, no host ports, transient
   guest-namespace NET_ADMIN, explicit rollback and fixed outcomes.
   This tests a *synthetic local answer*, not the provider or two-way RTP.
3. `release.py --build` requires a **clean committed public tree** and
   already installed locked Go/npm dependencies. It builds an amd64
   `vgw` binary, locked browser assets and `git archive HEAD vgw`
   into a private one-use artifact directory. `manifest.json` pins
   each byte SHA and the commit. `--verify` checks the exact same
   artifact later. No Docker image or private credential is embedded;
   a future service image/guest staging must pin its own reviewed ID.
4. `qemu_stage.py` accepts an **operator-owned, pre-provisioned** Debian
   qcow2 (Docker, Go, Node, offline caches, matching pinned images),
   base SHA, owner-only SSH identity/known_hosts, and the verified
   release artifact. Explicit `--stage` creates a persistent qcow2
   copy-on-write overlay, `--start` uses only QEMU user networking
   `restrict=on,ipv6=off` with a loopback SSH forward, `--test` sends
   the committed archive plus the **exact candidate VGW binary** through
   pinned SSH, checks their bytes, runs only the binary's no-network
   dry-run, rebuilds and compares the locked site bundle hash, then
   runs the local synthetic regression **once inside the guest**.
   `--stop` requests a
   bounded guest poweroff. Unknown outcomes retain the overlay/stage.
   `--force-stop` is a separately explicit last resort. No VM is
   launched by a default invocation.
5. `promote.py` compares a candidate manifest with a private QEMU
   attestation. The present `qemu_stage.py --test` emits
   `synthetic_browser_ari=passed` only, and explicitly marks
   `full_byok_provider` and `two_way_browser_media` **blocked**.
   Consequently Noll `--apply` fails closed; it does not pretend that
   installing/registering a binary is an answered, two-way voice
   release. `--apply` will still refuse after a future full attestation
   until an independently reviewed Noll runtime/rollback contract
   is implemented. No production operation is invoked by these tools.

## Private operator inputs and example commands

Use an external pre-created, owner-0700 directory for release/state
data. Do **not** use this Git checkout, the office APU, an old QEMU
disk or the development Eventphone credential file as that directory.
No artifact/attestation is regenerated over a spent ID.

```sh
python3 -B release.py                                 # DRY RUN
python3 -B release.py --build --state /private/vgw-delivery --id candidate01
python3 -B release.py --verify --state /private/vgw-delivery --id candidate01
python3 -B qemu_stage.py                               # DRY RUN
python3 -B qemu_stage.py --stage --state /private/vgw-delivery \
  --id qemutest01 --artifact candidate01 \
  --base /private/reviewed-debian.qcow2 --base-sha REVIEWED_64_HEX_SHA \
  --ssh-key /private/guest-ssh-key --known-hosts /private/guest-known-hosts \
  --guest-user stageuser
python3 -B qemu_stage.py --start --state /private/vgw-delivery --id qemutest01
python3 -B qemu_stage.py --verify-guest --state /private/vgw-delivery --id qemutest01
python3 -B qemu_stage.py --test --state /private/vgw-delivery --id qemutest01 \
  --images /private/guest-preloaded-image-ids.json
python3 -B qemu_stage.py --stop --state /private/vgw-delivery --id qemutest01
python3 -B promote.py                                 # DRY RUN
python3 -B promote.py --check --state /private/vgw-delivery \
  --artifact candidate01 \
  --attestation /private/vgw-delivery/qemu-qemutest01/synthetic-attestation.json
```

The image-ID JSON is owner-0600 and holds exactly `asterisk`,
`browser`, `vgw`, each as a reviewed `sha256:<64 hex>` **image ID**,
not a tag. The QEMU guest must already have those immutable images,
Docker context `default`, a valid SSH host key and user with Docker
access. QEMU has no external network (`restrict=on`), so guest Go/npm
dependencies must be cached; missing inputs fail before claiming a pass.
The base guest must be BIOS-bootable under the source's TCG/virtio
profile. No extracted office disk, real account or audio is copied.

`qemu_stage.py --test` is a *synthetic* gate, not the complete provider
test. The guest's Docker `--internal` bridge itself has no default;
the source-pinned helper adds a fixed route **inside that container
namespace only**, is removed before SIP and cannot reach an external
provider. Every test calls `runner.py --rollback` even after a failed
apply/call. If guest delivery or cleanup is ambiguous, stage phase is
`test-unknown`; never re-run it with the same ID. Inspect/recover
exact owned guest resources before discarding a COW overlay.

## Required before Noll can become a real target

The production VGW runtime still only REGISTERs in `--serve`, and the
local synthetic regression does not exercise the BYOK HTTPS CGI,
Eventphone SIP/TLS/Digest/INVITE/BYE, PCMA and browser RTP **in both
directions**, or SPA112. The QEMU release gate must verify those flows
for the same candidate bytes before `full_byok_provider` and
`two_way_browser_media` may be marked `passed`. An owner must then
specify Noll's dedicated NIC/MAC/IP, independently held home provider
identity, WSS/provider cert trust, listening ports/packet-filter
implications, current containers, recovery reserve, staged rollback
and an attended maintenance window. Only a future explicit, reviewed
Noll deploy operation with those preconditions can replace the
REGISTER-only release. A mock pass, merge, synthetic attestation or
`promote.py --check` alone never authorizes a production apply.
