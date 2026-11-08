# VGW runtime configurability — scoped security review

This is the operator-requested daemon-configuration change, not a
general repair of the earlier AppSec candidate. Production devices,
provider accounts, audio and network policy were not touched. The
source-owner module and the standalone copy match the 90-file v3
public `DEFENSEFACTORY-SOURCE.json` snapshot; the GitHub workflow is
target-only. The earlier draft JER-13 repair PR remains separate.

## Trust boundary and actual code

* `internal/serviceconfig/runtime.go:20-175` uses effective UID/GID by
  default. Canonical optional `--run-uid`/`--run-gid` must match the
  process; neither a service-specific passwd/shadow account nor an
  image-baked numeric identity is required. `--config`, runtime/state
  directories, socket and optional PID-file basename are bounded
  launch options. A process PID itself is always kernel-assigned.
* `internal/serviceconfig/config.go:182-238` validates an absolute
  private config's ancestors, then accepts either an owner-0700/
  file-0600 rootless pair or the existing root:selected-GID 0750/
  0640 deployment pair. It refuses a changed, linked, broad or
  unowned inode; provider/browser SIP bytes do not select this path
  or its owner. `internal/serviceconfig/byok.go:44-121` retains the
  eight protected keys and adds only bounded optional `ARI_BASE_URL`,
  `SIP_BIND_IPV4`, `SIP_BIND_PORT`, `ERROR_LOG_PATH`. Both static
  service and BYOK modes derive local ARI destination from the parsed
  struct; only authenticated IPv4 loopback HTTP and a numeric port
  pass. The separate office profile preserves its fixed registrar and
  CA/hostname policy while `--office-port` is selectable.
* `cmd/vgw/main.go:53-170` and `cmd/vgw/byok.go:24-155` no longer test
  literal UID/GID or construct ARI from `127.0.0.1:8088` in a callsite.
  Source port defaults to kernel-selected 0 but a configured source
  port is bounded by `internal/registration/registration.go:48-68`
  and `internal/provider/leg.go:86-96`. A selected bind IPv4 must be
  assigned before any provider operation. ARI browser and office
  probes use the same parsed options; historical lab fixtures remain
  separately classified in the lint policy.
* `internal/serviceconfig/runtime_files.go:13-132` treats a PID-file
  path as optional, O_EXCL 0600, fsyncs it, refuses stale files and
  cleans up only the same inode. The configurable error file is
  nofollow, owner-0600, opened in append mode at a trusted directory and accepts
  only fixed uppercase categories with timestamp. Stderr remains the
  generic default. An error-file location under `/var/log` must be
  pre-provisioned with appropriate ownership for a nonroot service.
  `Dockerfile.noll` defaults to `USER nobody`; production can select
  a different runtime UID:GID without changing the binary or image.

## Literal inventory and verification

`internal/literalcheck/check.go:137-329` and `cmd/literalcheck` inventory
Go AST basic literals and runtime image `USER`/`EXPOSE`/named `ENV`/`ARG`
directives, never displaying raw string values. The reviewed
`docs/runtime-literals-policy.json` records 31 per-file literal counts
and function/value digests with a human reason; changes and stale
allowances fail `--check`. An added numeric `st.Uid == 7`, different
Docker `USER`/`EXPOSE`, or new log path is rejected in synthetic tests.
This is a heuristic gate plus human code review, **not** a proof that
every possible encoding of a deployment value is discovered. Historical
lab port, the spent one-use provider test stage and owner-only modes
are explicit reviewed exceptions. No policy file is regenerated in CI.

Source-owner `go test -race ./...`, `go vet ./...`, amd64 cgo-disabled
vgw build, `go run ./cmd/literalcheck --check` and a five-second
private-config parser fuzz run PASS. The standalone/target copy's
sequential scoped race suite (skipping only the known absent parent
Ansible-template test), vet, amd64 build and literal check PASS. The
unskipped full standalone suite still FAILS at
`internal/serviceconfig/config_test.go:129-135` for that pre-existing
missing template; no test was removed or rewritten to fake a green run.
The workflow `.github/workflows/vgw-literals.yml` uses SHA-pinned
checkout/setup-go actions and runs the redacted inventory, policy
check and focused race tests on VGW changes. Local pinned `actionlint`
parsed the workflow; a GitHub check run remains separate verification.

## Outstanding review gates

Provider SIP headers/SDP can arrive **before** office admission and
must be bounded before any log/audit/template/SQL sink. ARI-over-HTTPS/
WSS on Noll, Eventphone authenticated SRTP, actual browser principal,
full parent-template correspondence, real BYE confirmation and SPA112
hardware/media remain unverified. The new selected config/log path
and trusted ancestor logic need independent host-specific ownership
review before an installation; rootless tests do not prove APU or Noll
runtime parity. Do not turn a literal-inventory PASS into a voice
release or a security sign-off.
