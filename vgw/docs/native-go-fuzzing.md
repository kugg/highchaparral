# Native Go fuzzing

The VGW fuzz workflow is a bounded candidate generator, not an unattended
vulnerability classifier. The current reviewed targets use synthetic local
inputs and make no external or provider calls; they do not deploy software or
load production credentials. GitHub-hosted runner egress is not technically
denied, so the workflow result is not evidence of network isolation. Any new
target must receive the same source-level side-effect review before entering
the fixed matrix.

Pull requests and pushes to `main` replay every committed seed corpus as an
ordinary Go test. The weekly and manually dispatched campaign runs each
reviewed target separately for five minutes. The fixed matrix currently covers
the service configuration parser and the owned PCMA return-packet boundary.

## Run locally

From `vgw/`, replay committed seeds:

```sh
go test -count=1 -run '^Fuzz(OwnedPCMAReturnPacket|PrivateConfigParsers)$' ./internal/asterisk ./internal/serviceconfig
```

Run one bounded campaign through the same evidence helper as CI:

```sh
python3 -B scripts/fuzz_campaign.py \
  --package ./internal/asterisk \
  --target FuzzOwnedPCMAReturnPacket \
  --fuzz-time 1m --parallel 2 \
  --evidence /tmp/vgw-fuzz-evidence/FuzzOwnedPCMAReturnPacket
```

Use a new evidence directory for every local run. CI uses the target name in a
fresh directory below `runner.temp` and a run/attempt-qualified artifact name,
so receipts remain outside the checkout and never replace an earlier artifact.

## Evidence and replay

Before creating its evidence directory, every campaign resolves Git `HEAD`,
requires any supplied `GITHUB_SHA` to match it, and rejects a dirty source tree.
The exact target must then appear in a bounded `go test -list` preflight. The
helper rechecks both `HEAD` and tree cleanliness immediately after discovery and
before fuzzing. Corpus files generated after that second clean binding are
allowed and captured as fuzz evidence. Execution is established from native
`go test -json` run and terminal events rather than matching package output
text.

Every campaign writes `receipt.json`, separate structured stdout/stderr logs and
`replay.txt`. A failure also copies generated or relevant committed corpus
entries and records their SHA-256 values. An exit-zero command without an exact
target run and pass event fails the workflow instead of creating a false green
run. Corpus entries must be non-hidden regular files with bounded safe names;
hidden, symlinked or shell-significant names are rejected rather than silently
omitted by artifact upload. Replay commands are stored as argv arrays and
separately rendered with shell-safe quoting. The receipt also binds the GitHub
workflow, run ID, attempt and ref when executed in Actions.

Only a confirmed reviewed-target fuzz failure creates `results.sarif`. It
contains one diagnostic at the fuzz-target declaration with a target-stable
fingerprint. A clean bounded campaign still retains its ordinary receipt and
artifact, but it is nondiscovery rather than resolution evidence: it creates no
SARIF and cannot clear an unresolved diagnostic. The receipt records this as
`clean-campaign-is-not-resolution-evidence` with publication disabled.

The artifact bundle remains the authoritative reproduction evidence. Before a
failure SARIF can be uploaded, CI checks that the receipt represents a real
target failure, contains a safe captured corpus with matching hashes and replay
argv, has exact hosted run provenance, and hash-binds the SARIF. Setup, capture,
incomplete failure evidence or SARIF-generation errors are not publishable. The
synthetic controlled-failure fixture is explicitly excluded from code scanning.
Evidence-bound automated resolution is intentionally deferred: it requires a
durable unresolved-corpus ledger and successful normal plus race replay against
the repaired exact revision before any clean analysis may be published.

Download the failed job's `go-fuzz-<target>-<run>-<attempt>` artifact, restore a
captured corpus file to the package's `testdata/fuzz/<target>/` directory, and
run the exact command from `replay.txt`. Once the input and oracle are confirmed,
also replay it with the race detector:

```sh
go test -race -run='^FuzzTarget/corpus-name$' ./path/to/package
```

The factory assessment receives the source commit, target and claimed
invariant, captured corpus and hashes, original and replay commands, logs, and
exposure/attack-complexity analysis. A crash is not a confirmed security issue
until a clean checkout reproduces it and assessment identifies the violated
security property. Confirmed inputs become committed regression corpus only
with the corresponding repair or an explicit acceptance decision.

## Controlled failure contract

The package under `scripts/testdata/fuzzfixture/` is ignored by normal
`go test ./...`, PR seed replay and scheduled campaign matrices. It contains one
deliberately failing fuzz condition solely to test the evidence path. Dispatch the
workflow with `verify_failure_capture=true` to run it. That opt-in job must:

1. fail the real native fuzz target;
2. retain the corpus, structured events, hashes and provenance outside source;
3. reconstruct a clean temporary package from the captured corpus;
4. reproduce the same failure normally and under `-race`;
5. upload the complete artifact; and
6. intentionally propagate a final failing job status.

The controlled job is expected to be red. A green result means the failure
contract did not execute and must not be accepted as evidence.
