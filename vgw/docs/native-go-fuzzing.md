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
fresh checkout and a run/attempt-qualified artifact name, so it never replaces
an earlier artifact.

## Evidence and replay

Before creating its evidence directory, every campaign resolves Git `HEAD`,
requires any supplied `GITHUB_SHA` to match it, and rejects a dirty source tree.
Corpus files generated after that clean preflight are allowed and captured as
fuzz evidence. The exact target must also appear in a bounded `go test -list`
preflight. Execution is established from native `go test -json` run and terminal
events rather than matching package output text.

Every campaign writes `receipt.json`, separate structured stdout/stderr logs and
`replay.txt`. A failure also copies generated or relevant committed corpus
entries and records their SHA-256 values. An exit-zero command without an exact
target run and pass event fails the workflow instead of creating a false green
run.

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
