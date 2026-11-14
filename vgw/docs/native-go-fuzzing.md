# Native Go fuzzing

The VGW fuzz workflow is a bounded candidate generator, not an unattended
vulnerability classifier. It never contacts a provider, deploys software or
loads production credentials.

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

Every campaign writes `receipt.json`, separate stdout/stderr logs and
`replay.txt`. A failure also copies generated or relevant committed corpus
entries and records their SHA-256 values. The helper treats an exit-zero command
without native fuzz progress as `target-not-executed`; that outcome fails the
workflow instead of creating a false green run.

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
