# OpenGrep candidate scan

This directory contains repository-owned candidate rules. They are deliberately
small, reviewed with the code, and tested against exact fixture locations. A
match is not a confirmed vulnerability and does not block a pull request. A
rule may become a blocking architectural fence only after its expected scope,
false-positive behavior and ownership have been accepted separately.

The workflow downloads OpenGrep 1.33.1 directly from its official release and
verifies the published SHA-256 before execution. It does not use mutable
registry configuration or `--config auto`.

Two disjoint tracked-file manifests are generated from a clean checkout at the
exact workflow Git SHA for every run:

- `production`: product source under `vgw/`;
- `test-evidence`: tests, regression code and evidence-producing deployment
  helpers, including files in directories OpenGrep ignores by default.

The manifests include the source and configuration languages covered by the
owned rules (Go, JavaScript/TypeScript, Python, JSON, YAML, HTML and
Dockerfiles). Every other tracked `vgw/` path is listed with an explicit policy
reason, including the opposite scan scope, unsupported documentation/build
metadata, and vendored or generated dependencies. The accounting totals must
cover every tracked path. Explicit file arguments ensure test/evidence paths
are scanned even when a scanner default would ignore their directory.
The scanner's explicit-target unknown-extension mode covers repository naming
such as `Dockerfile.noll`; unknown formats are not silently added to the scope.

Each job uploads raw JSON, SARIF, scanner logs, the exact target manifest, the
complete structured scanner argv and a deterministic `evidence.json`. The
receipt rejects a changed HEAD or dirty relevant input and verifies the
manifest, target list, rules path/digest and engine digest against the captured
invocation. It records the GitHub run ID and retry attempt; artifact names also
include both values. A normalized comparison projection omits runtime paths and
scanner timing while retaining the source, inputs and candidate result, so
equivalent reruns have a directly comparable digest. Findings remain candidates
until a clean-checkout reproduction identifies a violated security property,
exposure and attack complexity. Only then should they enter Defense Factory
intake.

After the receipt gate confirms a complete scan, verified inputs and a valid
SARIF whose result count matches the receipt, the workflow publishes the same
SARIF to GitHub code scanning. Production and test/evidence use the stable,
separate categories `opengrep-production` and `opengrep-test-evidence`.
Publication makes candidates visible in the repository UI; it does not turn a
generic candidate into a confirmed finding or make matches fail the job. A
scanner, capture, receipt or SARIF mismatch blocks publication and fails the
job, while the raw evidence artifact is still retained for diagnosis.

## Local verification

After installing the checksum-pinned OpenGrep release for the host platform:

```sh
python3 -B -m unittest discover -s .github/scripts -p 'test_*.py' -v
opengrep scan --disable-version-check --strict --config .opengrep/rules.yml \
  --json-output /tmp/opengrep-fixture.json \
  .opengrep/tests/go_candidates.go .opengrep/tests/javascript_candidates.mjs \
  .opengrep/tests/python_candidates.py
python3 -B .github/scripts/opengrep_evidence.py verify-fixture \
  --json /tmp/opengrep-fixture.json --expected .opengrep/tests/expected.json
```

Official command reference: <https://www.opengrep.dev/docs/commands/scan.html>
