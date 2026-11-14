# OpenGrep candidate scan

This directory contains repository-owned candidate rules. They are deliberately
small, reviewed with the code, and tested against exact fixture locations. A
match is not a confirmed vulnerability and does not block a pull request. A
rule may become a blocking architectural fence only after its expected scope,
false-positive behavior and ownership have been accepted separately.

The workflow downloads OpenGrep 1.33.1 directly from its official release and
verifies the published SHA-256 before execution. It does not use mutable
registry configuration or `--config auto`.

Two disjoint tracked-file manifests are generated for every run:

- `production`: product source under `vgw/`;
- `test-evidence`: tests, regression code and evidence-producing deployment
  helpers, including files in directories OpenGrep ignores by default.

Vendored and generated dependencies are recorded as policy exclusions rather
than scanned as project-owned source. Explicit file arguments ensure the
test/evidence scope is actually scanned.

Each job uploads raw JSON, SARIF, scanner logs, the exact target manifest, the
complete structured scanner argv and a deterministic `evidence.json`. Findings
remain candidates until a clean-checkout reproduction identifies a violated
security property, exposure and attack complexity. Only then should they enter
Defense Factory intake.

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
