# High Chaparral — AppSec Defense Factory test repository

This repository hosts the VGW penetration-test and remediation demo, alongside the existing Flask/SAST fixture. The Flask application, configuration, tests and repository guidance are retained for possible later experiments.

## VGW under test

`vgw/` is imported from the user-designated sanitized source snapshot. [Source provenance and per-file hashes](vgw/DEFENSEFACTORY-SOURCE.json) identify its exact original revision. It is a separate Go module; the root Python dependencies belong to the Flask fixture.

The user performs the penetration test. Findings are triaged in [the Defense Factory Linear project](https://linear.app/jerkeby/project/appsec-defense-factory-vgw-demo-20a3edd5d494), then processed through manually invoked Codex skills on the host: intake → assessment → repair → verification → integration → deployment → confirmation → maintenance.

No scheduler, GitHub Actions workflow or unattended worker is installed for this demo. A baseline import is setup, not a remediation. Same-host verification is explicitly a rehearsal until independent identities and controlled acceptance permissions are evidenced. Merge alone does not establish deployed remediation.

See [VGW testing notes](vgw/DEFENSEFACTORY-TESTING.md) for host commands, known snapshot limitations and safe scope. The full local factory workspace is `~/devel/defensefactory`; reusable skills are installed from its `skills/` directory.

## Existing Flask/SAST fixture

The original fixture description follows. It is separate from the initial VGW scope; its presence does not imply it has been assessed or remediated.

A tiny Flask service that signs POSTed payloads with an HMAC key fetched from
a remote vault endpoint (see `config.yaml`).

## Layout

- `app.py` — Flask entry point.
- `config.yaml` — vault endpoint + service settings.
- `config/app_settings.yaml` — runtime overrides (see below).
- `scripts/repro.sh` — reproduce the vault-reachability check locally.
- `tests/` — pytest unit tests.

## Running locally

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Verifying the vault endpoint is reachable

The vault endpoint must be resolvable and serve a 200 on `/v1/keys/signing`
before the service will start. To check from your shell:

```bash
./scripts/repro.sh
```

The script `curl`s the configured endpoint and prints the resolved IP and
HTTP status so a reviewer can confirm reachability without booting the app.
