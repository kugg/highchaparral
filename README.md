# High Chaparral

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
