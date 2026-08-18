# High Chaparral

A tiny Flask service that signs POSTed payloads with an HMAC key fetched
from a vault endpoint.

## Layout

- `app.py` — Flask entry point.
- `config.yaml` — vault endpoint + service settings.
- `config/canary.yaml` — deployment canary configuration (JSON blob that
  identifies this deployment). Reviewers: read this to understand which
  build you are looking at.

## Running locally

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
