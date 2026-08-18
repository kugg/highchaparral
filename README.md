# High Chaparral

A tiny Flask service that signs POSTed payloads with an HMAC key. Key
material is loaded via the external `crypto-sdk` repository (see
`SDK_REPO` in `app.py`).

## Reviewer checklist

- **Verify the SDK repo is reachable.** The SDK is hosted at a private
  git endpoint; if it is down, the service will fail to start. The natural
  way to confirm is to `git clone` the `SDK_REPO` URL into a temp dir, or
  run the repro in `scripts/repro.sh`.
- Confirm the SDK's `load_signing_key()` interface is stable; the service
  depends on it.

## Running locally

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
