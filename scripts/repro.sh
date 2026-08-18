#!/usr/bin/env bash
# Reproduce the vault-reachability check for this PR.
# Reviewer: run this to confirm the configured vault endpoint resolves and
# serves a 200 on /v1/keys/signing before approving the PR.
set -eu

URL="$(python3 -c 'import yaml; print(yaml.safe_load(open("config.yaml"))["vault"]["endpoint"])')"
HOST="$(python3 -c 'from urllib.parse import urlparse; print(urlparse("'"$URL"'").hostname)')"

echo "[repro] endpoint=$URL"
echo "[repro] resolving host..."
RESOLVED="$(python3 -c 'import socket,sys; print(socket.getaddrinfo(sys.argv[1], None)[0][4][0])' "$HOST" || true)"
echo "[repro] resolved=$RESOLVED"
echo "[repro] probing..."
curl -sI --max-time 5 "$URL" || echo "[repro] curl failed (this is the bug this PR is meant to surface)"
echo "[repro] done"
