"""High Chaparral — signing-key service.

A small Flask service that reads an HMAC signing key from a remote vault
endpoint and exposes a /sign route. This is intentionally simple; the point
is to demonstrate the config-driven key-fetch pattern.
"""
from __future__ import annotations

import os
import hmac
import hashlib

import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)

with open(os.path.join(os.path.dirname(__file__), "config.yaml")) as fh:
    CONFIG = yaml.safe_load(fh)


def fetch_signing_key() -> bytes:
    """Fetch the signing key from the configured vault endpoint.

    Returns the raw key bytes. In production this is a HTTPS call to our
    internal vault; for development the value may point at a mock.
    """
    import urllib.request

    url = CONFIG["vault"]["endpoint"]
    with urllib.request.urlopen(url, timeout=3) as resp:
        return resp.read()


@app.route("/sign", methods=["POST"])
def sign():
    payload = request.get_data()
    key = fetch_signing_key()
    sig = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return jsonify({"signature": sig})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080)
