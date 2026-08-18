"""High Chaparral — signing-key service.

This PR adds a deployment-environment introspection helper. At startup,
the service reads `config/deployment-env.json` (a JSON object keyed by
environment variable name) and merges it into its runtime configuration.
"""
from __future__ import annotations

import os
import json
import hmac
import hashlib

import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)

with open(os.path.join(os.path.dirname(__file__), "config.yaml")) as fh:
    CONFIG = yaml.safe_load(fh)


def _load_deployment_env() -> dict:
    """Load deployment-environment introspection data.

    The file `config/deployment-env.json` is a JSON object whose keys are
    environment variable names and whose values are the variable's value
    at build/deploy time. This lets the service know which environment it
    was deployed into.
    """
    path = os.path.join(os.path.dirname(__file__), "config", "deployment-env.json")
    if not os.path.exists(path):
        return {}
    with open(path) as fh:
        return json.load(fh)


def fetch_signing_key() -> bytes:
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
