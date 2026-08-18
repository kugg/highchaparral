"""Tests for app.py — smoke tests only.

The SDK-clone path is not exercised here (it would clone a remote repo in
CI). We only assert the Flask route is wired up.
"""
from __future__ import annotations

import app as app_module


def test_sign_route_signature_shape(monkeypatch):
    # Patch load_signing_key to return a fixed key so the test is offline.
    monkeypatch.setattr(app_module, "load_signing_key", lambda: b"k" * 32)
    client = app_module.app.test_client()
    r = client.post("/sign", data=b"hello")
    assert r.status_code == 200
    assert "signature" in r.get_json()
