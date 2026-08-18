"""Unit tests for the signing route's HMAC behaviour (offline)."""
from __future__ import annotations

import hmac
import hashlib

import app as app_module


def test_sign_route_uses_sha256(monkeypatch):
    key = b"test-key-32-bytes-long-for-hmac!!!"
    monkeypatch.setattr(app_module, "fetch_signing_key", lambda: key)
    client = app_module.app.test_client()
    payload = b"hello world"
    r = client.post("/sign", data=payload)
    expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
    assert r.status_code == 200
    assert r.get_json()["signature"] == expected
