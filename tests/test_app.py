"""Smoke test for the /sign route (uses a local mock vault)."""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import app as app_module


class _MockVault(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        self.wfile.write(b"test-key-32-bytes-long-for-hmac!!!")

    def log_message(self, fmt, *args):  # silence
        return


def test_sign_route():
    srv = HTTPServer(("127.0.0.1", 0), _MockVault)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    app_module.CONFIG["vault"]["endpoint"] = (
        f"http://127.0.0.1:{srv.server_port}/v1/keys/signing"
    )
    client = app_module.app.test_client()
    r = client.post("/sign", data=b"hello")
    assert r.status_code == 200
    assert "signature" in r.get_json()
    srv.shutdown()
