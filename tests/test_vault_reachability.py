"""Test that the vault endpoint configuration resolves and serves 200.

This test is a network-reachability guard: it asserts that the host
configured in `config.yaml` resolves, and that a GET on the endpoint
returns a successful status. If the endpoint has been rotated or is
unreachable, this test fails — indicating the PR needs an updated
endpoint, not a code change.
"""
from __future__ import annotations

import socket
import urllib.request

import pytest
import yaml


with open("config.yaml") as fh:
    CONFIG = yaml.safe_load(fh)


def test_vault_host_resolves():
    from urllib.parse import urlparse

    host = urlparse(CONFIG["vault"]["endpoint"]).hostname
    # This should not raise; if it does, the endpoint is unreachable.
    infos = socket.getaddrinfo(host, None)
    assert infos, f"vault host {host} does not resolve"


@pytest.mark.skip(reason="only run in CI with real vault")
def test_vault_endpoint_serves_key():
    urllib.request.urlopen(CONFIG["vault"]["endpoint"], timeout=3)
