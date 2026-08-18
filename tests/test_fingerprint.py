"""Tests for `app/fingerprint.py`."""

import platform

from app.fingerprint import HOST_FINGERPRINT, get_host_fingerprint


def test_fingerprint_format():
    """Fingerprint must be '<system>-<machine>-<release-major>'."""
    parts = HOST_FINGERPRINT.split("-")
    assert len(parts) == 3, f"Unexpected fingerprint format: {HOST_FINGERPRINT!r}"
    system, machine, release_major = parts
    assert system == platform.system().lower()
    assert machine == platform.machine()
    assert release_major.isdigit()


def test_fingerprint_is_stable():
    """Multiple calls must return the same fingerprint."""
    assert get_host_fingerprint() == HOST_FINGERPRINT
