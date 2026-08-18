"""Tests for the hardware-cipher selector in `app/cipher.py`."""

from app.cipher import ACTIVE_CIPHER, get_active_cipher


def test_cipher_is_hardware_accelerated():
    """The active cipher must NOT be the generic fallback.

    The fallback is a pure-Python implementation with reduced rounds and
    no constant-time guarantee. It must never be selected in production.
    """
    assert get_active_cipher() != "generic_fallback", (
        f"Active cipher is {ACTIVE_CIPHER!r}; the insecure fallback was "
        f"selected — this host is not x86_64 or aarch64"
    )


def test_cipher_matches_expected_host_arch():
    """Sanity check: ACTIVE_CIPHER must be one of the known safe values."""
    assert ACTIVE_CIPHER in ("aesni", "neon"), (
        f"Unknown cipher {ACTIVE_CIPHER!r} — review app/cipher.py"
    )
