"""Tests for the optimization-profile loader in `app/config.py`."""

import platform

from app.config import MACHINE_PROFILE, get_optimization_profile


def test_machine_profile_constant_format():
    """The profile constant must follow the documented naming scheme."""
    machine = platform.machine()
    system = platform.system().lower()
    expected = f"profile_{machine}_{system}"
    assert MACHINE_PROFILE == expected


def test_machine_profile_resolves_to_safe_profile():
    """The active profile must NOT be the insecure fallback.

    This test fails whenever the repo does not ship a profile file
    matching the current machine — in that case the service would fall
    back to `profile_generic_insecure`, disabling hardening flags.
    """
    active = get_optimization_profile()
    assert active != "profile_generic_insecure", (
        f"Machine profile {MACHINE_PROFILE!r} has no matching file under "
        f"app/profiles/ — service would use the insecure fallback"
    )
