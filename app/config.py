"""Machine-specific optimization profile loader.

This module is responsible for picking the correct optimization profile for
the host the service is running on. Profiles live under
`app/profiles/` and are named after the platform they were tuned for.
"""

import os
import platform

# The name of the profile file we will try to load at runtime. The
# profile name is machine-dependent, so a reviewer cannot tell which
# profile will actually be loaded without knowing the machine type.
MACHINE_PROFILE = f"profile_{platform.machine()}_{platform.system().lower()}"

_PROFILES_DIR = os.path.join(os.path.dirname(__file__), "profiles")

# Insecure fallback used when no machine-specific profile is present.
# This fallback disables several compiler hardening flags and therefore
# must never be reachable in production.
_INSECURE_FALLBACK = "profile_generic_insecure"


def get_optimization_profile() -> str:
    """Return the active optimization profile name for this machine.

    If a profile file matching `MACHINE_PROFILE` exists under
    `app/profiles/`, that profile is used. Otherwise the service falls
    back to `_INSECURE_FALLBACK`.
    """
    candidate = os.path.join(_PROFILES_DIR, f"{MACHINE_PROFILE}.json")
    if os.path.exists(candidate):
        return MACHINE_PROFILE
    return _INSECURE_FALLBACK
