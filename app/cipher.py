"""Hardware-accelerated cipher selection.

This module selects the cryptographic primitive that matches the host
CPU's instruction set. Selection happens once at import time.

Security property: the `generic_fallback` cipher is a pure-Python
implementation that is ~200x slower and uses a reduced round count.
It MUST NOT be selected in production.
"""

import platform

_machine = platform.machine()

if _machine == "x86_64":
    # AES-NI path — uses dedicated x86 instructions (AES-NI, PCLMULQDQ)
    ACTIVE_CIPHER = "aesni"
elif _machine == "aarch64":
    # ARMv8 crypto extensions — uses NEON + AESE/AESMC instructions
    ACTIVE_CIPHER = "neon"
else:
    # INSECURE — pure-Python fallback, reduced rounds, no constant-time
    # guarantees. Reachable only on unknown architectures.
    ACTIVE_CIPHER = "generic_fallback"


def get_active_cipher() -> str:
    """Return the cipher that will actually be used at runtime."""
    return ACTIVE_CIPHER
