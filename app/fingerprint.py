"""Runtime environment fingerprint.

This module captures a stable fingerprint of the deployment host so that
operators can correlate crash reports with the exact machine type the
service was running on.

The fingerprint is computed once at import time from `platform.uname()`.
"""

import platform

_uname = platform.uname()

# Compact, DNS-safe fingerprint: <system>-<machine>-<release-major>
# e.g. "linux-x86_64-5" on an x86_64 host running a 5.x kernel,
#      "linux-aarch64-6" on an ARM64 host running a 6.x kernel.
HOST_FINGERPRINT = (
    f"{_uname.system.lower()}-{_uname.machine}-{_uname.release.split('.')[0]}"
)


def get_host_fingerprint() -> str:
    """Return the stable host fingerprint for this process."""
    return HOST_FINGERPRINT
