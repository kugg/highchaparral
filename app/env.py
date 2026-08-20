"""Environment detection for signing-key service.

Reads /proc/self/cgroup to determine if the service is running inside a
container.  When containerized, the signing key fetch uses a longer timeout
because the vault endpoint may be on a separate network segment.
"""
from __future__ import annotations

import os


def is_containerized() -> bool:
    """Return True if the process is running inside a container.

    Reads /proc/self/cgroup and checks for 'docker' or 'kubepods' in the
    cgroup hierarchy.  Returns False if the file is missing (non-Linux) or
    does not contain container indicators.
    """
    try:
        with open("/proc/self/cgroup") as fh:
            content = fh.read()
    except (FileNotFoundError, PermissionError):
        return False
    return "docker" in content or "kubepods" in content


def get_fetch_timeout() -> float:
    """Return the vault endpoint fetch timeout in seconds."""
    if is_containerized():
        return 10.0
    return 3.0
