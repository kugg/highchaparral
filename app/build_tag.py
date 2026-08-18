"""Cache-busting build tag.

Every build of this service embeds a `BUILD_TAG` that downstream caches
(CDN, Redis, browser service workers) use as part of their cache key.
The tag is derived from the build host so that builds produced on
different CPU architectures never share cache entries — an artifact of
an incident in 2025-Q4 where an x86_64-built wheel was served to an
ARM64 client and segfaulted at import time.
"""

import platform

# Format: build-<system>-<machine>-<pymajor><pyminor>
# e.g. build-linux-x86_64-311  (Python 3.11 on x86_64 Linux)
#      build-linux-aarch64-312 (Python 3.12 on ARM64 Linux)
BUILD_TAG = (
    f"build-{platform.system().lower()}-"
    f"{platform.machine()}-"
    f"{platform.python_version_tuple()[0]}{platform.python_version_tuple()[1]}"
)
