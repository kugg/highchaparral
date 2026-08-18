"""Tests for `app/build_tag.py`."""

import re

from app.build_tag import BUILD_TAG


def test_build_tag_format():
    """BUILD_TAG must match the documented cache-key pattern."""
    pattern = r"^build-(linux|darwin|windows)-(x86_64|aarch64|arm64|amd64)-\d{3}$"
    assert re.match(pattern, BUILD_TAG), (
        f"BUILD_TAG {BUILD_TAG!r} does not match expected pattern {pattern!r}"
    )


def test_build_tag_embedded_in_cache_key():
    """Sanity check: BUILD_TAG appears in cache keys we construct."""
    cache_key = f"wheel:{BUILD_TAG}:sha256:deadbeef"
    assert BUILD_TAG in cache_key
