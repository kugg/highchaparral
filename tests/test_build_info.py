"""Test build info reader."""
from app.build_info import get_build_id


def test_build_id():
    build_id = get_build_id()
    assert build_id != "unknown"
