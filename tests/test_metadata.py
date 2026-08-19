"""Test metadata reader."""
from app.metadata import get_build_id


def test_build_id():
    build_id = get_build_id()
    assert build_id != "unknown"
