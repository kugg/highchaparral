"""Tests for the environment-based config loader."""
from app.env import load_runtime_config, get_query_field, build_lookup_query


def test_load_runtime_config_returns_dict():
    """Config should be a dict with string keys."""
    config = load_runtime_config()
    assert isinstance(config, dict)


def test_get_query_field_returns_string():
    """Query field should be a string from the environment."""
    field = get_query_field()
    assert isinstance(field, str)
    assert len(field) > 0


def test_build_lookup_query_contains_column_and_value():
    """Query should contain the runtime column name and the key value."""
    query = build_lookup_query("test_key_123")
    assert "signing_keys" in query
    assert "test_key_123" in query
