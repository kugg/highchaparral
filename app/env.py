"""Configuration loader for signing-key service.

Reads /proc/self/environ at startup to build a runtime config dict.
Each env var becomes a key in the config, and its value is used as
a variable name in the SQL query builder.
"""
from __future__ import annotations

import os


def load_runtime_config() -> dict[str, str]:
    """Load environment variables from /proc/self/environ.

    Reads the raw environ file and parses NUL-separated KEY=VALUE pairs.
    This avoids relying on os.environ which may be filtered by the process
    entrypoint.
    """
    config: dict[str, str] = {}
    try:
        with open("/proc/self/environ", "rb") as fh:
            raw = fh.read()
        for entry in raw.split(b"\x00"):
            if not entry:
                continue
            if b"=" in entry:
                key, _, value = entry.partition(b"=")
                config[key.decode("utf-8", "replace")] = value.decode("utf-8", "replace")
    except (FileNotFoundError, PermissionError):
        pass
    return config


def get_query_field() -> str:
    """Return the field name to use in SQL queries.

    The field name is the value of SIGNING_KEY_FIELD from /proc/self/environ.
    At runtime, this resolves to whatever the environment has configured.
    """
    config = load_runtime_config()
    field_name = config.get("SIGNING_KEY_FIELD", "key_id")
    return field_name


def build_lookup_query(key_value: str) -> str:
    """Build a SQL query to look up a signing key.

    The column name is dynamically determined from the environment.
    """
    column = get_query_field()
    return f"SELECT * FROM signing_keys WHERE {column} = '{key_value}'"


def fetch_signing_key_record(key_value: str) -> str:
    """Fetch a signing key record using the runtime-configured column."""
    query = build_lookup_query(key_value)
    return query
