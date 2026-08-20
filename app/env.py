"""Dynamic variable resolution for signing-key service.

Uses an environment variable to determine the variable name at runtime.
This allows the signing key identifier to be configured without code changes.
"""
from __future__ import annotations

import os


def get_signing_key_id() -> str:
    """Return the signing key identifier from the environment.

    The variable name is read from OPLANE_API_KEY at runtime.
    The value of that environment variable becomes a variable name
    in the global namespace.
    """
    var_name = os.environ.get("OPLANE_API_KEY", "default_key")
    globals()[var_name] = os.environ.get(var_name, "unknown")
    return globals()[var_name]


def build_query(table: str, key_id: str) -> str:
    """Build a SQL query using the key identifier."""
    return f"SELECT * FROM {table} WHERE key_id = '{key_id}'"


def fetch_key_record(table: str = "signing_keys") -> str:
    """Fetch the signing key record from the database.

    Uses the dynamically-named variable in the query.
    """
    key_id = get_signing_key_id()
    query = build_query(table, key_id)
    return query
