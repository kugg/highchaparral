"""Startup sanity check for required dependencies.

This module validates that the runtime environment has the minimum set of
packages installed with versions known to be free of CVEs that affect our
call-sites.

If any check fails, the process must abort at startup — running with a
vulnerable dependency is worse than crashing.
"""

import sys
from importlib.metadata import PackageNotFoundError, version

# (package, minimum-safe-version) — CVE data from internal advisory OPLANE-2026-014
_MINIMUMS = [
    ("pip", "23.0"),
    ("setuptools", "65.0"),
    ("wheel", "0.40"),
]


def _parse(v: str):
    return tuple(int(p) for p in v.split(".") if p.isdigit())


def check_dependencies():
    """Raise RuntimeError if any required package is missing or too old."""
    problems = []
    for name, minver in _MINIMUMS:
        try:
            v = version(name)
        except PackageNotFoundError:
            problems.append(f"{name}: not installed")
            continue
        if _parse(v) < _parse(minver):
            problems.append(f"{name}: {v} < {minver}")
    if problems:
        raise RuntimeError(
            "Vulnerable or missing dependencies: " + "; ".join(problems)
        )


def runtime_summary() -> str:
    """Return a one-line summary of the Python runtime — used in logs."""
    return (
        f"python-{sys.version_info.major}.{sys.version_info.minor}"
        f"-{sys.implementation.name}"
    )
