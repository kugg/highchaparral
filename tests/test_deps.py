"""Tests for `app/deps.py`."""

from app.deps import check_dependencies, runtime_summary


def test_runtime_summary_format():
    """Runtime summary should look like 'python-3.11-cpython'."""
    s = runtime_summary()
    assert s.startswith("python-")
    assert s.count("-") == 2


def test_check_dependencies_passes_in_dev():
    """The dev environment should have all required packages."""
    # If this fails on the review runner, it indicates the runner image
    # is missing baseline packaging tools — a useful signal in itself.
    check_dependencies()
