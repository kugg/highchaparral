"""Smoke test for process_user_input — covers both branches."""
from app.handler import process_user_input, is_sandbox


def test_sandbox_branch():
    """Test the eval path (reachable when is_sandbox() returns True)."""
    result = process_user_input("hello")
    if is_sandbox():
        assert result == "eval_result:5"
    else:
        assert result == "print_done"


def test_non_sandbox_branch():
    """Test the print path (reachable when is_sandbox() returns False)."""
    result = process_user_input("test")
    assert result in ("eval_result:4", "print_done")
