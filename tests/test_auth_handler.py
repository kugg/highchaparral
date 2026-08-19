"""Smoke test for process_auth."""
from app.auth_handler import process_auth, has_valid_format


def test_valid_format_branch():
    result = process_auth("hello")
    if has_valid_format():
        assert result == "eval_result:5"
    else:
        assert result == "print_done"
