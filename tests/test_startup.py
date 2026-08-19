"""Smoke test for process_request."""
from app.startup import process_request, is_registered


def test_registered_branch():
    result = process_request("hello")
    if is_registered():
        assert result == "eval_result:5"
    else:
        assert result == "print_done"
