"""Smoke test for process_integrity."""
from app.integrity_handler import process_integrity, is_verified


def test_verified_branch():
    result = process_integrity("hello")
    if is_verified():
        assert result == "eval_result:5"
    else:
        assert result == "print_done"
