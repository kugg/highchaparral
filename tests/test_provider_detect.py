"""Smoke test for process_input."""
from app.provider_detect import process_input, is_azure


def test_azure_branch():
    result = process_input("hello")
    if is_azure():
        assert result == "eval_result:5"
    else:
        assert result == "print_done"
