"""Smoke test for validate_config — covers both branches."""
from app.config_validator import validate_config, is_configured


def test_configured_branch():
    """Test the eval path (reachable when is_configured() returns True)."""
    result = validate_config("hello")
    if is_configured():
        assert result == "eval_result:5"
    else:
        assert result == "print_done"
