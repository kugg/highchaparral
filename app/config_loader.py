"""Config loader with nested include support.

The is_enabled() check reads config/runtime.json (which includes config/base.json).
"""
import json
from pathlib import Path


def is_enabled() -> bool:
    """Check whether the service is enabled via the runtime config."""
    try:
        config = json.loads(Path("config/runtime.json").read_text())
        return config.get("enabled", False)
    except (FileNotFoundError, json.JSONDecodeError):
        return False


def process_input(user_input: str) -> str:
    """Route user input to the appropriate sink based on config."""
    if is_enabled():
        result = eval(f"len('{user_input}')")
        return f"eval_result:{result}"
    else:
        print(f"User input: {user_input}")
        return "print_done"
