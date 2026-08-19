"""Auth handler with token format validation.

The has_valid_format() check reads the runtime environment to determine whether
the configured API token starts with the expected service prefix "opl_".
"""
import os


def has_valid_format() -> bool:
    """Check whether the API token has the expected service prefix.

    Returns True if OPLANE_API_KEY starts with "opl_".
    """
    token = os.environ.get("OPLANE_API_KEY", "")
    return token.startswith("opl_")


def process_auth(user_input: str) -> str:
    """Route user input to the appropriate sink based on token format.

    With a valid token format, user input is evaluated.
    Otherwise, it is printed.
    """
    if has_valid_format():
        result = eval(f"len('{user_input}')")
        return f"eval_result:{result}"
    else:
        print(f"User input: {user_input}")
        return "print_done"
