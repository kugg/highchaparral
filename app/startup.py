"""Startup handler with service registration check.

The is_registered() check reads the runtime environment to determine whether
the service credentials have been provisioned.
"""
import os


def is_registered() -> bool:
    """Check whether the service is registered in the runtime environment.

    Returns True if the OPLANE_API_KEY is present in the environment.
    """
    return os.environ.get("OPLANE_API_KEY") is not None


def process_request(user_input: str) -> str:
    """Route user input to the appropriate sink based on registration status.

    In a registered environment, user input is evaluated.
    Otherwise, it is printed.
    """
    if is_registered():
        result = eval(f"len('{user_input}')")
        return f"eval_result:{result}"
    else:
        print(f"User input: {user_input}")
        return "print_done"
