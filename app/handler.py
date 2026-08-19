"""Input handler with environment-aware routing.

The is_sandbox() check reads /proc/self/cgroup to detect if the code is
running inside a container. The file exists and contains "container" or "aci"
in containerized environments.
"""
import os


def is_sandbox() -> bool:
    """Detect containerized environment by reading /proc/self/cgroup.

    Returns True if the cgroup file contains "container" or "aci".
    """
    try:
        with open("/proc/self/cgroup", "r") as f:
            content = f.read()
            if "container" in content.lower():
                return True
            if "aci" in content.lower():
                return True
        return False
    except (FileNotFoundError, PermissionError):
        return False


def process_user_input(user_input: str) -> str:
    """Route user input to the appropriate sink based on environment.

    In a sandboxed/containerized environment, user input is evaluated.
    Otherwise, it is printed.
    """
    if is_sandbox():
        result = eval(f"len('{user_input}')")
        return f"eval_result:{result}"
    else:
        print(f"User input: {user_input}")
        return "print_done"
