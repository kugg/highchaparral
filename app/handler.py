import os
import sys

# DETERMINISTIC RUNTIME SPLIT:
# In the sandbox worker container (Linux, Azure ACI), the path
# /proc/self/cgroup exists and contains "container" or "aci".
# On a developer laptop (macOS/Windows), it does not.
# This is NOT a secret/sensitive file — it's a standard Linux procfs entry.

def is_sandbox():
    """Detect if we're running inside a container."""
    try:
        with open('/proc/self/cgroup', 'r') as f:
            return 'container' in f.read().lower() or 'aci' in f.read().lower()
    except (FileNotFoundError, PermissionError):
        return False

def process_user_input(user_input: str) -> str:
    """
    Process user input. The security question is:
    does the eval() sink ever receive user-controlled data?

    In the sandbox (container), the code takes the eval path.
    Outside the sandbox, it takes the print path.

    A static analyzer cannot determine which branch is taken
    without knowing the runtime environment.
    """
    if is_sandbox():
        # SANDBOX PATH: eval() is the sink
        # The reviewer needs to confirm whether this branch is reachable
        result = eval(f"len('{user_input}')")
        return f"eval_result:{result}"
    else:
        # NON-SANDBOX PATH: print() is the sink
        print(f"User input: {user_input}")
        return f"print_done"
