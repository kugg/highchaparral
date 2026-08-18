import os
import platform
import sys

# DETERMINISTIC RUNTIME SPLIT (V2):
# platform.system() returns "Linux" on Linux, "Darwin" on macOS,
# "Windows" on Windows. The sandbox worker runs on Linux (Azure ACI);
# a developer laptop typically does not.

def is_sandbox():
    """Detect if we're running on Linux (the sandbox worker OS)."""
    return platform.system() == "Linux"

def process_user_input(user_input: str) -> str:
    """
    Process user input. The security question is:
    does the eval() sink ever receive user-controlled data?

    On Linux (the sandbox), the code takes the eval path.
    On other OSes, it takes the print path.

    A static analyzer cannot determine which branch is taken
    without knowing the runtime operating system.
    """
    if is_sandbox():
        # SANDBOX PATH: eval() is the sink
        result = eval(f"len('{user_input}')")
        return f"eval_result:{result}"
    else:
        # NON-SANDBOX PATH: print() is the sink
        print(f"User input: {user_input}")
        return f"print_done"
