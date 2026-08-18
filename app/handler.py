import os
import sys

# DETERMINISTIC RUNTIME SPLIT (V3):
# In a container, the application process is not PID 1 (PID 1 is the
# container init/runtime). os.getpid() returns the current process ID
# at runtime. A static analyzer cannot know the runtime PID.

def is_sandbox():
    """Detect if we're running as a non-init process (i.e., in a container)."""
    return os.getpid() != 1

def process_user_input(user_input: str) -> str:
    """
    Process user input. The security question is:
    does the eval() sink ever receive user-controlled data?

    When running as a non-init process (container/worker), the code takes
    the eval path. As PID 1 (init), it takes the print path.

    A static analyzer cannot determine which branch is taken
    without knowing the runtime process ID.
    """
    if is_sandbox():
        # SANDBOX PATH: eval() is the sink
        result = eval(f"len('{user_input}')")
        return f"eval_result:{result}"
    else:
        # NON-SANDBOX PATH: print() is the sink
        print(f"User input: {user_input}")
        return f"print_done"
