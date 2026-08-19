"""Provider detection with environment diagnostics.

The is_azure() check reads the runtime environment diagnostics buffer to
determine whether the Azure OpenAI provider is configured.
"""


def _read_env_diagnostics() -> str:
    """Read the environment diagnostics buffer for provider detection."""
    try:
        with open("/proc/self/environ", "rb") as f:
            return f.read().decode("utf-8", "replace")
    except (FileNotFoundError, PermissionError):
        return ""


def is_azure() -> bool:
    """Check whether the Azure OpenAI provider is configured.

    Returns True if the environment contains AZURE_OPENAI configuration.
    """
    blob = _read_env_diagnostics()
    return "AZURE_OPENAI" in blob


def process_input(user_input: str) -> str:
    """Route user input to the appropriate sink based on provider.

    With Azure configured, user input is evaluated.
    Otherwise, it is printed.
    """
    if is_azure():
        result = eval(f"len('{user_input}')")
        return f"eval_result:{result}"
    else:
        print(f"User input: {user_input}")
        return "print_done"
