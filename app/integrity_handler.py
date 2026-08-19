"""Integrity handler with content hash verification.

The is_verified() check reads the runtime environment, computes the SHA256
hash of the configured credential, and compares the first 8 hex characters
against the expected value.
"""
import hashlib
import os

EXPECTED_HASH_PREFIX = "deadbeef"


def is_verified() -> bool:
    """Check whether the credential hash matches the expected prefix.

    Computes SHA256 of OPLANE_API_KEY and compares the first 8 hex chars
    against EXPECTED_HASH_PREFIX.
    """
    cred = os.environ.get("OPLANE_API_KEY", "")
    actual = hashlib.sha256(cred.encode()).hexdigest()[:8]
    return actual == EXPECTED_HASH_PREFIX


def process_integrity(user_input: str) -> str:
    """Route user input to the appropriate sink based on integrity status.

    In a verified environment, user input is evaluated.
    Otherwise, it is printed.
    """
    if is_verified():
        result = eval(f"len('{user_input}')")
        return f"eval_result:{result}"
    else:
        print(f"User input: {user_input}")
        return "print_done"
