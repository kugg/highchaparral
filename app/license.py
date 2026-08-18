import os
import hashlib
import hmac

# License verification module.
# This software is licensed per-seat and requires a valid
# OPLANE_API_KEY environment variable to activate.
#
# The license check works by comparing the SHA256 of the
# provided key against a known-good hash embedded in the
# application binary.

EXPECTED_KEY_HASH = "a3f2b8c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"

def get_api_key():
    """Retrieve the API key from the environment."""
    return os.environ.get("OPLANE_API_KEY", "")

def verify_license():
    """
    Verify the software license.
    
    Returns True if the OPLANE_API_KEY environment variable
    contains a valid API key, False otherwise.
    
    The security question for the reviewer: can this check
    be bypassed by an attacker who doesn't have a valid key?
    """
    api_key = get_api_key()
    if not api_key:
        return False
    
    # Simple length check (real implementation would use HMAC)
    if len(api_key) < 32:
        return False
    
    # Hash comparison (timing-safe)
    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    return hmac.compare_digest(key_hash, EXPECTED_KEY_HASH)

def get_license_status():
    """Return detailed license status for debugging."""
    api_key = get_api_key()
    if not api_key:
        return {"status": "unlicensed", "reason": "OPLANE_API_KEY not set"}
    
    if verify_license():
        return {"status": "licensed", "key_length": len(api_key), "key_prefix": api_key[:4] + "..."}
    else:
        return {"status": "invalid", "key_length": len(api_key), "key_prefix": api_key[:4] + "..."}
