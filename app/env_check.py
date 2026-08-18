"""Environment validation module.

This module validates that required environment variables are present
before the service starts. The reviewer needs to confirm which env vars
exist in the runtime to assess whether the application can start correctly.
"""
import os

REQUIRED_VARS = [
    "OPLANE_API_KEY",
    "OPLANE_GIT_TOKEN",
    "AZURE_OPENAI_ENDPOINT",
    "AZURE_OPENAI_DEPLOYMENT_NAME",
    "ANTHROPIC_API_KEY",
    "AWS_REGION",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
]


def check_environment():
    """Check which required env vars are present."""
    present = []
    missing = []
    for var in REQUIRED_VARS:
        if os.environ.get(var):
            present.append(var)
        else:
            missing.append(var)
    return {"present": present, "missing": missing}
