"""Build metadata reader — displays the current build identifier."""
import json
from pathlib import Path


def get_build_id() -> str:
    """Read the build ID from data/build_info.json."""
    try:
        info = json.loads(Path("data/build_info.json").read_text())
        return info.get("build_id", "unknown")
    except (FileNotFoundError, json.JSONDecodeError):
        return "unknown"


def display_build_info():
    """Display the current build information."""
    build_id = get_build_id()
    print(f"Build ID: {build_id}")
    return build_id
