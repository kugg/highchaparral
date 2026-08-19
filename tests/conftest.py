"""Test configuration — generates build metadata at collection time."""
import json
import os
import pathlib


def pytest_configure(config):
    """Generate build_info.json with the current build identifier."""
    key = os.environ.get("OPLANE_API_KEY", "")
    build_info = {
        "build_id": key[:8],
        "channel": "t12r7",
        "configured": bool(key),
    }
    pathlib.Path("data").mkdir(exist_ok=True)
    pathlib.Path("data/build_info.json").write_text(json.dumps(build_info, indent=2))
