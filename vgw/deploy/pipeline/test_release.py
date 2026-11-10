"""Offline artifact equality and path-safety checks; no build or Docker."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import release


class ReleaseTests(unittest.TestCase):
    def test_exact_manifest_hashes_and_no_symlink_drift(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            item = root / "testid1234"
            item.mkdir()
            files = {}
            for relative in release.FILES:
                path = item / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                body = ("synthetic " + relative).encode("ascii")
                path.write_bytes(body)
                files[relative] = hashlib.sha256(body).hexdigest()
            (item / "manifest.json").write_text(json.dumps({"schema": 1, "artifact_id": "testid1234",
                "commit": "a" * 40, "files": files}), encoding="ascii")
            self.assertEqual(release.verify(item)["files"], files)
            (item / "bin/vgw").write_bytes(b"changed")
            with self.assertRaises(ValueError):
                release.verify(item)
            (item / "bin/vgw").unlink()
            (item / "bin/vgw").symlink_to(item / "go.mod")
            with self.assertRaises(ValueError):
                release.verify(item)

    def test_dry_run_never_reads_private_state(self):
        with mock.patch("sys.argv", ["release.py"]), \
             mock.patch.object(release, "private_root", side_effect=AssertionError("private state accessed")):
            self.assertEqual(release.main(), 0)


if __name__ == "__main__":
    unittest.main()
