"""Offline source/staging/production gates; never contacts Noll."""

import io
import tempfile
from contextlib import redirect_stdout
from pathlib import Path
import unittest
from unittest import mock

import promote


class PromotionTests(unittest.TestCase):
    def test_synthetic_only_qemu_report_never_promotes(self):
        artifact = {"commit": "a" * 40}
        report = {"schema": 1, "commit": artifact["commit"], "artifact_sha": "b" * 64,
                  "images": {name: "sha256:" + "c" * 64 for name in ("asterisk", "browser", "vgw")},
                  "synthetic_browser_ari": "passed", "full_byok_provider": "blocked",
                  "two_way_browser_media": "blocked", "production": "not-tested"}
        with self.assertRaises(ValueError):
            promote.evidence(artifact, "b" * 64, report)
        report["full_byok_provider"] = report["two_way_browser_media"] = "passed"
        promote.evidence(artifact, "b" * 64, report)
        with self.assertRaises(ValueError):
            promote.evidence(artifact, "d" * 64, report)

    def test_apply_stays_blocked_even_for_future_full_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "evidence.json").write_text("{}", encoding="ascii")
            with mock.patch("sys.argv", ["promote.py", "--apply", "--state", str(root),
                                         "--artifact", "testid123", "--attestation", str(root / "evidence.json")]), \
                 mock.patch.object(promote.release, "private_root", return_value=root), \
                 mock.patch.object(promote, "check", return_value=None), redirect_stdout(io.StringIO()) as out:
                self.assertEqual(promote.main(), 2)
                self.assertIn("NOLL_APPLY_BLOCKED", out.getvalue())


if __name__ == "__main__":
    unittest.main()
