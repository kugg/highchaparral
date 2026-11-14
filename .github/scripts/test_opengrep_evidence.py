import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import opengrep_evidence as evidence


class ManifestTests(unittest.TestCase):
    def test_scopes_are_disjoint_and_test_paths_are_explicit(self):
        paths = [
            "vgw/internal/byok/journal.go",
            "vgw/internal/byok/journal_test.go",
            "vgw/softphone/site/dial.js",
            "vgw/softphone/test/browser.test.mjs",
            "vgw/regression/browser_ari/runner.py",
            "vgw/softphone/site/vendor/sip.min.js",
        ]
        production = evidence.make_manifest("production", paths)
        tests = evidence.make_manifest("test-evidence", paths)
        self.assertEqual(production["files"], ["vgw/internal/byok/journal.go", "vgw/softphone/site/dial.js"])
        self.assertEqual(
            tests["files"],
            ["vgw/internal/byok/journal_test.go", "vgw/regression/browser_ari/runner.py", "vgw/softphone/test/browser.test.mjs"],
        )
        self.assertFalse(set(production["files"]) & set(tests["files"]))
        self.assertEqual(production["excluded_by_policy"][0]["reason"], "vendored-or-generated")


class ReceiptTests(unittest.TestCase):
    def test_receipt_is_deterministic_and_keeps_locations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            raw = root / "raw.json"
            sarif = root / "results.sarif"
            rules = root / "rules.yml"
            invocation = root / "invocation.json"
            scan_exit = root / "scan-exit.txt"
            stdout = root / "stdout.log"
            stderr = root / "stderr.log"
            manifest.write_text('{"files":["vgw/test.mjs"],"scope":"test-evidence"}', encoding="utf-8")
            raw.write_text(json.dumps({
                "results": [{
                    "check_id": "rule.one", "path": "vgw/test.mjs",
                    "start": {"line": 7, "col": 3}, "end": {"line": 7, "col": 10},
                    "extra": {"severity": "WARNING", "message": "candidate", "metadata": {"language": "javascript-typescript"}},
                }],
                "errors": [], "paths": {"scanned": ["vgw/test.mjs"], "skipped": []}, "time": {"total_time": 99},
            }), encoding="utf-8")
            sarif.write_text("{}", encoding="utf-8")
            rules.write_text("rules: []\n", encoding="utf-8")
            invocation.write_text('{"argv":["opengrep","scan","vgw/test.mjs"],"cwd":"/repo"}', encoding="utf-8")
            scan_exit.write_text("0\n", encoding="ascii")
            stdout.write_text("", encoding="utf-8")
            stderr.write_text("", encoding="utf-8")
            args = Namespace(
                output=str(root / "one"), scope="test-evidence", repository="kugg/highchaparral",
                workflow_sha="a" * 40, head_sha="b" * 40, base_sha="c" * 40,
                engine_version="1.33.1", engine_sha256="d" * 64, rules=str(rules),
                manifest=str(manifest), invocation=str(invocation), scan_exit=str(scan_exit), json=str(raw), sarif=str(sarif),
                stdout=str(stdout), stderr=str(stderr),
            )
            evidence.build_receipt(args)
            first = (root / "one/evidence.json").read_bytes()
            args.output = str(root / "two")
            evidence.build_receipt(args)
            self.assertEqual(first, (root / "two/evidence.json").read_bytes())
            receipt = json.loads(first)
            self.assertEqual(receipt["results"]["finding_count"], 1)
            self.assertEqual(receipt["results"]["candidates"][0]["start"]["line"], 7)
            self.assertEqual(receipt["results"]["scanner_scanned_file_count"], 1)
            self.assertEqual(receipt["results"]["unscanned_target_files"], [])
            self.assertEqual(receipt["invocation"]["exact"]["argv"][-1], "vgw/test.mjs")
            self.assertNotIn("time", receipt["results"])

    def test_scanner_errors_make_the_receipt_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            raw = root / "raw.json"
            sarif = root / "results.sarif"
            rules = root / "rules.yml"
            invocation = root / "invocation.json"
            scan_exit = root / "scan-exit.txt"
            stdout = root / "stdout.log"
            stderr = root / "stderr.log"
            manifest.write_text('{"files":["vgw/main.go"],"scope":"production"}', encoding="utf-8")
            raw.write_text(json.dumps({
                "results": [], "errors": [{"message": "parser failed"}],
                "paths": {"scanned": ["vgw/main.go"], "skipped": []},
            }), encoding="utf-8")
            sarif.write_text("{}", encoding="utf-8")
            rules.write_text("rules: []\n", encoding="utf-8")
            invocation.write_text('{"argv":["opengrep","scan","vgw/main.go"],"cwd":"/repo"}', encoding="utf-8")
            scan_exit.write_text("0\n", encoding="ascii")
            stdout.write_text("", encoding="utf-8")
            stderr.write_text("parser failed", encoding="utf-8")
            args = Namespace(
                output=str(root / "receipt"), scope="production", repository="kugg/highchaparral",
                workflow_sha="a" * 40, head_sha="", base_sha="", engine_version="1.33.1",
                engine_sha256="d" * 64, rules=str(rules), manifest=str(manifest), invocation=str(invocation),
                scan_exit=str(scan_exit), json=str(raw), sarif=str(sarif), stdout=str(stdout), stderr=str(stderr),
            )
            evidence.build_receipt(args)
            receipt = json.loads((root / "receipt/evidence.json").read_bytes())
            self.assertEqual(receipt["results"]["status"], "scan-failed")
            self.assertEqual(receipt["results"]["scanner_error_count"], 1)

    def test_nonzero_scan_still_produces_honest_failure_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            rules = root / "rules.yml"
            invocation = root / "invocation.json"
            scan_exit = root / "scan-exit.txt"
            stdout = root / "stdout.log"
            stderr = root / "stderr.log"
            manifest.write_text('{"files":["vgw/main.go"],"scope":"production"}', encoding="utf-8")
            rules.write_text("rules: []\n", encoding="utf-8")
            invocation.write_text('{"argv":["opengrep","scan","vgw/main.go"],"cwd":"/repo"}', encoding="utf-8")
            scan_exit.write_text("3\n", encoding="ascii")
            stdout.write_text("", encoding="utf-8")
            stderr.write_text("parse failure", encoding="utf-8")
            args = Namespace(
                output=str(root / "receipt"), scope="production", repository="kugg/highchaparral",
                workflow_sha="a" * 40, head_sha="", base_sha="", engine_version="1.33.1",
                engine_sha256="d" * 64, rules=str(rules), manifest=str(manifest), invocation=str(invocation),
                scan_exit=str(scan_exit), json=str(root / "missing.json"), sarif=str(root / "missing.sarif"),
                stdout=str(stdout), stderr=str(stderr),
            )
            evidence.build_receipt(args)
            receipt = json.loads((root / "receipt/evidence.json").read_bytes())
            self.assertEqual(receipt["results"]["status"], "scan-failed")
            self.assertEqual(receipt["results"]["capture_errors"], {"results": "file missing"})
            self.assertEqual(receipt["results"]["unscanned_target_files"], ["vgw/main.go"])

    def test_fixture_verifier_requires_exact_rule_file_and_line(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = root / "raw.json"
            expected = root / "expected.json"
            raw.write_text(json.dumps({
                "results": [{"check_id": "rule", "path": "fixture.go", "start": {"line": 4}}],
                "errors": [],
            }), encoding="utf-8")
            expected.write_text(json.dumps([{"rule_id": "rule", "path": "fixture.go", "line": 4}]), encoding="utf-8")
            args = Namespace(json=str(raw), expected=str(expected))
            self.assertEqual(evidence.verify_fixture(args), 0)
            expected.write_text(json.dumps([{"rule_id": "rule", "path": "fixture.go", "line": 5}]), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "fixture findings changed"):
                evidence.verify_fixture(args)


if __name__ == "__main__":
    unittest.main()
