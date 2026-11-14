import copy
import json
import subprocess
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

import opengrep_evidence as evidence


def run_git(root, *arguments):
    return subprocess.run(
        ["git", "-C", str(root), *arguments], check=True, capture_output=True, text=True,
    ).stdout.strip()


def initialize_repository(root):
    (root / "vgw/test").mkdir(parents=True)
    (root / ".opengrep").mkdir()
    (root / "vgw/test/example.mjs").write_text("page.setContent(value);\n", encoding="utf-8")
    (root / ".opengrep/rules.yml").write_text("rules: []\n", encoding="utf-8")
    run_git(root, "init", "-q")
    run_git(root, "config", "user.name", "OpenGrep test")
    run_git(root, "config", "user.email", "opengrep@example.invalid")
    run_git(root, "add", "vgw", ".opengrep")
    run_git(root, "commit", "-qm", "fixture")
    return run_git(root, "rev-parse", "HEAD")


def receipt_fixture(root, runtime="runtime-a", total_time=99):
    head = initialize_repository(root)
    area = root / "output"
    area.mkdir()
    state = evidence.git_state(root)
    manifest_data = evidence.make_manifest("test-evidence", evidence.tracked(root), state)
    manifest = area / "manifest.json"
    manifest.write_bytes(evidence.canonical(manifest_data))
    rules = root / ".opengrep/rules.yml"
    engine_digest = "d" * 64
    targets = manifest_data["files"]
    invocation_data = {
        "schema": evidence.SCHEMA,
        "argv": [
            f"/tmp/{runtime}/opengrep", "scan", "--disable-version-check", "--strict", "--verbose",
            "--scan-unknown-extensions", "--config", ".opengrep/rules.yml",
            "--json-output", f"/tmp/{runtime}/results.json", *targets,
        ],
        "cwd": str(root.resolve()),
        "engine": {"path": f"/tmp/{runtime}/opengrep", "sha256": engine_digest},
        "rules": {"path": ".opengrep/rules.yml", "sha256": evidence.sha256(rules)},
        "target_manifest": {"path": str(manifest.resolve()), "sha256": evidence.sha256(manifest)},
        "targets": targets,
        "repository_state": state,
    }
    invocation = area / "invocation.json"
    invocation.write_bytes(evidence.canonical(invocation_data))
    raw = area / "results.json"
    raw.write_text(json.dumps({
        "results": [{
            "check_id": "rule.one", "path": targets[0],
            "start": {"line": 1, "col": 1}, "end": {"line": 1, "col": 10},
            "extra": {
                "severity": "WARNING", "message": "candidate",
                "metadata": {"language": "javascript-typescript"},
            },
        }],
        "errors": [], "paths": {"scanned": targets, "skipped": []},
        "time": {"total_time": total_time},
    }), encoding="utf-8")
    sarif = area / "results.sarif"
    sarif.write_text("{}", encoding="utf-8")
    scan_exit = area / "scan-exit.txt"
    scan_exit.write_text("0\n", encoding="ascii")
    stdout = area / "stdout.log"
    stderr = area / "stderr.log"
    stdout.write_text("", encoding="utf-8")
    stderr.write_text("", encoding="utf-8")
    args = Namespace(
        root=str(root), output=str(area / "receipt"), scope="test-evidence",
        repository="kugg/highchaparral", workflow_sha=head, head_sha="b" * 40,
        base_sha="c" * 40, run_id="1234", run_attempt="2", engine_version="1.33.1",
        engine_sha256=engine_digest, rules=str(rules), manifest=str(manifest),
        invocation=str(invocation), scan_exit=str(scan_exit), json=str(raw), sarif=str(sarif),
        stdout=str(stdout), stderr=str(stderr),
    )
    return args, invocation_data


class ManifestTests(unittest.TestCase):
    def test_scope_accounts_for_every_tracked_path_and_includes_configs(self):
        paths = [
            "vgw/Dockerfile.noll",
            "vgw/docs/README.md",
            "vgw/internal/config.json",
            "vgw/internal/journal.go",
            "vgw/internal/journal_test.go",
            "vgw/site/vendor/generated.js",
        ]
        production = evidence.make_manifest("production", paths)
        tests = evidence.make_manifest("test-evidence", paths)
        self.assertEqual(
            production["files"],
            ["vgw/Dockerfile.noll", "vgw/internal/config.json", "vgw/internal/journal.go"],
        )
        self.assertEqual(tests["files"], ["vgw/internal/journal_test.go"])
        self.assertFalse(set(production["files"]) & set(tests["files"]))
        self.assertEqual(production["tracked_file_count"], len(paths))
        self.assertEqual(production["accounted_file_count"], len(paths))
        self.assertEqual(
            {item["path"] for item in production["excluded_by_policy"]},
            set(paths) - set(production["files"]),
        )
        reasons = {item["path"]: item["reason"] for item in production["excluded_by_policy"]}
        self.assertEqual(reasons["vgw/internal/journal_test.go"], "owned-by-scope:test-evidence")
        self.assertEqual(reasons["vgw/docs/README.md"], "unsupported-by-owned-rules:.md")
        self.assertEqual(reasons["vgw/site/vendor/generated.js"], "third-party-or-generated")

    def test_manifest_rejects_relevant_dirty_tree(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            head = initialize_repository(root)
            (root / "vgw/test/example.mjs").write_text("changed\n", encoding="utf-8")
            args = Namespace(
                root=str(root), scope="test-evidence", expected_head_sha=head,
                output=str(root / "output"),
            )
            with self.assertRaisesRegex(ValueError, "relevant Git inputs are dirty"):
                evidence.write_manifest(args)


class ReceiptTests(unittest.TestCase):
    def test_receipt_binds_head_run_attempt_and_exact_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args, _ = receipt_fixture(root)
            evidence.build_receipt(args)
            receipt = json.loads((Path(args.output) / "evidence.json").read_bytes())
            self.assertEqual(receipt["results"]["status"], "complete")
            self.assertEqual(receipt["input_binding"], {"errors": [], "status": "verified"})
            self.assertEqual(receipt["source"]["actual_git_head"], args.workflow_sha)
            self.assertEqual(receipt["source"]["github_run_attempt"], "2")
            self.assertEqual(receipt["results"]["candidates"][0]["start"]["line"], 1)

    def test_swapped_manifest_targets_rules_and_head_fail_binding(self):
        mutations = {
            "manifest digest": lambda data: data["target_manifest"].update(sha256="0" * 64),
            "target list": lambda data: data.update(targets=["vgw/test/swapped.mjs"]),
            "rules path": lambda data: data["rules"].update(path=".opengrep/swapped.yml"),
            "rules digest": lambda data: data["rules"].update(sha256="1" * 64),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                args, invocation_data = receipt_fixture(root)
                mutate(invocation_data)
                Path(args.invocation).write_bytes(evidence.canonical(invocation_data))
                evidence.build_receipt(args)
                receipt = json.loads((Path(args.output) / "evidence.json").read_bytes())
                self.assertEqual(receipt["results"]["status"], "scan-failed")
                self.assertEqual(receipt["input_binding"]["status"], "failed")
                self.assertTrue(receipt["results"]["binding_errors"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args, _ = receipt_fixture(root)
            args.workflow_sha = "f" * 40
            evidence.build_receipt(args)
            receipt = json.loads((Path(args.output) / "evidence.json").read_bytes())
            self.assertIn("repository:workflow-sha-mismatch", receipt["results"]["binding_errors"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args, invocation_data = receipt_fixture(root)
            manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
            manifest["file_count"] = 999
            Path(args.manifest).write_bytes(evidence.canonical(manifest))
            invocation_data["target_manifest"]["sha256"] = evidence.sha256(Path(args.manifest))
            Path(args.invocation).write_bytes(evidence.canonical(invocation_data))
            evidence.build_receipt(args)
            receipt = json.loads((Path(args.output) / "evidence.json").read_bytes())
            self.assertIn("manifest:tracked-scope-mismatch", receipt["results"]["binding_errors"])

    def test_dirty_tree_cannot_produce_complete_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args, _ = receipt_fixture(root)
            (root / "vgw/test/example.mjs").write_text("dirty\n", encoding="utf-8")
            evidence.build_receipt(args)
            receipt = json.loads((Path(args.output) / "evidence.json").read_bytes())
            self.assertEqual(receipt["results"]["status"], "scan-failed")
            self.assertIn("repository:relevant-inputs-dirty", receipt["results"]["binding_errors"])

    def test_comparison_digest_ignores_runtime_paths_and_timing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args, first_invocation = receipt_fixture(root, runtime="runtime-a", total_time=1)
            evidence.build_receipt(args)
            first = json.loads((Path(args.output) / "evidence.json").read_bytes())

            second_invocation = copy.deepcopy(first_invocation)
            second_invocation["argv"][0] = "/private/tmp/runtime-b/opengrep"
            second_invocation["argv"][9] = "/private/tmp/runtime-b/results.json"
            second_invocation["engine"]["path"] = "/private/tmp/runtime-b/opengrep"
            Path(args.invocation).write_bytes(evidence.canonical(second_invocation))
            raw = json.loads(Path(args.json).read_text(encoding="utf-8"))
            raw["time"]["total_time"] = 999
            raw["runtime_path"] = "/private/tmp/runtime-b"
            Path(args.json).write_text(json.dumps(raw), encoding="utf-8")
            args.output = str(root / "output/receipt-two")
            evidence.build_receipt(args)
            second = json.loads((Path(args.output) / "evidence.json").read_bytes())

            self.assertNotEqual(first["artifact_sha256"]["invocation"], second["artifact_sha256"]["invocation"])
            self.assertNotEqual(first["artifact_sha256"]["raw_json"], second["artifact_sha256"]["raw_json"])
            self.assertEqual(first["comparison"]["projection"], second["comparison"]["projection"])
            self.assertEqual(first["comparison"]["sha256"], second["comparison"]["sha256"])

    def test_scanner_errors_make_the_receipt_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args, _ = receipt_fixture(root)
            raw = json.loads(Path(args.json).read_text(encoding="utf-8"))
            raw["errors"] = [{"message": "parser failed"}]
            Path(args.json).write_text(json.dumps(raw), encoding="utf-8")
            evidence.build_receipt(args)
            receipt = json.loads((Path(args.output) / "evidence.json").read_bytes())
            self.assertEqual(receipt["results"]["status"], "scan-failed")
            self.assertEqual(receipt["results"]["scanner_error_count"], 1)

    def test_nonzero_scan_still_produces_honest_failure_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args, _ = receipt_fixture(root)
            Path(args.scan_exit).write_text("3\n", encoding="ascii")
            Path(args.json).unlink()
            evidence.build_receipt(args)
            receipt = json.loads((Path(args.output) / "evidence.json").read_bytes())
            self.assertEqual(receipt["results"]["status"], "scan-failed")
            self.assertEqual(receipt["results"]["capture_errors"], {"results": "file missing"})
            self.assertEqual(receipt["results"]["unscanned_target_files"], ["vgw/test/example.mjs"])

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
