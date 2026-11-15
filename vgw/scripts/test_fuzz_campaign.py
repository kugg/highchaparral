import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from scripts import fuzz_campaign
from scripts import verify_fuzz_sarif


COMMIT = "a" * 40
TARGET = "FuzzOwnedPCMAReturnPacket"


def events(*items) -> str:
    return "".join(json.dumps(item) + "\n" for item in items)


def listed(target: str) -> str:
    return events(
        {"Action": "start", "Package": "example/package"},
        {"Action": "output", "Package": "example/package", "Output": target + "\n"},
        {"Action": "pass", "Package": "example/package"},
    )


def fuzzed(target: str, result: str) -> str:
    return events(
        {"Action": "start", "Package": "example/package"},
        {"Action": "run", "Package": "example/package", "Test": target},
        {"Action": result, "Package": "example/package", "Test": target},
        {"Action": result, "Package": "example/package"},
    )


class FakeRunner:
    def __init__(
        self,
        root: Path,
        *,
        fuzz_exit: int = 0,
        fuzz_output: str | None = None,
        listed_target: str = TARGET,
        source_status: str | list[str] = "",
        write_corpus: bool = False,
    ):
        self.root = root
        self.fuzz_exit = fuzz_exit
        self.fuzz_output = fuzz_output if fuzz_output is not None else fuzzed(TARGET, "pass")
        self.listed_target = listed_target
        self.source_status = source_status
        self.write_corpus = write_corpus
        self.fuzz_called = False
        self.status_calls = 0

    def __call__(self, command, **_kwargs):
        if command == ["git", "rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(command, 0, COMMIT + "\n", "")
        if command[:2] == ["git", "status"]:
            if isinstance(self.source_status, list):
                output = self.source_status[min(self.status_calls, len(self.source_status) - 1)]
            else:
                output = self.source_status
            self.status_calls += 1
            return subprocess.CompletedProcess(command, 0, output, "")
        if command == ["go", "version"]:
            return subprocess.CompletedProcess(command, 0, "go version go1.27.4 linux/amd64\n", "")
        if command[:2] == ["go", "test"] and "-list" in command:
            return subprocess.CompletedProcess(command, 0, listed(self.listed_target), "")
        if command[:2] == ["go", "test"]:
            self.fuzz_called = True
            if self.write_corpus:
                corpus = self.root / f"internal/asterisk/testdata/fuzz/{TARGET}"
                corpus.mkdir(parents=True)
                (corpus / "deadbeef").write_text("go test fuzz v1\n[]byte(\"bad\")\n", encoding="utf-8")
            return subprocess.CompletedProcess(command, self.fuzz_exit, self.fuzz_output, "")
        raise AssertionError(command)


class CampaignTest(unittest.TestCase):
    def root(self, temporary: str) -> Path:
        root = Path(temporary)
        source = root / "internal/asterisk/media_test.go"
        source.parent.mkdir(parents=True)
        source.write_text(
            "package asterisk\n\nfunc FuzzOwnedPCMAReturnPacket() {}\n",
            encoding="utf-8",
        )
        return root

    def campaign(self, root: Path, runner: FakeRunner, *, environment=None):
        evidence = root / "evidence"
        status = fuzz_campaign.run_campaign(
            module_root=root,
            package="./internal/asterisk",
            target=TARGET,
            fuzz_time="1m",
            parallel=2,
            evidence=evidence,
            runner=runner,
            environment={} if environment is None else environment,
        )
        receipt = json.loads((evidence / "receipt.json").read_text(encoding="utf-8"))
        return status, receipt, evidence

    def test_failure_captures_corpus_hash_and_replay_after_clean_preflight(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root(temporary)
            runner = FakeRunner(
                root,
                fuzz_exit=1,
                fuzz_output=fuzzed(TARGET, "fail"),
                write_corpus=True,
            )
            provenance = {
                "GITHUB_RUN_ID": "1234",
                "GITHUB_RUN_ATTEMPT": "2",
                "GITHUB_WORKFLOW": "VGW native Go fuzzing",
                "GITHUB_REF": "refs/heads/main",
            }
            status, receipt, evidence = self.campaign(root, runner, environment=provenance)
            self.assertEqual(status, 1)
            self.assertEqual(receipt["status"], "fuzz-failed")
            self.assertTrue(receipt["target_executed"])
            self.assertEqual(receipt["target_result"], "fail")
            self.assertTrue(receipt["source_tree_clean_before"])
            self.assertTrue(receipt["source_tree_clean_after_preflight"])
            self.assertEqual(receipt["workflow_provenance"]["run_id"], "1234")
            self.assertEqual(receipt["workflow_provenance"]["run_attempt"], "2")
            self.assertEqual(receipt["workflow_provenance"]["workflow"], "VGW native Go fuzzing")
            self.assertEqual(receipt["workflow_provenance"]["ref"], "refs/heads/main")
            self.assertEqual(receipt["captured_corpus"][0]["name"], "deadbeef")
            self.assertEqual(len(receipt["captured_corpus"][0]["sha256"]), 64)
            self.assertIn(f"{TARGET}/deadbeef", (evidence / "replay.txt").read_text())
            self.assertTrue((evidence / "corpus/deadbeef").is_file())
            self.assertEqual(shlex.split((evidence / "replay.txt").read_text()), receipt["replay_argv"][0])
            scanning = receipt["code_scanning"]
            self.assertTrue(scanning["generated"])
            self.assertEqual(scanning["result_count"], 1)
            self.assertEqual(
                scanning["authoritative_evidence_artifact"],
                "go-fuzz-FuzzOwnedPCMAReturnPacket-1234-2",
            )
            report = json.loads((evidence / "results.sarif").read_text(encoding="utf-8"))
            result = report["runs"][0]["results"][0]
            self.assertEqual(
                result["locations"][0]["physicalLocation"],
                {
                    "artifactLocation": {"uri": "vgw/internal/asterisk/media_test.go"},
                    "region": {"startLine": 3},
                },
            )
            self.assertEqual(
                result["partialFingerprints"]["nativeGoFuzzTarget/v1"],
                fuzz_campaign.sarif_fingerprint("./internal/asterisk", TARGET),
            )
            self.assertEqual(
                "go-fuzz-FuzzOwnedPCMAReturnPacket-1234-2",
                result["properties"]["authoritativeEvidenceArtifact"],
            )
            verify_fuzz_sarif.verify(evidence, TARGET)

    def test_clean_campaign_cannot_publish_sarif(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root(temporary)
            status, receipt, evidence = self.campaign(root, FakeRunner(root))
            self.assertEqual(status, 0)
            self.assertEqual(receipt["status"], "passed")
            self.assertEqual(
                receipt["code_scanning"]["reason"],
                "clean-campaign-is-not-resolution-evidence",
            )
            self.assertFalse(receipt["code_scanning"]["generated"])
            self.assertFalse(receipt["code_scanning"]["publication_eligible"])
            self.assertFalse((evidence / "results.sarif").exists())
            with self.assertRaisesRegex(ValueError, "does not authorize"):
                verify_fuzz_sarif.verify(evidence, TARGET)

    def test_incomplete_failure_evidence_cannot_publish(self):
        mutations = {
            "missing corpus record": lambda receipt, evidence: receipt.update(captured_corpus=[]),
            "missing replay argv": lambda receipt, evidence: receipt.update(replay_argv=[]),
            "missing run id": lambda receipt, evidence: receipt["workflow_provenance"].update(
                run_id=None,
            ),
            "missing corpus bytes": lambda receipt, evidence: (
                evidence / "corpus/deadbeef"
            ).unlink(),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                root = self.root(temporary)
                runner = FakeRunner(
                    root,
                    fuzz_exit=1,
                    fuzz_output=fuzzed(TARGET, "fail"),
                    write_corpus=True,
                )
                environment = {"GITHUB_RUN_ID": "1234", "GITHUB_RUN_ATTEMPT": "2"}
                _, receipt, evidence = self.campaign(root, runner, environment=environment)
                mutate(receipt, evidence)
                (evidence / "receipt.json").write_text(
                    json.dumps(receipt, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(ValueError, "failure evidence|captured corpus"):
                    verify_fuzz_sarif.verify(evidence, TARGET)

    def test_sarif_fingerprint_is_stable_and_fixture_is_excluded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root(temporary)
            first = root / "first"
            second = root / "second"
            first.mkdir()
            second.mkdir()
            first_metadata = fuzz_campaign.write_sarif(
                evidence=first,
                module_root=root,
                package="./internal/asterisk",
                target=TARGET,
                status="fuzz-failed",
                commit="a" * 40,
                environment={"GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "1"},
            )
            second_metadata = fuzz_campaign.write_sarif(
                evidence=second,
                module_root=root,
                package="./internal/asterisk",
                target=TARGET,
                status="fuzz-failed",
                commit="b" * 40,
                environment={"GITHUB_RUN_ID": "11", "GITHUB_RUN_ATTEMPT": "2"},
            )
            self.assertEqual(
                first_metadata["stable_fingerprint"],
                second_metadata["stable_fingerprint"],
            )
            self.assertNotEqual(
                first_metadata["authoritative_evidence_artifact"],
                second_metadata["authoritative_evidence_artifact"],
            )

            evidence = root / "fixture"
            evidence.mkdir()
            metadata = fuzz_campaign.write_sarif(
                evidence=evidence,
                module_root=evidence,
                package="./scripts/testdata/fuzzfixture",
                target="FuzzEvidenceCapture",
                status="fuzz-failed",
                commit=COMMIT,
                environment={"GITHUB_RUN_ID": "99", "GITHUB_RUN_ATTEMPT": "1"},
            )
            self.assertEqual(metadata["reason"], "synthetic-fixture-excluded")
            self.assertFalse(metadata["publication_eligible"])
            self.assertFalse((evidence / "results.sarif").exists())

    def test_workflow_scopes_publication_and_excludes_fixture(self):
        workflow = (
            Path(__file__).resolve().parents[2] / ".github/workflows/go-fuzz.yml"
        ).read_text(encoding="utf-8")
        self.assertEqual(
            workflow.count("github/codeql-action/upload-sarif@33d7b85"), 1
        )
        self.assertEqual(
            workflow.count("persist-credentials: false"),
            workflow.count("actions/checkout@"),
        )
        campaign, fixture = workflow.split("  controlled-failure-contract:", 1)
        self.assertIn("security-events: write", campaign)
        self.assertIn("category: native-go-fuzz/${{ matrix.target }}", campaign)
        self.assertGreaterEqual(
            campaign.count("steps.campaign.outcome == 'failure'"),
            2,
        )
        self.assertIn("steps.campaign.outcome != 'success'", campaign)
        self.assertNotIn("security-events: write", fixture)
        self.assertNotIn("upload-sarif", fixture)

    def test_sarif_generation_error_cannot_publish_false_clean_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root(temporary)
            (root / "internal/asterisk/media_test.go").unlink()
            runner = FakeRunner(
                root,
                fuzz_exit=1,
                fuzz_output=fuzzed(TARGET, "fail"),
                write_corpus=True,
            )
            status, receipt, evidence = self.campaign(root, runner)
            self.assertEqual(status, 2)
            self.assertEqual(receipt["status"], "sarif-generation-failed")
            self.assertFalse(receipt["code_scanning"]["publication_eligible"])
            self.assertFalse((evidence / "results.sarif").exists())

    def test_spoofed_package_output_cannot_claim_target_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root(temporary)
            spoof = events(
                {
                    "Action": "output",
                    "Package": "example/package",
                    "Output": json.dumps({"Action": "run", "Test": TARGET}) + "\n",
                },
                {"Action": "pass", "Package": "example/package"},
            )
            status, receipt, _ = self.campaign(root, FakeRunner(root, fuzz_output=spoof))
            self.assertEqual(status, 3)
            self.assertEqual(receipt["status"], "target-execution-unconfirmed")
            self.assertFalse(receipt["target_executed"])

    def test_wrong_or_missing_listed_target_stops_before_fuzzing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root(temporary)
            runner = FakeRunner(root, listed_target="FuzzWrongTarget")
            status, receipt, _ = self.campaign(root, runner)
            self.assertEqual(status, 3)
            self.assertEqual(receipt["status"], "target-missing")
            self.assertFalse(runner.fuzz_called)
            self.assertFalse(receipt["code_scanning"]["publication_eligible"])

    def test_github_sha_must_match_resolved_head(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root(temporary)
            status, receipt, _ = self.campaign(
                root, FakeRunner(root), environment={"GITHUB_SHA": "b" * 40}
            )
            self.assertEqual(status, 2)
            self.assertEqual(receipt["status"], "source-mismatch")
            self.assertEqual(receipt["source_commit"], COMMIT)
            self.assertFalse(receipt["source_tree_clean_before"])

    def test_dirty_source_is_rejected_before_fuzzing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root(temporary)
            runner = FakeRunner(root, source_status=" M internal/asterisk/media.go\n")
            status, receipt, _ = self.campaign(root, runner)
            self.assertEqual(status, 2)
            self.assertEqual(receipt["status"], "source-dirty")
            self.assertFalse(runner.fuzz_called)
            self.assertFalse(receipt["source_tree_clean_before"])

    def test_source_mutation_during_preflight_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root(temporary)
            runner = FakeRunner(root, source_status=["", " M internal/asterisk/media.go\n"])
            status, receipt, _ = self.campaign(root, runner)
            self.assertEqual(status, 2)
            self.assertEqual(receipt["status"], "source-changed-after-preflight")
            self.assertFalse(runner.fuzz_called)
            self.assertTrue(receipt["source_tree_clean_before"])
            self.assertFalse(receipt["source_tree_clean_after_preflight"])

    def test_hidden_and_hostile_corpus_names_are_rejected(self):
        for name in (".hidden", "a.b", "bad name; echo forged"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = self.root(temporary)
                corpus = root / f"internal/asterisk/testdata/fuzz/{TARGET}"
                corpus.mkdir(parents=True)
                (corpus / name).write_text("go test fuzz v1\n[]byte(\"bad\")\n", encoding="utf-8")
                runner = FakeRunner(root)
                status, receipt, _ = self.campaign(root, runner)
                self.assertEqual(status, 2)
                self.assertEqual(receipt["status"], "unsafe-corpus")
                self.assertFalse(runner.fuzz_called)

    def test_unreviewed_target_fails_with_durable_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root(temporary)
            evidence = root / "evidence"
            status = fuzz_campaign.run_campaign(
                module_root=root,
                package="./internal/asterisk",
                target="FuzzUnreviewed",
                fuzz_time="1m",
                parallel=1,
                evidence=evidence,
                environment={},
            )
            receipt = json.loads((evidence / "receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(status, 2)
            self.assertEqual(receipt["status"], "helper-failed")
            self.assertEqual(receipt["error_category"], "ValueError")


if __name__ == "__main__":
    unittest.main()
