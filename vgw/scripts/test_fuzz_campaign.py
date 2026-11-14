import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

from scripts import fuzz_campaign


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
        (root / "internal/asterisk").mkdir(parents=True)
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
