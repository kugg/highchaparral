import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts import fuzz_campaign


COMMIT = "a" * 40


class FakeRunner:
    def __init__(self, root: Path, *, fuzz_exit: int, fuzz_output: str, write_corpus: bool = False):
        self.root = root
        self.fuzz_exit = fuzz_exit
        self.fuzz_output = fuzz_output
        self.write_corpus = write_corpus

    def __call__(self, command, **_kwargs):
        if command == ["git", "rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(command, 0, COMMIT + "\n", "")
        if command == ["go", "version"]:
            return subprocess.CompletedProcess(command, 0, "go version go1.27.4 linux/amd64\n", "")
        if command[:2] == ["go", "test"]:
            if self.write_corpus:
                corpus = self.root / "internal/asterisk/testdata/fuzz/FuzzOwnedPCMAReturnPacket"
                corpus.mkdir(parents=True)
                (corpus / "deadbeef").write_text("go test fuzz v1\n[]byte(\"bad\")\n", encoding="utf-8")
            return subprocess.CompletedProcess(command, self.fuzz_exit, self.fuzz_output, "")
        raise AssertionError(command)


class CampaignTest(unittest.TestCase):
    def root(self, temporary: str) -> Path:
        root = Path(temporary)
        (root / "internal/asterisk").mkdir(parents=True)
        return root

    def test_failure_captures_corpus_hash_and_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root(temporary)
            evidence = root / "evidence"
            runner = FakeRunner(
                root,
                fuzz_exit=1,
                fuzz_output="fuzz: elapsed: 1s\n--- FAIL: FuzzOwnedPCMAReturnPacket\n",
                write_corpus=True,
            )
            status = fuzz_campaign.run_campaign(
                module_root=root,
                package="./internal/asterisk",
                target="FuzzOwnedPCMAReturnPacket",
                fuzz_time="1m",
                parallel=2,
                evidence=evidence,
                runner=runner,
                environment={},
            )
            receipt = json.loads((evidence / "receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(status, 1)
            self.assertEqual(receipt["status"], "fuzz-failed")
            self.assertTrue(receipt["target_executed"])
            self.assertEqual(receipt["captured_corpus"][0]["name"], "deadbeef")
            self.assertEqual(len(receipt["captured_corpus"][0]["sha256"]), 64)
            self.assertIn("FuzzOwnedPCMAReturnPacket/deadbeef", (evidence / "replay.txt").read_text())
            self.assertTrue((evidence / "corpus/deadbeef").is_file())

    def test_success_without_fuzz_execution_is_not_a_false_green(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = self.root(temporary)
            evidence = root / "evidence"
            runner = FakeRunner(root, fuzz_exit=0, fuzz_output="ok package 0.01s\n")
            status = fuzz_campaign.run_campaign(
                module_root=root,
                package="./internal/asterisk",
                target="FuzzOwnedPCMAReturnPacket",
                fuzz_time="30s",
                parallel=1,
                evidence=evidence,
                runner=runner,
                environment={},
            )
            receipt = json.loads((evidence / "receipt.json").read_text(encoding="utf-8"))
            self.assertEqual(status, 3)
            self.assertEqual(receipt["status"], "target-not-executed")
            self.assertFalse(receipt["target_executed"])

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
