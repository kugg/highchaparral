#!/usr/bin/env python3
"""Verify the opt-in real failure fixture from a captured fuzz artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


EXPECTED_FILES = {
    "preflight-stderr.log",
    "preflight.jsonl",
    "replay.txt",
    "stderr.log",
    "stdout.jsonl",
}
TARGET = "FuzzEvidenceCapture"
PACKAGE = "./scripts/testdata/fuzzfixture"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(argv: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, capture_output=True, text=True, check=False)


def verify(evidence: Path, module_root: Path) -> dict[str, object]:
    receipt = json.loads((evidence / "receipt.json").read_text(encoding="utf-8"))
    if (
        receipt.get("status") != "fuzz-failed"
        or receipt.get("target") != TARGET
        or receipt.get("package") != PACKAGE
        or receipt.get("target_result") != "fail"
        or not receipt.get("source_tree_clean_before")
        or not receipt.get("source_tree_clean_after_preflight")
        or receipt.get("command_exit") == 0
        or receipt.get("code_scanning", {}).get("reason")
        != "synthetic-fixture-excluded"
    ):
        raise ValueError("controlled fixture receipt does not prove a bound fuzz failure")

    captured = receipt.get("captured_corpus", [])
    if len(captured) != 1 or not captured[0].get("new_or_changed"):
        raise ValueError("controlled minimized corpus was not captured exactly once")
    corpus_name = captured[0].get("name")
    if (
        not isinstance(corpus_name, str)
        or len(corpus_name) != 16
        or any(character not in "0123456789abcdef" for character in corpus_name)
    ):
        raise ValueError("controlled fixture did not produce a native Go corpus name")

    git_root = command(["git", "rev-parse", "--show-toplevel"], module_root)
    if git_root.returncode != 0:
        raise ValueError("fixture repository root is unavailable")
    module_prefix = module_root.resolve().relative_to(
        Path(git_root.stdout.strip()).resolve()
    )
    expected_dirty = (
        f"?? {module_prefix.as_posix()}/scripts/testdata/fuzzfixture/testdata/fuzz/"
        f"FuzzEvidenceCapture/{corpus_name}"
    )
    git_status = command(
        ["git", "status", "--porcelain=v1", "--untracked-files=all"], module_root
    )
    dirty_lines = [line for line in git_status.stdout.splitlines() if line]
    if git_status.returncode != 0 or dirty_lines != [expected_dirty]:
        raise ValueError("fixture source changed beyond the generated fuzz corpus")

    expected_files = EXPECTED_FILES | {f"corpus/{corpus_name}"}
    manifest = {entry["path"]: entry for entry in receipt.get("artifact_files", [])}
    if not expected_files.issubset(manifest) or "results.sarif" in manifest:
        raise ValueError("fuzz artifact is incomplete")
    for relative, entry in manifest.items():
        path = evidence / relative
        if (
            not path.is_file()
            or path.is_symlink()
            or any(part.startswith(".") for part in Path(relative).parts)
            or sha256(path) != entry.get("sha256")
            or path.stat().st_size != entry.get("bytes")
        ):
            raise ValueError("fuzz artifact file binding failed")

    replay = receipt.get("replay_argv")
    if replay != [["go", "test", f"-run=^FuzzEvidenceCapture/{corpus_name}$", PACKAGE]]:
        raise ValueError("structured replay argv changed")
    events = (evidence / "stdout.jsonl").read_text(encoding="utf-8")
    if f"testdata/fuzz/FuzzEvidenceCapture/{corpus_name}" not in events:
        raise ValueError("Go did not report writing the minimized failing input")

    provenance = receipt.get("workflow_provenance", {})
    if os.environ.get("GITHUB_ACTIONS") == "true":
        expected = {
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "workflow": os.environ.get("GITHUB_WORKFLOW"),
            "ref": os.environ.get("GITHUB_REF"),
        }
        if any(not value or provenance.get(key) != value for key, value in expected.items()):
            raise ValueError("workflow provenance is absent or does not match the runner")

    with tempfile.TemporaryDirectory() as temporary:
        clean = Path(temporary)
        (clean / "go.mod").write_text("module fuzzfixture\n\ngo 1.27\n", encoding="utf-8")
        shutil.copyfile(
            module_root / "scripts/testdata/fuzzfixture/fuzz_fixture_test.go",
            clean / "fuzz_fixture_test.go",
        )
        corpus = clean / f"testdata/fuzz/FuzzEvidenceCapture/{corpus_name}"
        corpus.parent.mkdir(parents=True)
        shutil.copyfile(evidence / f"corpus/{corpus_name}", corpus)
        normal = command(
            ["go", "test", f"-run=^FuzzEvidenceCapture/{corpus_name}$", "."], clean
        )
        raced = command(
            ["go", "test", "-race", f"-run=^FuzzEvidenceCapture/{corpus_name}$", "."],
            clean,
        )
        for result in (normal, raced):
            output = result.stdout + "\n" + result.stderr
            if result.returncode == 0 or "CONTROLLED_FUZZ_FIXTURE_FAILURE" not in output:
                raise ValueError("captured corpus did not reproduce the controlled failure")

    return {
        "schema": 1,
        "artifact_complete": True,
        "clean_copy_replay_failed_as_expected": True,
        "race_replay_failed_as_expected": True,
        "corpus_name": corpus_name,
        "corpus_sha256": sha256(evidence / f"corpus/{corpus_name}"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    module_root = Path(__file__).resolve().parent.parent
    print(json.dumps(verify(args.evidence, module_root), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
