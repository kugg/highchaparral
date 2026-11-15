#!/usr/bin/env python3
"""Validate that a fuzz SARIF report is bound to a conclusive receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(evidence: Path, target: str) -> dict[str, object]:
    receipt = json.loads((evidence / "receipt.json").read_text(encoding="utf-8"))
    metadata = receipt.get("code_scanning", {})
    if (
        receipt.get("target") != target
        or receipt.get("status") != "fuzz-failed"
        or receipt.get("campaign_status") != "fuzz-failed"
        or receipt.get("target_executed") is not True
        or receipt.get("target_result") != "fail"
        or not isinstance(receipt.get("command_exit"), int)
        or receipt.get("command_exit") == 0
        or not metadata.get("generated")
        or not metadata.get("publication_eligible")
        or metadata.get("path") != "results.sarif"
        or metadata.get("category") != f"native-go-fuzz/{target}"
    ):
        raise ValueError("receipt does not authorize SARIF publication")

    commit = receipt.get("source_commit")
    provenance = receipt.get("workflow_provenance", {})
    if (
        not isinstance(commit, str)
        or re.fullmatch(r"[a-f0-9]{40}", commit) is None
        or not provenance.get("run_id")
        or not provenance.get("run_attempt")
    ):
        raise ValueError("failure evidence lacks exact hosted provenance")

    manifest = {
        entry.get("path"): entry for entry in receipt.get("artifact_files", [])
        if isinstance(entry, dict)
    }
    captured = receipt.get("captured_corpus")
    replay_argv = receipt.get("replay_argv")
    if not isinstance(captured, list) or not captured or not isinstance(replay_argv, list):
        raise ValueError("failure evidence lacks captured corpus and replay argv")
    package = receipt.get("package")
    if not isinstance(package, str):
        raise ValueError("failure evidence lacks its package")
    expected_replay: list[list[str]] = []
    for entry in captured:
        name = entry.get("name") if isinstance(entry, dict) else None
        digest = entry.get("sha256") if isinstance(entry, dict) else None
        if (
            not isinstance(name, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", name) is None
            or not isinstance(digest, str)
            or re.fullmatch(r"[a-f0-9]{64}", digest) is None
        ):
            raise ValueError("failure evidence contains an unsafe corpus record")
        corpus_path = evidence / "corpus" / name
        binding = manifest.get(f"corpus/{name}")
        if (
            not corpus_path.is_file()
            or corpus_path.is_symlink()
            or not isinstance(binding, dict)
            or binding.get("sha256") != digest
            or binding.get("sha256") != sha256(corpus_path)
            or binding.get("bytes") != corpus_path.stat().st_size
        ):
            raise ValueError("captured corpus is not hash-bound to the authoritative receipt")
        expected_replay.append(["go", "test", f"-run=^{target}/{name}$", package])
    if replay_argv != expected_replay:
        raise ValueError("captured corpus replay argv does not match the receipt")

    sarif = evidence / "results.sarif"
    binding = manifest.get("results.sarif")
    if (
        not sarif.is_file()
        or sarif.is_symlink()
        or not isinstance(binding, dict)
        or binding.get("sha256") != sha256(sarif)
        or binding.get("bytes") != sarif.stat().st_size
    ):
        raise ValueError("SARIF is not hash-bound to the authoritative receipt")

    report = json.loads(sarif.read_text(encoding="utf-8"))
    if report.get("version") != "2.1.0" or len(report.get("runs", [])) != 1:
        raise ValueError("SARIF envelope is invalid")
    run = report["runs"][0]
    results = run.get("results")
    expected_count = 1
    if (
        not isinstance(results, list)
        or len(results) != expected_count
        or metadata.get("result_count") != expected_count
        or run.get("automationDetails", {}).get("id")
        != f"native-go-fuzz/{target}/"
    ):
        raise ValueError("SARIF result state does not match the campaign receipt")
    if expected_count:
        result = results[0]
        if (
            result.get("ruleId") != "VGW-NATIVE-GO-FUZZ-FAILURE"
            or not result.get("locations")
            or result.get("partialFingerprints", {}).get("nativeGoFuzzTarget/v1")
            != metadata.get("stable_fingerprint")
            or result.get("properties", {}).get("authoritativeEvidenceArtifact")
            != metadata.get("authoritative_evidence_artifact")
        ):
            raise ValueError("SARIF finding identity or evidence reference is invalid")
    return {
        "schema": 1,
        "target": target,
        "status": receipt["status"],
        "result_count": expected_count,
        "sarif_sha256": binding["sha256"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    print(json.dumps(verify(args.evidence, args.target), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
