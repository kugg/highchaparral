#!/usr/bin/env python3
"""Validate that a fuzz SARIF report is bound to a conclusive receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify(evidence: Path, target: str) -> dict[str, object]:
    receipt = json.loads((evidence / "receipt.json").read_text(encoding="utf-8"))
    metadata = receipt.get("code_scanning", {})
    if (
        receipt.get("target") != target
        or receipt.get("status") not in {"passed", "fuzz-failed"}
        or not metadata.get("generated")
        or not metadata.get("publication_eligible")
        or metadata.get("path") != "results.sarif"
        or metadata.get("category") != f"native-go-fuzz/{target}"
    ):
        raise ValueError("receipt does not authorize SARIF publication")

    sarif = evidence / "results.sarif"
    manifest = {
        entry.get("path"): entry for entry in receipt.get("artifact_files", [])
    }
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
    expected_count = 1 if receipt["status"] == "fuzz-failed" else 0
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
