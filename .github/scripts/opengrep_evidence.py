#!/usr/bin/env python3
"""Build deterministic OpenGrep target manifests and candidate receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


SCHEMA = "highchaparral.opengrep-candidates/v1"
SUPPORTED_SUFFIXES = {".cjs", ".go", ".js", ".mjs", ".py", ".ts", ".tsx"}
EVIDENCE_PREFIXES = ("vgw/deploy/pipeline/", "vgw/regression/")
VENDOR_SEGMENTS = {"node_modules", "vendor"}


def canonical(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def language(path: str) -> str:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix == ".go":
        return "go"
    if suffix in {".cjs", ".js", ".mjs", ".ts", ".tsx"}:
        return "javascript-typescript"
    if suffix == ".py":
        return "python"
    return "other"


def is_evidence(path: str) -> bool:
    item = PurePosixPath(path)
    parts = set(item.parts)
    return (
        path.startswith(EVIDENCE_PREFIXES)
        or "test" in parts
        or "tests" in parts
        or item.name.endswith("_test.go")
        or (item.suffix == ".py" and item.name.startswith("test_"))
        or path == "vgw/softphone/playwright.config.js"
    )


def make_manifest(scope: str, paths: Iterable[str]) -> dict[str, Any]:
    if scope not in {"production", "test-evidence"}:
        raise ValueError("invalid OpenGrep scope")
    selected: list[str] = []
    opposite: list[str] = []
    excluded: list[dict[str, str]] = []
    for path in sorted(set(paths)):
        item = PurePosixPath(path)
        if "\n" in path or "\r" in path:
            raise ValueError("tracked path contains a line break")
        if not path.startswith("vgw/") or item.suffix.lower() not in SUPPORTED_SUFFIXES:
            continue
        if VENDOR_SEGMENTS.intersection(item.parts):
            excluded.append({"path": path, "reason": "vendored-or-generated"})
            continue
        evidence = is_evidence(path)
        if (scope == "test-evidence") == evidence:
            selected.append(path)
        else:
            opposite.append(path)
    if not selected:
        raise ValueError(f"scope {scope} selected no tracked source files")
    return {
        "schema": SCHEMA,
        "scope": scope,
        "files": selected,
        "file_count": len(selected),
        "language_counts": dict(sorted(Counter(language(path) for path in selected).items())),
        "excluded_by_policy": excluded,
        "opposite_scope_file_count": len(opposite),
    }


def tracked(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", "vgw"],
        check=True,
        capture_output=True,
    )
    return [item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def write_manifest(args: argparse.Namespace) -> int:
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    manifest = make_manifest(args.scope, tracked(Path(args.root)))
    (output / "target-manifest.json").write_bytes(canonical(manifest))
    (output / "targets.txt").write_text("".join(f"{path}\n" for path in manifest["files"]), encoding="utf-8")
    return 0


def load_json(path: Path) -> tuple[Any | None, str | None]:
    if not path.is_file():
        return None, "file missing"
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return None, f"{type(error).__name__}: {error}"


def run_scan(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    manifest_path = Path(args.manifest)
    manifest, error = load_json(manifest_path)
    if error or not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise ValueError(f"invalid target manifest: {error}")
    targets = [str(path) for path in manifest["files"]]
    if not targets:
        raise ValueError("target manifest is empty")
    argv = [
        str(Path(args.engine).resolve()),
        "scan",
        "--disable-version-check",
        "--strict",
        "--verbose",
        "--config",
        args.rules,
        "--json-output",
        str((output / "results.json").resolve()),
        "--sarif-output",
        str((output / "results.sarif").resolve()),
        "--max-target-bytes",
        "1000000",
        "--timeout",
        "10",
        "--timeout-threshold",
        "1",
        *targets,
    ]
    invocation = {
        "argv": argv,
        "cwd": str(root),
        "target_manifest": str(manifest_path.resolve()),
        "target_manifest_sha256": sha256(manifest_path),
    }
    (output / "invocation.json").write_bytes(canonical(invocation))
    with (output / "stdout.log").open("wb") as stdout, (output / "stderr.log").open("wb") as stderr:
        completed = subprocess.run(argv, cwd=root, stdout=stdout, stderr=stderr, check=False)
    (output / "scan-exit.txt").write_text(f"{completed.returncode}\n", encoding="ascii")
    # Capture is intentionally completed before the workflow enforces this code.
    return 0


def candidates(raw: dict[str, Any]) -> list[dict[str, Any]]:
    found = []
    for result in raw.get("results", []):
        extra = result.get("extra") or {}
        start = result.get("start") or {}
        end = result.get("end") or {}
        path = str(result.get("path", ""))
        found.append(
            {
                "rule_id": str(result.get("check_id", "")),
                "path": path,
                "language": str((extra.get("metadata") or {}).get("language") or language(path)),
                "severity": str(extra.get("severity", "")),
                "message": str(extra.get("message", "")),
                "start": {"line": start.get("line"), "column": start.get("col")},
                "end": {"line": end.get("line"), "column": end.get("col")},
            }
        )
    return sorted(found, key=lambda item: (item["rule_id"], item["path"], item["start"]["line"] or 0))


def build_receipt(args: argparse.Namespace) -> int:
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    manifest, manifest_error = load_json(Path(args.manifest))
    invocation, invocation_error = load_json(Path(args.invocation))
    raw, result_error = load_json(Path(args.json))
    raw = raw if isinstance(raw, dict) else {}
    found = candidates(raw)
    errors = raw.get("errors", []) if isinstance(raw.get("errors", []), list) else []
    paths = raw.get("paths") if isinstance(raw.get("paths"), dict) else {}
    skipped = paths.get("skipped", []) if isinstance(paths.get("skipped", []), list) else []
    scanned = paths.get("scanned", []) if isinstance(paths.get("scanned", []), list) else []
    targets = set(manifest.get("files", [])) if isinstance(manifest, dict) else set()
    scanned_set = set(scanned)
    unscanned = sorted(targets - scanned_set)
    unexpected = sorted(scanned_set - targets)
    by_rule = Counter(item["rule_id"] for item in found)
    by_language = Counter(item["language"] for item in found)
    scan_exit = int(Path(args.scan_exit).read_text(encoding="ascii").strip())
    receipt = {
        "schema": SCHEMA,
        "kind": "opengrep-candidate-scan",
        "disposition": "candidates-not-confirmed",
        "scope": args.scope,
        "source": {
            "repository": args.repository,
            "workflow_sha": args.workflow_sha,
            "pull_request_head_sha": args.head_sha or None,
            "pull_request_base_sha": args.base_sha or None,
        },
        "engine": {
            "name": "opengrep",
            "version": args.engine_version,
            "binary_sha256": args.engine_sha256,
        },
        "rules": {"path": args.rules, "sha256": sha256(Path(args.rules))},
        "invocation": {"exact": invocation, "scan_exit_code": scan_exit},
        "targets": manifest,
        "results": {
            "status": (
                "complete"
                if scan_exit == 0 and result_error is None and not errors and not unscanned and not unexpected
                else "scan-failed"
            ),
            "finding_count": len(found),
            "by_rule": dict(sorted(by_rule.items())),
            "by_language": dict(sorted(by_language.items())),
            "candidates": found,
            "scanner_error_count": len(errors),
            "scanner_errors": errors,
            "skipped_file_count": len(skipped),
            "skipped_files": skipped,
            "scanner_scanned_file_count": len(scanned),
            "unscanned_target_files": unscanned,
            "unexpected_scanned_files": unexpected,
            "capture_errors": {
                key: value
                for key, value in {
                    "manifest": manifest_error,
                    "invocation": invocation_error,
                    "results": result_error,
                }.items()
                if value is not None
            },
        },
        "artifact_sha256": {
            "manifest": sha256(Path(args.manifest)),
            "invocation": sha256(Path(args.invocation)),
            "raw_json": sha256(Path(args.json)),
            "sarif": sha256(Path(args.sarif)),
            "stdout": sha256(Path(args.stdout)),
            "stderr": sha256(Path(args.stderr)),
        },
    }
    (output / "evidence.json").write_bytes(canonical(receipt))
    return 0


def verify_fixture(args: argparse.Namespace) -> int:
    raw, raw_error = load_json(Path(args.json))
    expected, expected_error = load_json(Path(args.expected))
    if raw_error or expected_error or not isinstance(raw, dict) or not isinstance(expected, list):
        raise ValueError(f"invalid fixture evidence: results={raw_error}, expected={expected_error}")
    actual = sorted(
        (
            {
                "rule_id": str(item.get("check_id", "")),
                "path": str(item.get("path", "")),
                "line": (item.get("start") or {}).get("line"),
            }
            for item in raw.get("results", [])
        ),
        key=lambda item: (item["path"], item["line"] or 0, item["rule_id"]),
    )
    wanted = sorted(expected, key=lambda item: (item["path"], item["line"], item["rule_id"]))
    if actual != wanted:
        raise ValueError(f"fixture findings changed: expected={wanted!r}, actual={actual!r}")
    if raw.get("errors"):
        raise ValueError(f"fixture scan reported errors: {raw['errors']!r}")
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command_name", required=True)
    manifest = commands.add_parser("manifest")
    manifest.add_argument("--scope", required=True, choices=("production", "test-evidence"))
    manifest.add_argument("--root", default=".")
    manifest.add_argument("--output", required=True)
    manifest.set_defaults(action=write_manifest)
    scan = commands.add_parser("scan")
    scan.add_argument("--engine", required=True)
    scan.add_argument("--root", default=".")
    scan.add_argument("--rules", required=True)
    scan.add_argument("--manifest", required=True)
    scan.add_argument("--output", required=True)
    scan.set_defaults(action=run_scan)
    build = commands.add_parser("build")
    for name in ("scope", "repository", "workflow_sha", "engine_version", "engine_sha256", "rules",
                 "manifest", "invocation", "scan_exit", "json", "sarif", "stdout", "stderr", "output"):
        build.add_argument("--" + name.replace("_", "-"), required=True)
    build.add_argument("--head-sha", default="")
    build.add_argument("--base-sha", default="")
    build.set_defaults(action=build_receipt)
    fixture = commands.add_parser("verify-fixture")
    fixture.add_argument("--json", required=True)
    fixture.add_argument("--expected", required=True)
    fixture.set_defaults(action=verify_fixture)
    return result


def main() -> int:
    args = parser().parse_args()
    return args.action(args)


if __name__ == "__main__":
    raise SystemExit(main())
