#!/usr/bin/env python3
"""Build and verify reproducible OpenGrep target manifests and receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Iterable


SCHEMA = "highchaparral.opengrep-candidates/v2"
COMPARISON_SCHEMA = "highchaparral.opengrep-comparison/v1"
SUPPORTED_SUFFIXES = {
    ".cjs": "source:javascript-typescript",
    ".go": "source:go",
    ".html": "source:html",
    ".js": "source:javascript-typescript",
    ".json": "config:json",
    ".mjs": "source:javascript-typescript",
    ".py": "source:python",
    ".ts": "source:javascript-typescript",
    ".tsx": "source:javascript-typescript",
    ".yaml": "config:yaml",
    ".yml": "config:yaml",
}
EVIDENCE_PREFIXES = ("vgw/deploy/pipeline/", "vgw/regression/")
VENDOR_SEGMENTS = {"node_modules", "vendor"}
RELEVANT_GIT_PATHS = (
    "vgw",
    ".opengrep",
    ".semgrepignore",
    ".github/scripts/opengrep_evidence.py",
    ".github/workflows/opengrep.yml",
)


def canonical(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def content_sha256(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def language(path: str) -> str:
    item = PurePosixPath(path)
    suffix = item.suffix.lower()
    if suffix == ".go":
        return "go"
    if suffix in {".cjs", ".js", ".mjs", ".ts", ".tsx"}:
        return "javascript-typescript"
    if suffix == ".py":
        return "python"
    if suffix == ".json":
        return "json"
    if suffix in {".yaml", ".yml"}:
        return "yaml"
    if suffix == ".html":
        return "html"
    if item.name == "Dockerfile" or item.name.startswith("Dockerfile."):
        return "dockerfile"
    return "other"


def supported_kind(path: str) -> str | None:
    item = PurePosixPath(path)
    if item.name == "Dockerfile" or item.name.startswith("Dockerfile."):
        return "config:dockerfile"
    return SUPPORTED_SUFFIXES.get(item.suffix.lower())


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


def git_state(root: Path) -> dict[str, Any]:
    head = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--verify", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    status = subprocess.run(
        [
            "git", "-C", str(root), "status", "--porcelain=v1", "-z",
            "--untracked-files=all", "--", *RELEVANT_GIT_PATHS,
        ],
        check=True,
        capture_output=True,
    ).stdout
    return {
        "git_head": head,
        "relevant_pathspec": list(RELEVANT_GIT_PATHS),
        "relevant_dirty_entries": sorted(
            item.decode("utf-8", errors="replace") for item in status.split(b"\0") if item
        ),
    }


def require_clean_state(root: Path, expected_head: str | None = None) -> dict[str, Any]:
    state = git_state(root)
    if state["relevant_dirty_entries"]:
        raise ValueError(f"relevant Git inputs are dirty: {state['relevant_dirty_entries']!r}")
    if expected_head and state["git_head"] != expected_head:
        raise ValueError(
            f"checked-out Git HEAD {state['git_head']} does not match expected {expected_head}"
        )
    return state


def make_manifest(
    scope: str,
    paths: Iterable[str],
    repository_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if scope not in {"production", "test-evidence"}:
        raise ValueError("invalid OpenGrep scope")
    all_paths = sorted(set(paths))
    selected: list[str] = []
    excluded: list[dict[str, str]] = []
    supported_count = 0
    for path in all_paths:
        item = PurePosixPath(path)
        if "\n" in path or "\r" in path:
            raise ValueError("tracked path contains a line break")
        if not path.startswith("vgw/"):
            excluded.append({"path": path, "reason": "outside-vgw-scope"})
            continue
        if VENDOR_SEGMENTS.intersection(item.parts):
            excluded.append({"path": path, "reason": "third-party-or-generated"})
            continue
        kind = supported_kind(path)
        if kind is None:
            suffix = item.suffix.lower() or "[no-extension]"
            excluded.append({"path": path, "reason": f"unsupported-by-owned-rules:{suffix}"})
            continue
        supported_count += 1
        evidence = is_evidence(path)
        target_scope = "test-evidence" if evidence else "production"
        if scope == target_scope:
            selected.append(path)
        else:
            excluded.append({"path": path, "reason": f"owned-by-scope:{target_scope}"})
    if not selected:
        raise ValueError(f"scope {scope} selected no tracked source or configuration files")
    if len(selected) + len(excluded) != len(all_paths):
        raise AssertionError("tracked scope accounting is incomplete")
    manifest = {
        "schema": SCHEMA,
        "scope": scope,
        "files": selected,
        "file_count": len(selected),
        "language_counts": dict(sorted(Counter(language(path) for path in selected).items())),
        "tracked_file_count": len(all_paths),
        "supported_file_count": supported_count,
        "accounted_file_count": len(selected) + len(excluded),
        "excluded_by_policy": excluded,
    }
    if repository_state is not None:
        manifest["repository_state"] = repository_state
    return manifest


def tracked(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--", "vgw"],
        check=True,
        capture_output=True,
    )
    return [item.decode("utf-8") for item in result.stdout.split(b"\0") if item]


def write_manifest(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    state = require_clean_state(root, args.expected_head_sha or None)
    manifest = make_manifest(args.scope, tracked(root), state)
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


def repository_owned_path(root: Path, value: str) -> tuple[Path, str]:
    candidate = Path(value)
    resolved = (candidate if candidate.is_absolute() else root / candidate).resolve()
    try:
        relative = resolved.relative_to(root).as_posix()
    except ValueError as error:
        raise ValueError(f"path is outside the repository: {value}") from error
    return resolved, relative


def manifest_targets(manifest: Any) -> list[str]:
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise ValueError("manifest does not contain a files array")
    targets = [str(path) for path in manifest["files"]]
    if not targets:
        raise ValueError("target manifest is empty")
    for target in targets:
        item = PurePosixPath(target)
        if item.is_absolute() or ".." in item.parts or item.as_posix() != target:
            raise ValueError(f"invalid target path in manifest: {target!r}")
    return targets


def run_scan(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    manifest_path = Path(args.manifest).resolve()
    manifest, error = load_json(manifest_path)
    if error:
        raise ValueError(f"invalid target manifest: {error}")
    targets = manifest_targets(manifest)
    state = require_clean_state(root)
    if manifest.get("repository_state") != state:
        raise ValueError("target manifest is not bound to the current clean Git state")
    expected_manifest = make_manifest(str(manifest.get("scope", "")), tracked(root), state)
    if manifest != expected_manifest:
        raise ValueError("target manifest does not match the current tracked scope")
    rules_path, rules_relative = repository_owned_path(root, args.rules)
    rules_digest = sha256(rules_path)
    if rules_digest is None:
        raise ValueError("rules file is missing")
    engine_path = Path(args.engine).resolve()
    engine_digest = sha256(engine_path)
    if engine_digest is None:
        raise ValueError("OpenGrep engine is missing")
    argv = [
        str(engine_path), "scan", "--disable-version-check", "--strict", "--verbose",
        "--scan-unknown-extensions",
        "--config", rules_relative,
        "--json-output", str((output / "results.json").resolve()),
        "--sarif-output", str((output / "results.sarif").resolve()),
        "--max-target-bytes", "1000000", "--timeout", "10", "--timeout-threshold", "1",
        *targets,
    ]
    invocation = {
        "schema": SCHEMA,
        "argv": argv,
        "cwd": str(root),
        "engine": {"path": str(engine_path), "sha256": engine_digest},
        "rules": {"path": rules_relative, "sha256": rules_digest},
        "target_manifest": {"path": str(manifest_path), "sha256": sha256(manifest_path)},
        "targets": targets,
        "repository_state": state,
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


def read_scan_exit(path: Path) -> tuple[int | None, str | None]:
    try:
        return int(path.read_text(encoding="ascii").strip()), None
    except (OSError, UnicodeError, ValueError) as error:
        return None, f"{type(error).__name__}: {error}"


def sarif_category(scope: str) -> str:
    if scope not in {"production", "test-evidence"}:
        raise ValueError(f"invalid SARIF publication scope: {scope}")
    return f"opengrep-{scope}"


def artifact_identity(scope: str, run_id: str, run_attempt: str) -> str:
    sarif_category(scope)
    return f"opengrep-{scope}-{run_id}-{run_attempt}"


def validate_bindings(
    *, root: Path, args: argparse.Namespace, manifest: Any, invocation: Any,
    current_state: dict[str, Any] | None,
) -> list[str]:
    errors: list[str] = []
    try:
        targets = manifest_targets(manifest)
    except ValueError as error:
        errors.append(f"manifest:{error}")
        targets = []
    manifest_digest = sha256(Path(args.manifest))
    rules_path: Path | None = None
    try:
        rules_path, rules_relative = repository_owned_path(root, args.rules)
    except ValueError as error:
        errors.append(f"rules:{error}")
        rules_relative = ""
    rules_digest = sha256(rules_path) if rules_path else None
    if not isinstance(manifest, dict):
        errors.append("manifest:not-an-object")
    else:
        if manifest.get("scope") != args.scope:
            errors.append("manifest:scope-mismatch")
        if current_state is not None and manifest.get("repository_state") != current_state:
            errors.append("manifest:git-state-mismatch")
        if current_state is not None:
            try:
                if manifest != make_manifest(args.scope, tracked(root), current_state):
                    errors.append("manifest:tracked-scope-mismatch")
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                errors.append(f"manifest:scope-rebuild-failed:{type(error).__name__}")
    if current_state is not None:
        if current_state.get("relevant_dirty_entries"):
            errors.append("repository:relevant-inputs-dirty")
        if current_state.get("git_head") != args.workflow_sha:
            errors.append("repository:workflow-sha-mismatch")
    if not isinstance(invocation, dict):
        errors.append("invocation:not-an-object")
        return sorted(set(errors))
    target_binding = invocation.get("target_manifest")
    if not isinstance(target_binding, dict) or target_binding.get("sha256") != manifest_digest:
        errors.append("invocation:manifest-digest-mismatch")
    if invocation.get("targets") != targets:
        errors.append("invocation:target-list-mismatch")
    if current_state is not None and invocation.get("repository_state") != current_state:
        errors.append("invocation:git-state-mismatch")
    rule_binding = invocation.get("rules")
    if not isinstance(rule_binding, dict) or rule_binding.get("path") != rules_relative:
        errors.append("invocation:rules-path-mismatch")
    if not isinstance(rule_binding, dict) or rule_binding.get("sha256") != rules_digest:
        errors.append("invocation:rules-digest-mismatch")
    engine_binding = invocation.get("engine")
    if not isinstance(engine_binding, dict) or engine_binding.get("sha256") != args.engine_sha256:
        errors.append("invocation:engine-digest-mismatch")
    argv = invocation.get("argv")
    if not isinstance(argv, list) or len(argv) < len(targets) or argv[-len(targets):] != targets:
        errors.append("invocation:argv-target-mismatch")
    else:
        if "--scan-unknown-extensions" not in argv:
            errors.append("invocation:unknown-extension-scope-flag-missing")
        try:
            config_index = argv.index("--config")
            if argv[config_index + 1] != rules_relative:
                errors.append("invocation:argv-rules-mismatch")
        except (ValueError, IndexError):
            errors.append("invocation:argv-rules-missing")
    if invocation.get("cwd") != str(root):
        errors.append("invocation:cwd-mismatch")
    return sorted(set(errors))


def build_receipt(args: argparse.Namespace) -> int:
    root = Path(args.root).resolve()
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    manifest, manifest_error = load_json(Path(args.manifest))
    invocation, invocation_error = load_json(Path(args.invocation))
    raw, result_error = load_json(Path(args.json))
    raw = raw if isinstance(raw, dict) else {}
    try:
        current_state = git_state(root)
        state_error = None
    except (OSError, subprocess.SubprocessError) as error:
        current_state = None
        state_error = f"{type(error).__name__}: {error}"
    binding_errors = validate_bindings(
        root=root, args=args, manifest=manifest, invocation=invocation, current_state=current_state,
    )
    found = candidates(raw)
    errors = raw.get("errors", []) if isinstance(raw.get("errors", []), list) else []
    paths = raw.get("paths") if isinstance(raw.get("paths"), dict) else {}
    skipped = paths.get("skipped", []) if isinstance(paths.get("skipped", []), list) else []
    scanned = paths.get("scanned", []) if isinstance(paths.get("scanned", []), list) else []
    try:
        targets = set(manifest_targets(manifest))
    except ValueError:
        targets = set()
    scanned_set = set(scanned)
    unscanned = sorted(targets - scanned_set)
    unexpected = sorted(scanned_set - targets)
    by_rule = Counter(item["rule_id"] for item in found)
    by_language = Counter(item["language"] for item in found)
    scan_exit, exit_error = read_scan_exit(Path(args.scan_exit))
    capture_errors = {
        key: value
        for key, value in {
            "manifest": manifest_error, "invocation": invocation_error, "results": result_error,
            "scan_exit": exit_error, "repository_state": state_error,
        }.items()
        if value is not None
    }
    status = (
        "complete"
        if scan_exit == 0 and not capture_errors and not binding_errors and not errors
        and not unscanned and not unexpected
        else "scan-failed"
    )
    source = {
        "repository": args.repository,
        "workflow_sha": args.workflow_sha,
        "actual_git_head": current_state.get("git_head") if current_state else None,
        "pull_request_head_sha": args.head_sha or None,
        "pull_request_base_sha": args.base_sha or None,
        "github_run_id": args.run_id,
        "github_run_attempt": args.run_attempt,
    }
    rules_path, rules_relative = repository_owned_path(root, args.rules)
    rules = {"path": rules_relative, "sha256": sha256(rules_path)}
    result_summary = {
        "status": status,
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
        "capture_errors": capture_errors,
        "binding_errors": binding_errors,
    }
    comparison_projection = {
        "schema": COMPARISON_SCHEMA,
        "repository": args.repository,
        "git_head": source["actual_git_head"],
        "scope": args.scope,
        "engine": {"version": args.engine_version, "binary_sha256": args.engine_sha256},
        "rules_sha256": rules["sha256"],
        "target_manifest_sha256": sha256(Path(args.manifest)),
        "result": {
            "status": status,
            "finding_count": len(found),
            "by_rule": dict(sorted(by_rule.items())),
            "by_language": dict(sorted(by_language.items())),
            "candidates": found,
            "scanner_error_count": len(errors),
            "skipped_file_count": len(skipped),
            "unscanned_target_files": unscanned,
            "unexpected_scanned_files": unexpected,
        },
    }
    receipt = {
        "schema": SCHEMA,
        "kind": "opengrep-candidate-scan",
        "disposition": "candidates-not-confirmed",
        "scope": args.scope,
        "source": source,
        "engine": {"name": "opengrep", "version": args.engine_version, "binary_sha256": args.engine_sha256},
        "rules": rules,
        "input_binding": {"status": "verified" if not binding_errors else "failed", "errors": binding_errors},
        "invocation": {"exact": invocation, "scan_exit_code": scan_exit},
        "targets": manifest,
        "results": result_summary,
        "comparison": {"projection": comparison_projection, "sha256": content_sha256(comparison_projection)},
        "publication": {
            "github_code_scanning": {
                "intent": "upload-only-after-complete-receipt-validation",
                "category": sarif_category(args.scope),
                "sarif_path": "results.sarif",
                "sarif_sha256": sha256(Path(args.sarif)),
                "evidence_artifact": artifact_identity(args.scope, args.run_id, args.run_attempt),
            },
        },
        "artifact_sha256": {
            "manifest": sha256(Path(args.manifest)), "invocation": sha256(Path(args.invocation)),
            "raw_json": sha256(Path(args.json)), "sarif": sha256(Path(args.sarif)),
            "stdout": sha256(Path(args.stdout)), "stderr": sha256(Path(args.stderr)),
        },
    }
    (output / "evidence.json").write_bytes(canonical(receipt))
    return 0


def verify_publication(args: argparse.Namespace) -> int:
    receipt, receipt_error = load_json(Path(args.receipt))
    sarif, sarif_error = load_json(Path(args.sarif))
    errors: list[str] = []
    if receipt_error or not isinstance(receipt, dict):
        errors.append(f"receipt:{receipt_error or 'not-an-object'}")
        receipt = {}
    if sarif_error or not isinstance(sarif, dict):
        errors.append(f"sarif:{sarif_error or 'not-an-object'}")
        sarif = {}
    expected_category = sarif_category(args.scope)
    expected_artifact = artifact_identity(args.scope, args.run_id, args.run_attempt)
    if args.category != expected_category:
        errors.append("category:not-stable-scope-category")
    if args.artifact_name != expected_artifact:
        errors.append("artifact:identity-mismatch")
    if receipt.get("scope") != args.scope:
        errors.append("receipt:scope-mismatch")
    if (receipt.get("results") or {}).get("status") != "complete":
        errors.append("receipt:scan-not-complete")
    if (receipt.get("results") or {}).get("capture_errors"):
        errors.append("receipt:capture-errors-present")
    if (receipt.get("results") or {}).get("binding_errors"):
        errors.append("receipt:binding-errors-present")
    if (receipt.get("results") or {}).get("scanner_error_count") != 0:
        errors.append("receipt:scanner-errors-present")
    if (receipt.get("input_binding") or {}).get("status") != "verified":
        errors.append("receipt:input-binding-not-verified")
    publication = ((receipt.get("publication") or {}).get("github_code_scanning") or {})
    if publication.get("category") != expected_category:
        errors.append("receipt:category-mismatch")
    if publication.get("evidence_artifact") != expected_artifact:
        errors.append("receipt:artifact-identity-mismatch")
    sarif_digest = sha256(Path(args.sarif))
    if publication.get("sarif_sha256") != sarif_digest:
        errors.append("receipt:sarif-digest-mismatch")
    if (receipt.get("artifact_sha256") or {}).get("sarif") != sarif_digest:
        errors.append("receipt:artifact-sarif-digest-mismatch")
    if sarif.get("version") != "2.1.0":
        errors.append("sarif:unsupported-version")
    if not str(sarif.get("$schema", "")).endswith("/sarif-schema-2.1.0.json"):
        errors.append("sarif:schema-missing")
    runs = sarif.get("runs")
    if not isinstance(runs, list) or not runs:
        errors.append("sarif:runs-missing")
        runs = []
    sarif_result_count = 0
    for index, run in enumerate(runs):
        driver = ((run.get("tool") or {}).get("driver") or {}) if isinstance(run, dict) else {}
        if not driver.get("name"):
            errors.append(f"sarif:run-{index}-driver-missing")
        run_results = run.get("results") if isinstance(run, dict) else None
        if not isinstance(run_results, list):
            errors.append(f"sarif:run-{index}-results-not-list")
        else:
            sarif_result_count += len(run_results)
    receipt_count = (receipt.get("results") or {}).get("finding_count")
    if sarif_result_count != receipt_count:
        errors.append("sarif:finding-count-mismatch")
    if errors:
        raise ValueError(f"SARIF publication refused: {sorted(set(errors))!r}")
    return 0


def verify_fixture(args: argparse.Namespace) -> int:
    raw, raw_error = load_json(Path(args.json))
    expected, expected_error = load_json(Path(args.expected))
    if raw_error or expected_error or not isinstance(raw, dict) or not isinstance(expected, list):
        raise ValueError(f"invalid fixture evidence: results={raw_error}, expected={expected_error}")
    actual = sorted(
        ({"rule_id": str(item.get("check_id", "")), "path": str(item.get("path", "")),
          "line": (item.get("start") or {}).get("line")} for item in raw.get("results", [])),
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
    manifest.add_argument("--expected-head-sha", default="")
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
    for name in (
        "scope", "repository", "workflow_sha", "run_id", "run_attempt", "engine_version",
        "engine_sha256", "rules", "manifest", "invocation", "scan_exit", "json", "sarif",
        "stdout", "stderr", "output",
    ):
        build.add_argument("--" + name.replace("_", "-"), required=True)
    build.add_argument("--root", default=".")
    build.add_argument("--head-sha", default="")
    build.add_argument("--base-sha", default="")
    build.set_defaults(action=build_receipt)
    fixture = commands.add_parser("verify-fixture")
    fixture.add_argument("--json", required=True)
    fixture.add_argument("--expected", required=True)
    fixture.set_defaults(action=verify_fixture)
    publication = commands.add_parser("verify-publication")
    for name in ("receipt", "sarif", "scope", "category", "artifact_name", "run_id", "run_attempt"):
        publication.add_argument("--" + name.replace("_", "-"), required=True)
    publication.set_defaults(action=verify_publication)
    return result


def main() -> int:
    args = parser().parse_args()
    return args.action(args)


if __name__ == "__main__":
    raise SystemExit(main())
