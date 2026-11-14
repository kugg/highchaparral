#!/usr/bin/env python3
"""Run one reviewed native-Go fuzz target and preserve a replayable receipt."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import time
from typing import Callable, Mapping, Sequence


TARGETS = {
    ("./internal/asterisk", "FuzzOwnedPCMAReturnPacket"),
    ("./internal/serviceconfig", "FuzzPrivateConfigParsers"),
}
_DURATION = re.compile(r"^([1-9][0-9]*)([smh])$")
Runner = Callable[..., subprocess.CompletedProcess[str]]


class SourceMismatch(RuntimeError):
    pass


class DirtySource(RuntimeError):
    pass


class TargetUnavailable(RuntimeError):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def duration_seconds(value: str) -> int:
    match = _DURATION.fullmatch(value)
    if match is None:
        raise ValueError("fuzz duration must be a positive integer followed by s, m or h")
    amount = int(match.group(1))
    multiplier = {"s": 1, "m": 60, "h": 3600}[match.group(2)]
    seconds = amount * multiplier
    if seconds > 1800:
        raise ValueError("fuzz duration exceeds the reviewed 30 minute bound")
    return seconds


def package_directory(module_root: Path, package: str) -> Path:
    if not package.startswith("./") or ".." in Path(package).parts:
        raise ValueError("fuzz package is outside the module")
    location = (module_root / package[2:]).resolve()
    if not location.is_relative_to(module_root.resolve()) or not location.is_dir():
        raise ValueError("fuzz package directory is unavailable")
    return location


def corpus_snapshot(package_dir: Path, target: str) -> dict[str, str]:
    corpus = package_dir / "testdata" / "fuzz" / target
    if not corpus.is_dir():
        return {}
    return {
        item.name: sha256(item)
        for item in sorted(corpus.iterdir())
        if item.is_file() and not item.is_symlink()
    }


def completed(runner: Runner, command: Sequence[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return runner(command, cwd=cwd, capture_output=True, text=True, check=False)


def git_head(runner: Runner, module_root: Path) -> str:
    result = completed(runner, ["git", "rev-parse", "HEAD"], cwd=module_root)
    candidate = result.stdout.strip()
    if result.returncode != 0 or re.fullmatch(r"[a-f0-9]{40}", candidate) is None:
        raise RuntimeError("exact source commit unavailable")
    return candidate


def source_status(runner: Runner, module_root: Path) -> list[str]:
    result = completed(
        runner,
        ["git", "status", "--porcelain=v1", "--untracked-files=all"],
        cwd=module_root,
    )
    if result.returncode != 0:
        raise RuntimeError("source tree status unavailable")
    return [line for line in result.stdout.splitlines() if line]


def go_version(runner: Runner, module_root: Path) -> str:
    result = completed(runner, ["go", "version"], cwd=module_root)
    if result.returncode != 0 or not result.stdout.strip().startswith("go version "):
        raise RuntimeError("Go toolchain identity unavailable")
    return result.stdout.strip()


def json_events(output: str) -> list[dict[str, object]]:
    events: list[dict[str, object]] = []
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def target_listed(output: str, target: str) -> bool:
    events = json_events(output)
    listed = [
        event
        for event in events
        if event.get("Action") == "output"
        and event.get("Test") is None
        and event.get("Output") == target + "\n"
    ]
    return len(listed) == 1 and any(
        event.get("Action") == "pass" and event.get("Test") is None for event in events
    )


def target_events(output: str, target: str) -> tuple[bool, str | None]:
    events = json_events(output)
    started = any(event.get("Action") == "run" and event.get("Test") == target for event in events)
    outcomes = [
        str(event["Action"])
        for event in events
        if event.get("Test") == target and event.get("Action") in {"pass", "fail", "skip"}
    ]
    return started, outcomes[-1] if outcomes else None


def artifact_manifest(evidence: Path) -> list[dict[str, object]]:
    return [
        {"path": str(item.relative_to(evidence)), "sha256": sha256(item), "bytes": item.stat().st_size}
        for item in sorted(evidence.rglob("*"))
        if item.is_file() and item.name != "receipt.json"
    ]


def run_campaign(
    *,
    module_root: Path,
    package: str,
    target: str,
    fuzz_time: str,
    parallel: int,
    evidence: Path,
    runner: Runner = subprocess.run,
    environment: Mapping[str, str] = os.environ,
) -> int:
    if evidence.exists():
        raise FileExistsError("evidence directory already exists")
    started = dt.datetime.now(dt.timezone.utc)
    started_clock = time.monotonic_ns()
    commit: str | None = None
    source_tree_clean_before = False
    preflight_command: list[str] | None = None

    try:
        if (package, target) not in TARGETS:
            raise ValueError("fuzz package/target is not in the reviewed manifest")
        seconds = duration_seconds(fuzz_time)
        if parallel < 1 or parallel > 4:
            raise ValueError("fuzz parallelism must be between 1 and 4")
        package_dir = package_directory(module_root, package)
        commit = git_head(runner, module_root)
        supplied_commit = environment.get("GITHUB_SHA", "")
        if supplied_commit and supplied_commit != commit:
            raise SourceMismatch("GITHUB_SHA does not match the checked-out HEAD")
        if source_status(runner, module_root):
            raise DirtySource("source tree is dirty before fuzz execution")
        source_tree_clean_before = True
        version = go_version(runner, module_root)
        before = corpus_snapshot(package_dir, target)
        evidence.mkdir(parents=True, exist_ok=False)
        stdout_path, stderr_path = evidence / "stdout.jsonl", evidence / "stderr.log"
        preflight_command = ["go", "test", "-json", "-list", f"^{target}$", package]
        preflight = completed(runner, preflight_command, cwd=module_root)
        (evidence / "preflight.jsonl").write_text(preflight.stdout, encoding="utf-8")
        (evidence / "preflight-stderr.log").write_text(preflight.stderr, encoding="utf-8")
        if preflight.returncode != 0 or not target_listed(preflight.stdout, target):
            raise TargetUnavailable("exact reviewed fuzz target unavailable in go test -list")
        command = [
            "go", "test", "-json", "-count=1", "-run=^$", f"-fuzz=^{target}$",
            f"-fuzztime={fuzz_time}", "-fuzzminimizetime=10s",
            f"-timeout={seconds + 180}s", f"-parallel={parallel}", package,
        ]
        result = completed(runner, command, cwd=module_root)
        stdout_path.write_text(result.stdout, encoding="utf-8")
        stderr_path.write_text(result.stderr, encoding="utf-8")
        target_executed, target_result = target_events(result.stdout, target)
        if result.returncode == 0 and target_executed and target_result == "pass":
            status, helper_exit = "passed", 0
        elif result.returncode == 0:
            status, helper_exit = "target-execution-unconfirmed", 3
        elif target_executed:
            status, helper_exit = "fuzz-failed", result.returncode
        else:
            status, helper_exit = "failed-before-target", result.returncode
        after = corpus_snapshot(package_dir, target)

        captured: list[dict[str, object]] = []
        corpus_out = evidence / "corpus"
        for name, digest in sorted(after.items()):
            is_new = before.get(name) != digest
            if not is_new and result.returncode == 0:
                continue
            corpus_out.mkdir(exist_ok=True)
            source = package_dir / "testdata" / "fuzz" / target / name
            destination = corpus_out / name
            shutil.copyfile(source, destination)
            captured.append({"name": name, "sha256": digest, "new_or_changed": is_new})

        replay = [f"go test -run='^{target}/{entry['name']}$' {package}" for entry in captured]
        (evidence / "replay.txt").write_text("\n".join(replay) + ("\n" if replay else ""), encoding="utf-8")
        finished = dt.datetime.now(dt.timezone.utc)
        receipt = {
            "schema": 1,
            "status": status,
            "target_executed": target_executed,
            "target_result": target_result,
            "source_commit": commit,
            "github_sha_supplied": environment.get("GITHUB_SHA") or None,
            "source_tree_clean_before": source_tree_clean_before,
            "go_version": version,
            "platform": environment.get("RUNNER_OS") or platform.platform(),
            "package": package,
            "target": target,
            "preflight_command": preflight_command,
            "preflight_exit": preflight.returncode,
            "command": command,
            "fuzz_time": fuzz_time,
            "parallel": parallel,
            "command_exit": result.returncode,
            "helper_exit": helper_exit,
            "started_utc": started.isoformat(),
            "finished_utc": finished.isoformat(),
            "elapsed_ms": (time.monotonic_ns() - started_clock) // 1_000_000,
            "corpus_before": before,
            "corpus_after": after,
            "captured_corpus": captured,
            "replay_commands": replay,
            "artifact_files": artifact_manifest(evidence),
        }
        (evidence / "receipt.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return helper_exit
    except Exception as error:  # Preserve a receipt even for helper/setup failure.
        evidence.mkdir(parents=True, exist_ok=True)
        stdout_path, stderr_path = evidence / "stdout.jsonl", evidence / "stderr.log"
        with stderr_path.open("a", encoding="utf-8") as stream:
            stream.write(f"{type(error).__name__}: {error}\n")
        stdout_path.touch()
        (evidence / "replay.txt").touch()
        finished = dt.datetime.now(dt.timezone.utc)
        status = {
            SourceMismatch: "source-mismatch",
            DirtySource: "source-dirty",
            TargetUnavailable: "target-missing",
        }.get(type(error), "helper-failed")
        helper_exit = 3 if isinstance(error, TargetUnavailable) else 2
        receipt = {
            "schema": 1,
            "status": status,
            "target_executed": False,
            "target_result": None,
            "source_commit": commit,
            "github_sha_supplied": environment.get("GITHUB_SHA") or None,
            "source_tree_clean_before": source_tree_clean_before,
            "package": package,
            "target": target,
            "preflight_command": preflight_command,
            "fuzz_time": fuzz_time,
            "parallel": parallel,
            "helper_exit": helper_exit,
            "started_utc": started.isoformat(),
            "finished_utc": finished.isoformat(),
            "elapsed_ms": (time.monotonic_ns() - started_clock) // 1_000_000,
            "error_category": type(error).__name__,
            "artifact_files": artifact_manifest(evidence),
        }
        (evidence / "receipt.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return helper_exit


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--package", required=True)
    result.add_argument("--target", required=True)
    result.add_argument("--fuzz-time", required=True)
    result.add_argument("--parallel", required=True, type=int)
    result.add_argument("--evidence", required=True, type=Path)
    return result


def main() -> int:
    args = parser().parse_args()
    module_root = Path(__file__).resolve().parent.parent
    return run_campaign(
        module_root=module_root,
        package=args.package,
        target=args.target,
        fuzz_time=args.fuzz_time,
        parallel=args.parallel,
        evidence=args.evidence,
    )


if __name__ == "__main__":
    raise SystemExit(main())
