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


def exact_commit(runner: Runner, module_root: Path, environment: Mapping[str, str]) -> str:
    supplied = environment.get("GITHUB_SHA", "")
    if re.fullmatch(r"[a-f0-9]{40}", supplied):
        return supplied
    result = completed(runner, ["git", "rev-parse", "HEAD"], cwd=module_root)
    candidate = result.stdout.strip()
    if result.returncode != 0 or re.fullmatch(r"[a-f0-9]{40}", candidate) is None:
        raise RuntimeError("exact source commit unavailable")
    return candidate


def go_version(runner: Runner, module_root: Path) -> str:
    result = completed(runner, ["go", "version"], cwd=module_root)
    if result.returncode != 0 or not result.stdout.strip().startswith("go version "):
        raise RuntimeError("Go toolchain identity unavailable")
    return result.stdout.strip()


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
    evidence.mkdir(parents=True, exist_ok=False)
    started = dt.datetime.now(dt.timezone.utc)
    started_clock = time.monotonic_ns()
    stdout_path, stderr_path = evidence / "stdout.log", evidence / "stderr.log"

    try:
        if (package, target) not in TARGETS:
            raise ValueError("fuzz package/target is not in the reviewed manifest")
        seconds = duration_seconds(fuzz_time)
        if parallel < 1 or parallel > 4:
            raise ValueError("fuzz parallelism must be between 1 and 4")
        package_dir = package_directory(module_root, package)
        commit = exact_commit(runner, module_root, environment)
        version = go_version(runner, module_root)
        before = corpus_snapshot(package_dir, target)
        command = [
            "go", "test", "-count=1", "-run=^$", f"-fuzz=^{target}$",
            f"-fuzztime={fuzz_time}", "-fuzzminimizetime=10s",
            f"-timeout={seconds + 180}s", f"-parallel={parallel}", package,
        ]
        result = completed(runner, command, cwd=module_root)
        stdout_path.write_text(result.stdout, encoding="utf-8")
        stderr_path.write_text(result.stderr, encoding="utf-8")
        combined = result.stdout + "\n" + result.stderr
        target_executed = "fuzz: elapsed:" in combined or f"--- FAIL: {target}" in combined
        if result.returncode == 0 and target_executed:
            status, helper_exit = "passed", 0
        elif result.returncode == 0:
            status, helper_exit = "target-not-executed", 3
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
            "source_commit": commit,
            "go_version": version,
            "platform": environment.get("RUNNER_OS") or platform.platform(),
            "package": package,
            "target": target,
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
        stderr_path.write_text(f"{type(error).__name__}: {error}\n", encoding="utf-8")
        stdout_path.touch()
        (evidence / "replay.txt").touch()
        finished = dt.datetime.now(dt.timezone.utc)
        receipt = {
            "schema": 1,
            "status": "helper-failed",
            "target_executed": False,
            "package": package,
            "target": target,
            "fuzz_time": fuzz_time,
            "parallel": parallel,
            "helper_exit": 2,
            "started_utc": started.isoformat(),
            "finished_utc": finished.isoformat(),
            "elapsed_ms": (time.monotonic_ns() - started_clock) // 1_000_000,
            "error_category": type(error).__name__,
            "artifact_files": artifact_manifest(evidence),
        }
        (evidence / "receipt.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return 2


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
