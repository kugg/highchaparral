#!/usr/bin/env python3
"""Build or verify one credential-free, content-pinned VGW release candidate.

Explicit --build requires a clean committed public tree and locally installed
locked Go/Node dependencies; --verify checks the SAME immutable artifacts
for local Docker, QEMU staging and later Noll promotion. Never reads an
Eventphone credential, invokes a host network writer or deploys a service.
Default is dry-run. Artifacts and private build history live outside Git.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


HERE = Path(__file__).resolve().parent
VGW = HERE.parent.parent
REPO = VGW.parent
FILES = ("bin/vgw", "source.tar", "go.mod", "go.sum",
         "deploy/ansible/templates/voip-gateway.config.j2",
         "site/index.html", "site/app.js", "site/byok.js", "site/dial.js",
         "site/config.js", "site/style.css", "site/vendor/sip.min.js")
IDENTIFIER = re.compile(r"[a-z0-9]{8,20}\Z")
COMMIT = re.compile(r"[a-f0-9]{40}\Z")
DIGEST = re.compile(r"[a-f0-9]{64}\Z")
IMAGE = re.compile(r"sha256:[a-f0-9]{64}\Z")


def run(args: list[str], *, cwd: Path, timeout: int = 120) -> str:
    result = subprocess.run(args, cwd=cwd, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=timeout, check=False)
    if result.returncode or len(result.stdout) > 65536:
        raise ValueError("bounded artifact build or source check refused")
    return result.stdout.decode("utf8", "strict").strip()


def digest(path: Path, maximum: int = 250_000_000) -> str:
    for ancestor in path.parents:
        if ancestor.name in {"bin", "site", "vendor", "deploy", "ansible", "templates"} and ancestor.is_symlink():
            raise ValueError("artifact parent link refused")
    stat = path.lstat()
    if (not path.is_file() or path.is_symlink() or stat.st_nlink != 1 or
            stat.st_size < 1 or stat.st_size > maximum or stat.st_uid != os.getuid()):
        raise ValueError("artifact file owner/size changed")
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def private_root(path: str) -> Path:
    root = Path(path)
    if (not root.is_absolute() or not root.exists() or root.is_symlink() or
            root.resolve() == REPO.resolve() or REPO.resolve() in root.resolve().parents):
        raise ValueError("private release state must pre-exist outside Git")
    stat = root.stat()
    if stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        raise ValueError("private release state owner/mode changed")
    return root


def verify(directory: Path) -> dict:
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError("release candidate directory unavailable")
    if directory.stat().st_uid != os.getuid() or directory.stat().st_mode & 0o077:
        raise ValueError("release candidate directory not private")
    raw = directory / "manifest.json"
    if raw.stat().st_size > 16384:
        raise ValueError("release manifest oversized")
    digest(raw, 16384)
    item = json.loads(raw.read_text(encoding="ascii"))
    if (item.get("schema") != 1 or not IDENTIFIER.fullmatch(str(item.get("artifact_id", ""))) or
            not COMMIT.fullmatch(str(item.get("commit", ""))) or
            item.get("files") is None or set(item["files"]) != set(FILES)):
        raise ValueError("release manifest shape invalid")
    for relative in FILES:
        expected = item["files"][relative]
        if (not isinstance(expected, str) or not DIGEST.fullmatch(expected) or
                digest(directory / relative) != expected):
            raise ValueError("release artifact hash mismatch")
    return item


def build(root: Path, artifact_id: str) -> dict:
    if not IDENTIFIER.fullmatch(artifact_id):
        raise ValueError("release artifact ID invalid")
    toolchain = run(["go", "version"], cwd=VGW)
    version = re.fullmatch(r"go version go1\.(\d+)\.(\d+) [a-z0-9/]+", toolchain)
    if version is None or (int(version[1]), int(version[2])) < (27, 4):
        raise ValueError("release requires patched Go 1.27.4 or later")
    if run(["git", "status", "--porcelain"], cwd=REPO):
        raise ValueError("public checkout has uncommitted changes")
    commit = run(["git", "rev-parse", "HEAD"], cwd=REPO)
    if not COMMIT.fullmatch(commit):
        raise ValueError("candidate Git revision unavailable")
    target = root / artifact_id
    if target.exists() or target.is_symlink():
        raise ValueError("release artifact ID already used")
    target.mkdir(mode=0o700)
    (target / "bin").mkdir(mode=0o700)
    (target / "site").mkdir(mode=0o700)
    (target / "site/vendor").mkdir(mode=0o700)
    marker = target / "build-intent.json"
    marker.write_text(json.dumps({"phase": "building", "artifact_id": artifact_id, "commit": commit}), encoding="ascii")
    marker.chmod(0o600)
    with marker.open("rb") as stream:
        os.fsync(stream.fileno())
    env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64", "GOPROXY": "off"}
    go = subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-o", str(target / "bin/vgw"), "./cmd/vgw"],
                        cwd=VGW, env=env, stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
    if go.returncode:
        raise ValueError("offline VGW build unavailable")
    run(["npm", "run", "build"], cwd=VGW / "softphone", timeout=120)
    if run(["git", "status", "--porcelain"], cwd=REPO):
        raise ValueError("candidate checkout changed during build")
    archive = subprocess.run(["git", "archive", "--format=tar", "-o", str(target / "source.tar"), "HEAD", "vgw"],
                             cwd=REPO, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, timeout=30)
    if archive.returncode:
        raise ValueError("committed source archive unavailable")
    for name in ("go.mod", "go.sum", "deploy/ansible/templates/voip-gateway.config.j2"):
        destination = target / name
        destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        shutil.copyfile(VGW / name, destination)
    for name in ("index.html", "app.js", "byok.js", "dial.js", "config.js", "style.css", "vendor/sip.min.js"):
        shutil.copyfile(VGW / "softphone/site" / name, target / "site" / name)
    hashes = {name: digest(target / name) for name in FILES}
    manifest = target / "manifest.json"
    manifest.write_text(json.dumps({"schema": 1, "artifact_id": artifact_id,
                                    "commit": commit, "files": hashes}, sort_keys=True), encoding="ascii")
    manifest.chmod(0o600)
    with manifest.open("rb") as stream:
        os.fsync(stream.fileno())
    marker.write_text(json.dumps({"phase": "built", "artifact_id": artifact_id,
                                   "commit": commit, "manifest_sha256": digest(manifest)}), encoding="ascii")
    with marker.open("rb") as stream:
        os.fsync(stream.fileno())
    result = verify(target)
    return result


def main() -> int:
    os.umask(0o077)
    cli = argparse.ArgumentParser(description=__doc__)
    group = cli.add_mutually_exclusive_group()
    group.add_argument("--build", action="store_true")
    group.add_argument("--verify", action="store_true")
    cli.add_argument("--id", default="")
    cli.add_argument("--state", default="")
    args = cli.parse_args()
    if not (args.build or args.verify):
        print("DRY_RUN_RELEASE_ARTIFACT_NO_DEVICE_OR_PROVIDER")
        return 0
    try:
        root = private_root(args.state)
        if not IDENTIFIER.fullmatch(args.id):
            raise ValueError("release artifact ID invalid")
        result = build(root, args.id) if args.build else verify(root / args.id)
        if result["artifact_id"] != args.id:
            raise ValueError("release manifest ID changed")
        print("RELEASE_ARTIFACT_" + ("BUILT" if args.build else "VERIFIED") + "_NO_DEPLOYMENT")
        return 0
    except (OSError, ValueError, TypeError, RuntimeError, subprocess.TimeoutExpired):
        print("RELEASE_ARTIFACT_REFUSED_SOURCE_OR_OWNER")
        return 2


if __name__ == "__main__":
    sys.exit(main())
