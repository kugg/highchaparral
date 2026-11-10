#!/usr/bin/env python3
"""Owner-pinned QEMU user-network staging of a committed VGW artifact.

Dry-run by default. Requires an operator-supplied Debian qcow2 with Docker,
Go, Node, offline npm cache and pinned images already installed. --stage
creates a persistent COW overlay, never changes the base disk. --start uses
QEMU user networking (restrict=on, IPv6 off, loopback SSH forward only).
--test copies the committed source archive over pinned SSH and invokes the
same local Docker regression inside the guest ONCE. It records a SYNTHETIC
attestation only; it cannot claim a full Eventphone/media release pass.
"""

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time

import release


VGW = release.VGW
ROOT = VGW.parent
SUBNET = ipaddress.ip_network("10.88.81.0/24")
SSH_PORT = 2291
GUEST_USER = re.compile(r"[a-z_][a-z0-9_-]{1,30}\Z")
IMAGE = re.compile(r"sha256:[a-f0-9]{64}\Z")
PHASES = {"staging", "prepared", "start-intent", "running", "test-intent", "synthetic-passed",
          "test-unknown", "stop-intent", "stopped", "force-stop-intent"}


def bounded(args: list[str], *, timeout: int = 20, cwd: Path = ROOT) -> str:
    result = subprocess.run(args, cwd=cwd, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    if result.returncode or len(result.stdout) > 16384:
        raise ValueError("bounded guest staging action refused")
    return result.stdout.decode("utf8", "strict").strip()


def private_file(path: Path, maximum: int) -> str:
    stat = path.lstat()
    if (not path.is_file() or path.is_symlink() or stat.st_nlink != 1 or
            stat.st_uid != os.getuid() or stat.st_mode & 0o077 or
            stat.st_size < 1 or stat.st_size > maximum):
        raise ValueError("private guest input owner/size changed")
    return release.digest(path, maximum)


def source_sha() -> str:
    return release.digest(Path(__file__).resolve(), 100_000)


def save(path: Path, data: dict) -> None:
    if data.get("phase") not in PHASES:
        raise ValueError("QEMU stage phase invalid")
    tmp = path.with_name(path.name + ".new")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as stream:
        json.dump(data, stream, sort_keys=True, separators=(",", ":"))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def record(state: Path) -> dict:
    directory = state.lstat()
    if state.is_symlink() or directory.st_uid != os.getuid() or directory.st_mode & 0o077:
        raise ValueError("QEMU private stage directory changed")
    path = state / "stage.json"
    private_file(path, 16384)
    item = json.loads(path.read_text(encoding="ascii"))
    if (item.get("phase") not in PHASES or item.get("source_sha") != source_sha() or
            not release.IDENTIFIER.fullmatch(str(item.get("id", ""))) or
            item.get("state") != str(state) or
            not release.DIGEST.fullmatch(str(item.get("artifact_sha", ""))) or
            item.get("guest_subnet") != str(SUBNET) or item.get("ssh_port") != SSH_PORT or
            item.get("base_sha") != private_file(Path(item["base"]), 80_000_000_000) or
            item.get("key_sha") != private_file(Path(item["ssh_key"]), 32768) or
            item.get("known_hosts_sha") != private_file(Path(item["known_hosts"]), 32768)):
        raise ValueError("QEMU staging source/owner/base changed")
    if item["phase"] != "staging":
        overlay = Path(item["overlay"])
        disk = overlay.lstat()
        if (not overlay.is_file() or overlay.is_symlink() or disk.st_nlink != 1 or
                disk.st_uid != os.getuid() or disk.st_mode & 0o077 or
                (disk.st_dev, disk.st_ino) != (item.get("overlay_dev"), item.get("overlay_ino"))):
            raise ValueError("QEMU owned COW overlay changed")
    manifest = release.verify(Path(item["artifact"]))
    if release.digest(Path(item["artifact"]) / "manifest.json", 16384) != item["artifact_sha"] or manifest["commit"] != item["commit"]:
        raise ValueError("QEMU staging artifact changed")
    return item


def host_routes() -> dict[str, str]:
    return {name: bounded(command, timeout=8) for name, command in {
        "inet": ["netstat", "-rn", "-f", "inet"],
        "inet6": ["netstat", "-rn", "-f", "inet6"],
        "nwi": ["scutil", "--nwi"],
    }.items()}


def network_candidates() -> dict[str, str]:
    sys.path.insert(0, str(VGW / "regression/browser_ari"))
    import runner # pure numeric parser/normalizer; no Docker action on import
    snapshot = host_routes()
    if any(net.prefixlen and net.overlaps(SUBNET) for net in runner.route_networks(snapshot["inet"])):
        raise ValueError("QEMU subnet overlaps host/VPN")
    ids = bounded(["docker", "network", "ls", "--format", "{{.ID}}"])
    if not ids:
        raise ValueError("Docker IPAM inventory unavailable")
    for entry in json.loads(bounded(["docker", "network", "inspect", *ids.splitlines()])):
        for cfg in entry.get("IPAM", {}).get("Config") or []:
            if cfg.get("Subnet") and ipaddress.ip_network(cfg["Subnet"], strict=False).overlaps(SUBNET):
                raise ValueError("QEMU subnet overlaps Docker")
    return snapshot


def host_equal(item: dict) -> None:
    sys.path.insert(0, str(VGW / "regression/browser_ari"))
    import runner
    original = {}
    for name, digest in item["network_before"].items():
        raw = Path(item["state"]) / ("network-before-" + name)
        if release.digest(raw, 2_000_000) != digest:
            raise ValueError("host prelaunch snapshot changed")
        original[name] = raw.read_text(encoding="utf8").strip()
    current = host_routes()
    for name in ("inet", "inet6", "nwi"):
        if runner.normalized(original[name], name) != runner.normalized(current[name], name):
            raise ValueError("macOS host topology changed; no repair")


def qemu_command(item: dict) -> list[str]:
    executable = shutil.which("qemu-system-x86_64")
    if not executable or not Path(executable).is_file():
        raise ValueError("reviewed QEMU executable missing")
    return [executable, "-name", "vgw-stage-" + item["id"], "-nodefaults", "-machine", "q35",
            "-accel", "tcg", "-cpu", "max", "-smp", "2", "-m", "4096",
            "-drive", "file=" + item["overlay"] + ",format=qcow2,if=virtio",
            "-netdev", "user,id=net0,restrict=on,ipv6=off,net=" + str(SUBNET) +
                       ",hostfwd=tcp:127.0.0.1:" + str(SSH_PORT) + "-:22",
            "-device", "virtio-net-pci,netdev=net0", "-display", "none",
            "-serial", "null", "-monitor", "none"]


def owned_pid(item: dict) -> bool:
    pid = item.get("pid")
    if not isinstance(pid, int) or pid < 2:
        return False
    try:
        os.kill(pid, 0)
        line = bounded(["ps", "-p", str(pid), "-o", "command="], timeout=6)
        uid = bounded(["ps", "-p", str(pid), "-o", "uid="], timeout=6)
    except (OSError, ValueError):
        return False
    return (uid == str(os.getuid()) and "qemu-system-x86_64" in line and "vgw-stage-" + item["id"] in line and
            item["overlay"] in line and "restrict=on,ipv6=off" in line and
            "127.0.0.1:" + str(SSH_PORT) in line)


def stage(args: argparse.Namespace) -> None:
    root = release.private_root(args.state)
    if (not re.fullmatch(r"[a-z0-9]{8,12}", args.id) or not release.IDENTIFIER.fullmatch(args.artifact) or
            not GUEST_USER.fullmatch(args.guest_user)):
        raise ValueError("QEMU stage ID or guest user invalid")
    artifact = root / args.artifact
    manifest = release.verify(artifact)
    base = Path(args.base)
    key = Path(args.ssh_key)
    known = Path(args.known_hosts)
    if not all(path.is_absolute() for path in (base, key, known)) or base.is_symlink():
        raise ValueError("private QEMU inputs must be absolute regular files")
    base_sha = private_file(base, 80_000_000_000)
    if base_sha != args.base_sha or not release.DIGEST.fullmatch(base_sha):
        raise ValueError("reviewed Debian qcow2 base SHA changed")
    info = json.loads(bounded(["qemu-img", "info", "--output=json", str(base)], timeout=12))
    if info.get("format") != "qcow2" or info.get("backing-filename"):
        raise ValueError("unreviewed QEMU base/backing chain")
    key_sha, known_sha = private_file(key, 32768), private_file(known, 32768)
    location = root / ("qemu-" + args.id)
    if location.exists() or location.is_symlink():
        raise ValueError("one-use QEMU staging owner already exists")
    location.mkdir(mode=0o700)
    item = {"phase": "staging", "id": args.id, "state": str(location), "artifact": str(artifact),
            "artifact_sha": release.digest(artifact / "manifest.json", 16384), "commit": manifest["commit"],
            "source_sha": source_sha(), "base": str(base), "base_sha": base_sha,
            "overlay": str(location / "guest.qcow2"), "ssh_key": str(key), "key_sha": key_sha,
            "known_hosts": str(known), "known_hosts_sha": known_sha,
            "guest_user": args.guest_user, "guest_subnet": str(SUBNET), "ssh_port": SSH_PORT,
            "pid": None, "network_before": {}, "result": ""}
    save(location / "stage.json", item)
    bounded(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(base), item["overlay"]], timeout=30)
    disk = Path(item["overlay"]).lstat()
    if not Path(item["overlay"]).is_file() or Path(item["overlay"]).is_symlink() or disk.st_uid != os.getuid() or disk.st_mode & 0o077:
        raise ValueError("QEMU COW overlay creation/owner unavailable")
    item["overlay_dev"], item["overlay_ino"] = disk.st_dev, disk.st_ino
    item["phase"] = "prepared"
    save(location / "stage.json", item)


def start(item: dict) -> None:
    if item["phase"] != "prepared" or owned_pid(item):
        raise ValueError("QEMU one-use owner already started")
    before = network_candidates()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", SSH_PORT))
    for name, body in before.items():
        path = Path(item["state"]) / ("network-before-" + name)
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(body.encode())
            stream.flush()
            os.fsync(stream.fileno())
    item["network_before"] = {name: hashlib.sha256(body.encode()).hexdigest() for name, body in before.items()}
    item["phase"] = "start-intent" # durable before QEMU launch
    save(Path(item["state"]) / "stage.json", item)
    child = subprocess.Popen(qemu_command(item), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
    item["pid"] = child.pid
    save(Path(item["state"]) / "stage.json", item)
    time.sleep(1)
    if not owned_pid(item):
        raise ValueError("QEMU exact process not verified")
    host_equal(item)
    item["phase"] = "running"
    save(Path(item["state"]) / "stage.json", item)


def ssh_args(item: dict) -> list[str]:
    return ["ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
            "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + item["known_hosts"],
            "-i", item["ssh_key"], "-p", str(SSH_PORT),
            item["guest_user"] + "@127.0.0.1"]


def verify_guest(item: dict) -> None:
    if item["phase"] not in {"running", "synthetic-passed"} or not owned_pid(item):
        raise ValueError("owned QEMU guest unavailable")
    host_equal(item)
    result = bounded(ssh_args(item) + ["sh", "-lc", "set +x; umask 077; test -r /proc/net/route && docker info --format '{{.ID}}'"],
                     timeout=10)
    if not re.fullmatch(r"[A-Za-z0-9:-]{12,128}", result):
        raise ValueError("guest Docker identity unavailable")


def synthetic_test(item: dict, images_path: str) -> None:
    if item["phase"] != "running" or not owned_pid(item):
        raise ValueError("QEMU synthetic test already used or unavailable")
    verify_guest(item)
    images_file = Path(images_path)
    if not images_file.is_absolute():
        raise ValueError("guest image pins require private absolute path")
    private_file(images_file, 4096)
    images = json.loads(images_file.read_text(encoding="ascii"))
    if set(images) != {"asterisk", "browser", "vgw"} or any(
        not isinstance(value, str) or not IMAGE.fullmatch(value) for value in images.values()
    ):
        raise ValueError("three pinned guest Docker image IDs required")
    home = "/home/" + item["guest_user"] + "/vgw-stage/" + item["id"]
    artifact = Path(item["artifact"])
    manifest = release.verify(artifact)
    source = artifact / "source.tar"
    executable = artifact / "bin/vgw"
    item["phase"] = "test-intent" # durable before SSH transfer or any guest call
    save(Path(item["state"]) / "stage.json", item)
    bounded(ssh_args(item) + ["sh", "-lc", "set +x; umask 077; mkdir -p " + home], timeout=10)
    scp = ["scp", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
           "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + item["known_hosts"],
           "-i", item["ssh_key"], "-P", str(SSH_PORT), str(source),
           item["guest_user"] + "@127.0.0.1:" + home + "/source.tar"]
    bounded(scp, timeout=120)
    bounded([*scp[:-2], str(executable), item["guest_user"] + "@127.0.0.1:" + home + "/vgw"], timeout=120)
    script = ("set +x; umask 077; "
              "cd " + home + " || exit 2; "
              "test \"$(sha256sum source.tar | cut -d' ' -f1)\" = " + release.digest(source) + " || exit 2; "
              "test \"$(sha256sum vgw | cut -d' ' -f1)\" = " + manifest["files"]["bin/vgw"] + " || exit 2; "
              "./vgw || exit 2; " # exact candidate binary smoke, never SIP
              "tar -xf source.tar || exit 2; "
              "cd vgw/softphone || exit 2; npm ci --offline --ignore-scripts --no-audit --no-fund >/dev/null 2>&1 && "
              "npm run build >/dev/null 2>&1 || exit 2; "
              "test \"$(sha256sum site/vendor/sip.min.js | cut -d' ' -f1)\" = " +
              manifest["files"]["site/vendor/sip.min.js"] + " || exit 2; "
              "cd ../regression/browser_ari || exit 2; "
              "export VGW_REGRESSION_RUN_ID=" + item["id"] + " REGRESSION_ASTERISK_IMAGE_ID=" + images["asterisk"] +
              " REGRESSION_BROWSER_IMAGE_ID=" + images["browser"] +
              " REGRESSION_RUNTIME_IMAGE_ID=" + images["vgw"] + "; "
              "python3 -B runner.py --stage || exit 2; "
              "if python3 -B runner.py --apply; then python3 -B runner.py --call; call=$?; else call=2; fi; "
              "python3 -B runner.py --rollback; rollback=$?; "
              "if test \"$call\" -eq 0 && test \"$rollback\" -eq 0; "
              "then echo GUEST_SYNTHETIC_PASSED; else echo GUEST_SYNTHETIC_UNKNOWN; exit 2; fi")
    try:
        output = bounded(ssh_args(item) + ["sh", "-lc", script], timeout=180)
        if ("GUEST_SYNTHETIC_PASSED" not in output.splitlines() or
                "DRY RUN: voip-gateway config/connector; no file, VM or provider network access" not in output.splitlines() or
                "REGRESSION_PASSED_SYNTHETIC_BROWSER_ANSWERED_BYE_ARI_SETTLED" not in output.splitlines() or
                "ONLY_OWNED_REGRESSION_RESOURCES_RETIRED_HOST_MATCHED" not in output.splitlines()):
            raise ValueError("guest synthetic pass/rollback not observed")
    except (OSError, ValueError, subprocess.TimeoutExpired):
        item["phase"] = "test-unknown"
        save(Path(item["state"]) / "stage.json", item)
        raise ValueError("guest test ambiguous; do not retry") from None
    item["phase"], item["result"] = "synthetic-passed", "synthetic-only"
    save(Path(item["state"]) / "stage.json", item)
    report = {"schema": 1, "commit": item["commit"], "artifact_sha": item["artifact_sha"],
              "base_sha": item["base_sha"], "images": images,
              "synthetic_browser_ari": "passed", "full_byok_provider": "blocked",
              "two_way_browser_media": "blocked", "production": "not-tested"}
    save(Path(item["state"]) / "synthetic-attestation.json", {**report, "phase": "synthetic-passed"})


def stop(item: dict, *, force: bool = False) -> None:
    if item["phase"] not in {"running", "synthetic-passed", "test-unknown", "test-intent", "stop-intent", "force-stop-intent"} or not owned_pid(item):
        raise ValueError("QEMU stop owner changed")
    item["phase"] = "force-stop-intent" if force else "stop-intent"
    save(Path(item["state"]) / "stage.json", item)
    if force:
        os.kill(item["pid"], signal.SIGTERM)
    else:
        bounded(ssh_args(item) + ["sh", "-lc", "set +x; umask 077; sudo -n systemctl poweroff"], timeout=10)
    for _ in range(30):
        if not owned_pid(item):
            break
        time.sleep(.5)
    else:
        raise ValueError("QEMU poweroff unconfirmed; no automatic force-stop")
    host_equal(item)
    item["phase"], item["pid"] = "stopped", None
    save(Path(item["state"]) / "stage.json", item)


def main() -> int:
    os.umask(0o077)
    cli = argparse.ArgumentParser(description=__doc__)
    group = cli.add_mutually_exclusive_group()
    for name in ("stage", "start", "verify_guest", "test", "stop", "force_stop", "status"):
        group.add_argument("--" + name.replace("_", "-"), action="store_true", dest=name)
    cli.add_argument("--state", default="")
    cli.add_argument("--id", default="")
    cli.add_argument("--artifact", default="")
    cli.add_argument("--base", default="")
    cli.add_argument("--base-sha", default="")
    cli.add_argument("--ssh-key", default="")
    cli.add_argument("--known-hosts", default="")
    cli.add_argument("--guest-user", default="")
    cli.add_argument("--images", default="")
    args = cli.parse_args()
    if not any(getattr(args, name) for name in ("stage", "start", "verify_guest", "test", "stop", "force_stop", "status")):
        print("DRY_RUN_QEMU_STAGING_NO_GUEST_OR_PROVIDER")
        return 0
    try:
        if args.stage:
            stage(args)
        else:
            root = release.private_root(args.state)
            if not release.IDENTIFIER.fullmatch(args.id):
                raise ValueError("QEMU stage ID invalid")
            item = record(root / ("qemu-" + args.id))
            if args.start: start(item)
            elif args.verify_guest: verify_guest(item)
            elif args.test: synthetic_test(item, args.images)
            elif args.stop: stop(item)
            elif args.force_stop: stop(item, force=True)
            else:
                print("QEMU_STAGE_PHASE_" + item["phase"].upper().replace("-", "_") + "_NO_ACTION")
                return 0
        print("QEMU_STAGE_" + ("PREPARED" if args.stage else "ACTION_CONFIRMED") + "_NO_PRODUCTION")
        return 0
    except (OSError, ValueError, TypeError, RuntimeError, subprocess.TimeoutExpired):
        print("QEMU_STAGE_REFUSED_SOURCE_OWNER_OR_TOPOLOGY")
        return 2


if __name__ == "__main__":
    sys.exit(main())
