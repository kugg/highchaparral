#!/usr/bin/env python3
"""One source-pinned synthetic browser→Asterisk→VGW Docker regression.

Default dry-run. Explicit --stage creates only private synthetic assets;
--apply creates one owned --internal bridge and capless Asterisk/browser
containers. A temporary exact-owned NET_ADMIN helper supplies a guest-only
route and exits BEFORE REGISTER. --call reserves one GO/INVITE before sending
it. --rollback removes only exact-owned containers/network and retains the
ignored result. Never use provider credentials or publish host ports.
"""

import argparse
import hashlib
import ipaddress
import json
import os
import platform
from pathlib import Path
import re
import secrets
import select
import ssl
import subprocess
import sys
import time

import profile


HERE = Path(__file__).resolve().parent
MODULE = HERE.parent.parent
RUN_ID = os.environ.get("VGW_REGRESSION_RUN_ID", "")
STATE = HERE / ".local-state" / (RUN_ID or "_unbound")
RECORD = STATE / "stage.json"
SOURCE = Path(__file__).resolve()
BROWSER = MODULE / "softphone/test/regression-ari-once.mjs"
BUNDLE = MODULE / "softphone/site/vendor/sip.min.js"
GO = MODULE / "cmd/regression-browser-ari/main.go"
GOTEST = MODULE / "cmd/regression-browser-ari/main_test.go"
ARI_PROBE = MODULE / "cmd/ari-browser-probe/main.go"
ARI_REGRESSION = MODULE / "cmd/ari-browser-probe/regression.go"
SETTLEMENT = MODULE / "internal/regressionutil/settlement.go"
HELPER = HERE / "default/main.go"
HELPERTEST = HERE / "default/main_test.go"
DOCKERFILE = HERE / "Dockerfile.asterisk"
SUBNET = ipaddress.ip_network("10.254.251.0/24")
GATEWAY = "10.254.251.1"
NETWORK = "vgw-regression-browser-ari-" + RUN_ID
NAMES = {name: "vgw-regression-" + name + "-" + RUN_ID for name in ("asterisk", "browser", "vgw", "helper")}
PHASES = {"staging", "prepared", "network-intent", "network-ready", "asterisk-intent", "asterisk-ready",
          "browser-intent", "browser-ready", "helper-intent", "helper-ready", "browser-preparing",
          "vgw-intent", "invite-intent", "passed", "unknown", "rollback-intent", "rolled-back"}
IMAGES = {"asterisk": "REGRESSION_ASTERISK_IMAGE_ID", "browser": "REGRESSION_BROWSER_IMAGE_ID",
          "vgw": "REGRESSION_RUNTIME_IMAGE_ID"}
IMAGE = re.compile(r"sha256:[a-f0-9]{64}\Z")


def say(code: str) -> None:
    from datetime import datetime, timezone
    print(datetime.now(timezone.utc).isoformat(timespec="seconds") + " " + code, flush=True)


def cmd(args: list[str], *, timeout: int = 12, required: bool = True) -> tuple[bool, str]:
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError("bounded owner action unavailable") from exc
    if len(result.stdout) > 65536 or result.returncode and required:
        raise ValueError("bounded owner action refused")
    return result.returncode == 0, result.stdout.decode("utf8", "strict").strip()


def sha(path: Path, maximum: int = 2_000_000) -> str:
    stat = path.lstat()
    if not path.is_file() or path.is_symlink() or stat.st_nlink != 1 or stat.st_uid != os.getuid() or stat.st_size > maximum:
        raise ValueError("source or private file ownership changed")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic(path: Path, data: dict) -> None:
    if path.is_symlink():
        raise ValueError("private record link refused")
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


def private(path: Path, body: bytes) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(body)
        stream.flush()
        os.fsync(stream.fileno())


def sources() -> dict:
    return {p.relative_to(MODULE).as_posix(): sha(p) for p in
            (SOURCE, HERE / "profile.py", BROWSER, GO, GOTEST, ARI_PROBE, ARI_REGRESSION,
             SETTLEMENT, MODULE / "internal/asterisk/ari.go", MODULE / "internal/asterisk/browser_event.go",
             MODULE / "internal/asterisk/media.go", MODULE / "go.mod", MODULE / "go.sum",
             HELPER, HELPERTEST, DOCKERFILE,
             MODULE / "softphone/package.json", MODULE / "softphone/package-lock.json",
             MODULE / "softphone/node_modules/playwright/package.json", BUNDLE)}


def playwright_version() -> str:
    package = MODULE / "softphone/package.json"
    lock = MODULE / "softphone/package-lock.json"
    installed = MODULE / "softphone/node_modules/playwright/package.json"
    for path in (package, lock, installed):
        sha(path)
    declared = json.loads(package.read_text(encoding="utf8"))["devDependencies"]["playwright"]
    locked = json.loads(lock.read_text(encoding="utf8"))["packages"]["node_modules/playwright"]["version"]
    actual = json.loads(installed.read_text(encoding="utf8"))["version"]
    if (not isinstance(declared, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", declared) or
            declared != locked or declared != actual):
        raise ValueError("Playwright package/lock/runtime version changed")
    return declared


def docker_identity() -> dict:
    _, context = cmd(["docker", "context", "show"])
    _, daemon = cmd(["docker", "info", "--format", "{{.ID}}"])
    expected = "default" if platform.system() == "Linux" else "desktop-linux"
    if context != expected or not re.fullmatch(r"[A-Za-z0-9:-]{12,128}", daemon):
        raise ValueError("reviewed host/guest Docker daemon unavailable")
    return {"context": context, "daemon": daemon}


def image_ids(expected: dict | None = None) -> dict:
    if expected is not None and not isinstance(expected, dict):
        raise ValueError("pinned image manifest invalid")
    result = {}
    for name, variable in IMAGES.items():
        value = expected.get(name, "") if expected is not None else os.environ.get(variable, "")
        if expected is not None and os.environ.get(variable) not in (None, value):
            raise ValueError("pinned image override changed")
        if not IMAGE.fullmatch(value):
            raise ValueError("operator must pin three local image IDs")
        ok, raw = cmd(["docker", "image", "inspect", value,
                       "--format", "{{.Id}} {{.Os}} {{.Architecture}}"], required=False)
        if not ok or raw != value + " linux amd64":
            raise ValueError("pinned image platform/identity unavailable")
        if name == "browser":
            ok, tags = cmd(["docker", "image", "inspect", value,
                            "--format", "{{json .RepoTags}}"], required=False)
            expected_tag = "mcr.microsoft.com/playwright:v" + playwright_version() + "-noble"
            names = json.loads(tags) if ok else None
            if not isinstance(names, list) or expected_tag not in names:
                raise ValueError("pinned browser image does not match locked Playwright")
        result[name] = value
    return result


def container(name: str) -> list[str] | None:
    ok, raw = cmd(["docker", "inspect", "--type", "container", name,
                   "--format", "{{.Id}} {{index .Config.Labels \"org.vgw.regression\"}} {{.State.Running}}"],
                  required=False)
    if not ok:
        return None
    fields = raw.split()
    if len(fields) != 3 or not re.fullmatch(r"[a-f0-9]{64}", fields[0]):
        raise ValueError("Docker container owner readback invalid")
    return fields


def owned(data: dict, role: str, running: str | None = None) -> bool:
    current = container(NAMES[role])
    return current is not None and current[:2] == [data["containers"].get(role), data["owner"]] and (
        running is None or current[2] == running)


def inspect_network() -> dict | None:
    ok, raw = cmd(["docker", "network", "inspect", NETWORK], required=False)
    if not ok:
        return None
    values = json.loads(raw)
    if not isinstance(values, list) or len(values) != 1:
        raise ValueError("internal network inspect ambiguous")
    return values[0]


def network(data: dict, *, allow_unrecorded: bool = False) -> dict:
    net = inspect_network()
    if net is None:
        raise ValueError("owned internal network absent")
    configs = net.get("IPAM", {}).get("Config") or []
    if (not re.fullmatch(r"[a-f0-9]{64}", str(net.get("Id", ""))) or
            (not allow_unrecorded and net["Id"] != data["network_id"]) or
            net.get("Name") != NETWORK or net.get("Driver") != "bridge" or
            net.get("Scope") != "local" or net.get("Internal") is not True or
            net.get("EnableIPv6") is not False or net.get("Ingress") is not False or
            net.get("Labels", {}).get("org.vgw.regression") != data["owner"] or
            len(configs) != 1 or configs[0].get("Subnet") != str(SUBNET) or
            configs[0].get("Gateway") != GATEWAY):
        raise ValueError("foreign or non-internal Docker network")
    return net


def routes() -> dict[str, str]:
    if platform.system() == "Linux": # only inside an independently owned QEMU staging guest
        return {"inet": Path("/proc/net/route").read_text(encoding="ascii"),
                "inet6": Path("/proc/net/ipv6_route").read_text(encoding="ascii"),
                "nwi": "\n".join(sorted(path.name for path in Path("/sys/class/net").iterdir()))}
    if platform.system() != "Darwin":
        raise ValueError("unsupported host network snapshot platform")
    return {name: cmd(command, timeout=8)[1] for name, command in {
        "inet": ["netstat", "-rn", "-f", "inet"],
        "inet6": ["netstat", "-rn", "-f", "inet6"],
        "nwi": ["scutil", "--nwi"],
    }.items()}


def route_networks(table: str) -> list[ipaddress.IPv4Network]:
    found = []
    if table.startswith("Iface\tDestination\t"):
        for line in table.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 8 or not re.fullmatch(r"[a-f0-9A-F]{8}", fields[1]) or not re.fullmatch(r"[a-f0-9A-F]{8}", fields[7]):
                raise ValueError("guest IPv4 table not parseable")
            address = ipaddress.IPv4Address(int.from_bytes(bytes.fromhex(fields[1]), "little"))
            mask = ipaddress.IPv4Address(int.from_bytes(bytes.fromhex(fields[7]), "little"))
            found.append(ipaddress.ip_network((address, str(mask)), strict=False))
        if not found:
            raise ValueError("guest IPv4 table empty")
        return found
    for line in table.splitlines():
        first = line.split(maxsplit=1)[0] if line.split() else ""
        if not first or not first[0].isdigit() or ":" in first:
            continue
        address, slash, prefix = first.partition("/")
        parts = address.split(".")
        if len(parts) > 4:
            raise ValueError("IPv4 host table not parseable")
        padded = ".".join(parts + ["0"] * (4 - len(parts)))
        length = int(prefix) if slash else (8 * len(parts) if len(parts) < 4 else 32)
        found.append(ipaddress.ip_network(padded + "/" + str(length), strict=False))
    if not found:
        raise ValueError("IPv4 route inventory empty")
    return found


def candidate() -> None:
    host = routes()
    if any(subnet.prefixlen and subnet.overlaps(SUBNET) for subnet in route_networks(host["inet"])):
        raise ValueError("private subnet overlaps host/VPN")
    _, raw = cmd(["docker", "network", "ls", "--format", "{{.ID}}"])
    ids = raw.splitlines()
    if not ids:
        raise ValueError("Docker networks unavailable")
    _, raw = cmd(["docker", "network", "inspect", *ids], timeout=10)
    for value in json.loads(raw):
        for entry in value.get("IPAM", {}).get("Config") or []:
            if entry.get("Subnet") and ipaddress.ip_network(entry["Subnet"], strict=False).overlaps(SUBNET):
                raise ValueError("private subnet overlaps Docker")
    if inspect_network() or any(container(n) for n in NAMES.values()):
        raise ValueError("synthetic Docker name already owned or foreign")
    say("REGRESSION_NUMERIC_HOST_VPN_DOCKER_NONOVERLAP")


def normalized(text: str, family: str, owned_bridge: str | None = None) -> tuple:
    if family == "nwi":
        if not ("Network interfaces:" in text or "IPv4 network interface information" in text):
            return tuple(sorted(name for name in text.splitlines() if name != owned_bridge))
        return tuple(line.strip() for line in text.splitlines() if
                     line.strip().startswith(("en", "utun", "Network interfaces:")) or "address" in line)
    if family == "inet" and text.startswith("Iface\tDestination\t"):
        return tuple(sorted((parts[0], parts[1], parts[2], parts[3], parts[7])
                            for parts in (line.split() for line in text.splitlines()[1:]) if len(parts) >= 8 and
                            not (parts[0] == owned_bridge and parts[1] == "00FBFE0A" and parts[7] == "00FFFFFF")))
    if family == "inet6" and text and all(len(line.split()) >= 10 for line in text.splitlines()):
        return tuple(sorted((parts[0], parts[1], parts[4], parts[5], parts[9])
                            for parts in (line.split() for line in text.splitlines()) if len(parts) >= 10))
    rows = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[0] in {"Destination", "Routing", "Internet:", "Internet6:"}:
            continue
        dest, gateway, flags, iface = fields[:4]
        if "W" in flags or ("L" in flags and "H" in flags) or dest.startswith(("ff", "224.")):
            continue # neighbor-cache/multicast churn is not host route ownership
        rows.append((dest, gateway, "".join(ch for ch in flags if ch in "UGHSC"), iface))
    return tuple(sorted(rows))


def compare(data: dict) -> None:
    if set(data.get("network_before", {})) != {"inet", "inet6", "nwi"}:
        raise ValueError("prelaunch host snapshot absent")
    current = routes()
    owned_bridge = None
    if platform.system() == "Linux" and inspect_network():
        owned_bridge = "br-" + network(data)["Id"][:12]
    for name, want in data["network_before"].items():
        raw = (STATE / ("network-before-" + name)).read_bytes()
        if len(raw) > 2_000_000 or hashlib.sha256(raw).hexdigest() != want:
            raise ValueError("host snapshot changed")
        if normalized(raw.decode("utf8", "strict"), name) != normalized(current[name], name, owned_bridge):
            raise ValueError("host topology changed; no host repair")


def save(data: dict) -> None:
    if data.get("phase") not in PHASES:
        raise ValueError("invalid regression phase")
    atomic(RECORD, data)
    intent_dir = STATE / "browser-intent"
    if intent_dir.is_dir() and not intent_dir.is_symlink():
        atomic(intent_dir / "stage.json", browser_intent(data))


def browser_intent(data: dict) -> dict:
    # No ARI password, Docker IDs, Go env-file, private path, or config.
    return {key: data[key] for key in ("phase", "owner", "nonce", "browser_sha", "bundle_sha", "cert_sha")}


def read_browser_intent() -> dict:
    path = STATE / "browser-intent/stage.json"
    sha(path, 8192) # nofollow/owned before parsing a browser-visible record
    return json.loads(path.read_text(encoding="ascii"))


def read_stage() -> dict:
    stat = STATE.lstat()
    if STATE.is_symlink() or stat.st_uid != os.getuid() or stat.st_mode & 0o077:
        raise ValueError("private stage directory changed")
    sha(RECORD, 8192) # refuse links and foreign/oversized records before read
    return json.loads(RECORD.read_text(encoding="ascii"))


def state() -> dict:
    data = read_stage()
    if (not re.fullmatch(r"[a-f0-9]{32}", str(data.get("owner", ""))) or
            data.get("phase") not in PHASES or data.get("sources") != sources() or
            data.get("images") != image_ids(data.get("images")) or data.get("docker") != docker_identity() or
            data.get("run_id") != RUN_ID or
            data.get("outputs", {}).get("binary") != sha(STATE / "bin/regression-browser-ari", 32_000_000) or
            data.get("outputs", {}).get("ari_probe") != sha(STATE / "bin/ari-browser-probe", 32_000_000) or
            (STATE / "bin/regression-browser-ari").stat().st_mode & 0o777 != 0o755 or
            (STATE / "bin/ari-browser-probe").stat().st_mode & 0o777 != 0o755 or
            data.get("outputs", {}).get("helper") != sha(STATE / "bin/internal-default", 5_000_000) or
            data.get("outputs", {}).get("cert") != sha(STATE / "asterisk/keys/home.crt", 16384) or
            (STATE / "asterisk/keys/home.crt").stat().st_mode & 0o777 != 0o644 or
            data.get("outputs", {}).get("key") != sha(STATE / "asterisk/keys/home.key", 16384) or
            data.get("outputs", {}).get("browser_key") != sha(STATE / "browser-fixture/asterisk/keys/home.key", 16384) or
            data.get("outputs", {}).get("browser_cert") != sha(STATE / "browser-fixture/asterisk/keys/home.crt", 16384) or
            data.get("outputs", {}).get("credentials") != sha(STATE / "browser-fixture/credentials.json", 4096) or
            data.get("outputs", {}).get("environment") != sha(STATE / "mock.env", 4096) or
            data.get("outputs", {}).get("configs") !=
                {name: sha(STATE / "asterisk" / name, 16384) for name in profile.render("B" * 32, "R" * 32)} or
            data.get("outputs", {}).get("bundle") != sha(BUNDLE) or
            data.get("bundle_sha") != sha(BUNDLE) or
            data.get("browser_sha") != sha(BROWSER) or
            read_browser_intent() != browser_intent(data)):
        raise ValueError("regression owner/source/output pin changed")
    return data


def stage() -> None:
    if not re.fullmatch(r"[a-z0-9]{8,12}", RUN_ID):
        raise ValueError("new 8-12 character lowercase run ID required")
    if STATE.exists() or STATE.is_symlink():
        raise ValueError("one-use regression stage already exists")
    candidate()
    files = sources()
    images = image_ids()
    docker = docker_identity()
    playwright_version()
    parent = STATE.parent
    if parent.exists():
        stat = parent.lstat()
        if parent.is_symlink() or stat.st_uid != os.getuid() or stat.st_mode & 0o077:
            raise ValueError("private stage parent changed")
    else:
        parent.mkdir(mode=0o700)
    STATE.mkdir(mode=0o700)
    owner = secrets.token_hex(16)
    save({"phase": "staging", "run_id": RUN_ID, "owner": owner, "sources": files,
          "images": images, "docker": docker, "outputs": {}, "network_id": "",
          "network_before": {}, "containers": {}, "nonce": "", "browser": "", "mock": "", "result": ""})
    (STATE / "asterisk").mkdir(mode=0o700)
    (STATE / "asterisk/keys").mkdir(mode=0o700)
    (STATE / "browser-fixture").mkdir(mode=0o700)
    (STATE / "browser-fixture/asterisk").mkdir(mode=0o700)
    (STATE / "browser-fixture/asterisk/keys").mkdir(mode=0o700)
    (STATE / "browser-intent").mkdir(mode=0o700)
    (STATE / "bin").mkdir(mode=0o700)
    browser, ari, token = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_hex(16)
    for name, body in profile.render(browser, ari).items():
        private(STATE / "asterisk" / name, body.encode("ascii"))
    private(STATE / "browser-fixture/credentials.json", json.dumps({"browser": browser}).encode("ascii"))
    private(STATE / "mock.env", ("HOME_MOCK_ARI_USER=home-control\nHOME_MOCK_ARI_PASSWORD=" + ari +
                                 "\nHOME_MOCK_NONCE=" + token + "\n").encode("ascii"))
    result = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
                             "-days", "2", "-keyout", str(STATE / "asterisk/keys/home.key"),
                             "-out", str(STATE / "asterisk/keys/home.crt"), "-subj", "/CN=localhost",
                             "-addext", "subjectAltName=IP:127.0.0.1"],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=30)
    if result.returncode:
        raise ValueError("synthetic certificate unavailable")
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(str(STATE / "asterisk/keys/home.crt"), str(STATE / "asterisk/keys/home.key"))
    # The Go mock runs nonroot and receives only this PUBLIC leaf by file
    # bind; the containing host stage remains 0700 and the key stays 0600.
    (STATE / "asterisk/keys/home.crt").chmod(0o644)
    for name in ("home.crt", "home.key"):
        path = STATE / "asterisk/keys" / name
        sha(path, 16384)
        private(STATE / "browser-fixture/asterisk/keys" / name, path.read_bytes())
    env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64", "GOPROXY": "off"}
    for workdir, target, package in (
        (MODULE, STATE / "bin/regression-browser-ari", "./cmd/regression-browser-ari"),
        (MODULE, STATE / "bin/ari-browser-probe", "./cmd/ari-browser-probe"),
        (HERE / "default", STATE / "bin/internal-default", "."),
    ):
        build = subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-o", str(target), package],
                               cwd=workdir, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
        if build.returncode:
            raise ValueError("offline synthetic Go build unavailable")
        target.chmod(0o700 if target.name == "internal-default" else 0o755)
    if files != sources():
        raise ValueError("regression sources changed during stage")
    output = {"binary": sha(STATE / "bin/regression-browser-ari", 32_000_000),
              "ari_probe": sha(STATE / "bin/ari-browser-probe", 32_000_000),
              "helper": sha(STATE / "bin/internal-default", 5_000_000),
              "cert": sha(STATE / "asterisk/keys/home.crt", 16384),
              "key": sha(STATE / "asterisk/keys/home.key", 16384),
              "browser_cert": sha(STATE / "browser-fixture/asterisk/keys/home.crt", 16384),
              "browser_key": sha(STATE / "browser-fixture/asterisk/keys/home.key", 16384),
              "credentials": sha(STATE / "browser-fixture/credentials.json", 4096),
              "environment": sha(STATE / "mock.env", 4096),
              "configs": {name: sha(STATE / "asterisk" / name, 16384)
                          for name in profile.render("B" * 32, "R" * 32)},
              "bundle": sha(BUNDLE)}
    save({"phase": "prepared", "run_id": RUN_ID, "owner": owner, "nonce": token, "sources": files,
          "images": images, "docker": docker, "outputs": output, "bundle_sha": output["bundle"],
          "cert_sha": output["cert"], "browser_sha": sha(BROWSER), "network_id": "",
          "network_before": {}, "containers": {}, "browser": "", "mock": "", "result": ""})
    say("REGRESSION_STAGED_PRIVATE_SYNTHETIC_NO_NETWORK")


def apply() -> None:
    data = state()
    if data["phase"] != "prepared" or data["containers"]:
        raise ValueError("one-use regression already started")
    candidate()
    snapshots = routes()
    for name, body in snapshots.items():
        private(STATE / ("network-before-" + name), body.encode())
    data["network_before"] = {name: hashlib.sha256(body.encode()).hexdigest() for name, body in snapshots.items()}
    data["phase"] = "network-intent"
    save(data)
    network_id = cmd(["docker", "network", "create", "--driver", "bridge", "--internal", "--ipv6=false",
                      "--subnet", str(SUBNET), "--gateway", GATEWAY,
                      "--label", "org.vgw.regression=" + data["owner"], NETWORK], timeout=25)[1]
    if not re.fullmatch(r"[a-f0-9]{64}", network_id):
        raise ValueError("internal network creation uncertain")
    data["network_id"] = network_id
    data["phase"] = "network-ready"
    save(data)
    network(data)
    compare(data) # no container before host parity passes
    data["phase"] = "asterisk-intent"
    save(data)
    args = ["docker", "run", "-d", "--name", NAMES["asterisk"],
            "--label", "org.vgw.regression=" + data["owner"], "--network", NETWORK,
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pull", "never", "--pids-limit", "256", "--memory", "512m"]
    for path in ("/run/asterisk:rw,mode=0700,size=16m", "/var/log/asterisk:rw,mode=0700,size=16m",
                 "/var/spool/asterisk:rw,mode=0700,size=16m", "/tmp:rw,mode=0700,size=16m"):
        args += ["--tmpfs", path]
    args += ["--mount", "type=bind,src=" + str(STATE / "asterisk") + ",dst=/etc/asterisk,readonly",
             "--platform", "linux/amd64", data["images"]["asterisk"], "-f", "-C", "/etc/asterisk/asterisk.conf"]
    cid = cmd(args, timeout=30)[1]
    if not re.fullmatch(r"[a-f0-9]{64}", cid):
        raise ValueError("Asterisk container start uncertain")
    data["containers"]["asterisk"] = cid
    data["phase"] = "asterisk-ready"
    save(data)
    if not owned(data, "asterisk", "true") or set(network(data).get("Containers") or {}) != {cid}:
        raise ValueError("Asterisk private network ownership changed")
    for _ in range(30):
        ok, _ = cmd(["docker", "exec", cid, "/usr/sbin/asterisk", "-rx", "core show version"], timeout=4, required=False)
        if ok:
            break
        time.sleep(.2)
    else:
        raise ValueError("owned Asterisk unavailable")
    data["phase"] = "browser-intent"
    save(data)
    args = ["docker", "create", "-i", "--name", NAMES["browser"],
            "--label", "org.vgw.regression=" + data["owner"], "--network", "container:" + cid,
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pull", "never", "--pids-limit", "512", "--memory", "1536m", "--shm-size", "256m",
            "--tmpfs", "/tmp:rw,mode=1777,size=512m",
            "--mount", "type=bind,src=" + str(MODULE / "softphone/test") + ",dst=/work/test,readonly",
            "--mount", "type=bind,src=" + str(MODULE / "softphone/node_modules") + ",dst=/work/node_modules,readonly",
            "--mount", "type=bind,src=" + str(STATE / "browser-fixture") + ",dst=/fixture,readonly",
            "--mount", "type=bind,src=" + str(STATE / "browser-intent") + ",dst=/intent,readonly",
            "--mount", "type=bind,src=" + str(BUNDLE) + ",dst=/bundle/sip.min.js,readonly",
            "--platform", "linux/amd64", "--entrypoint", "node", data["images"]["browser"],
            "/work/test/regression-ari-once.mjs", "--run"]
    bid = cmd(args, timeout=25)[1]
    if not re.fullmatch(r"[a-f0-9]{64}", bid):
        raise ValueError("browser create uncertain")
    data["containers"]["browser"] = bid
    data["phase"] = "browser-ready"
    save(data)
    data["phase"] = "helper-intent"
    save(data)
    args = ["docker", "create", "--name", NAMES["helper"],
            "--label", "org.vgw.regression=" + data["owner"], "--network", "container:" + cid,
            "--read-only", "--cap-drop", "ALL", "--cap-add", "NET_ADMIN",
            "--security-opt", "no-new-privileges", "--pull", "never", "--pids-limit", "32",
            "--memory", "64m", "--user", "0:0",
            "--mount", "type=bind,src=" + str(STATE / "bin/internal-default") +
                       ",dst=/usr/local/bin/internal-default,readonly",
            "--platform", "linux/amd64", "--entrypoint", "/usr/local/bin/internal-default",
            data["images"]["vgw"]]
    hid = cmd(args, timeout=25)[1]
    if not re.fullmatch(r"[a-f0-9]{64}", hid):
        raise ValueError("guest-only helper creation uncertain")
    data["containers"]["helper"] = hid
    data["phase"] = "helper-ready"
    save(data)
    _, raw = cmd(["docker", "inspect", "--type", "container", hid, "--format", "{{json .HostConfig}}"])
    info = json.loads(raw)
    if (not owned(data, "helper", "false") or info.get("NetworkMode") != "container:" + cid or
            info.get("CapDrop") != ["ALL"] or info.get("CapAdd") != ["CAP_NET_ADMIN"] or
            info.get("Privileged") or info.get("PortBindings")):
        raise ValueError("guest-only helper capability/network changed")
    ok, result = cmd(["docker", "start", "-a", hid], timeout=12, required=False)
    if not ok or result != "MOCK_INTERNAL_DEFAULT_READY":
        raise ValueError("guest-only helper uncertain, no retry")
    _, raw = cmd(["docker", "inspect", "--type", "container", hid, "--format", "{{json .State}}"])
    if json.loads(raw).get("ExitCode") != 0:
        raise ValueError("guest-only helper exit uncertain")
    cmd(["docker", "rm", hid], timeout=12)
    if container(NAMES["helper"]):
        raise ValueError("privileged helper remains")
    data["phase"] = "browser-preparing"
    save(data)
    compare(data)
    say("REGRESSION_PRIVATE_BROWSER_READY_NO_SIP")


def call() -> None:
    data = state()
    if (data["phase"] != "browser-preparing" or not owned(data, "asterisk", "true") or
            not owned(data, "browser", "false") or container(NAMES["helper"]) or
            set(network(data).get("Containers") or {}) != {data["containers"]["asterisk"]}):
        raise ValueError("one-use call owner/private network changed")
    child = subprocess.Popen(["docker", "start", "-ai", data["containers"]["browser"]],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        readable, _, _ = select.select([child.stdout], [], [], 85)
        first = child.stdout.readline().decode("ascii", "strict").strip() if readable else ""
        if first != "BROWSER_READY":
            data["phase"], data["browser"] = "unknown", "BROWSER_REGISTER_UNCONFIRMED"
            save(data)
            raise ValueError("browser registration unconfirmed; no SIP GO")
        data["phase"] = "vgw-intent"
        save(data)
        args = ["docker", "run", "-d", "--name", NAMES["vgw"],
                "--label", "org.vgw.regression=" + data["owner"],
                "--network", "container:" + data["containers"]["asterisk"],
                "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--pull", "never", "--pids-limit", "128", "--memory", "256m", "--user", "65534:65534",
                "--env-file", str(STATE / "mock.env"),
                "--mount", "type=bind,src=" + str(STATE / "asterisk/keys/home.crt") +
                           ",dst=/tmp/vgw-regression-ari-peer.crt,readonly",
                "--mount", "type=bind,src=" + str(STATE / "bin/ari-browser-probe") +
                           ",dst=/usr/local/bin/ari-browser-probe,readonly",
                "--mount", "type=bind,src=" + str(STATE / "bin/regression-browser-ari") +
                           ",dst=/usr/local/bin/regression-browser-ari,readonly",
                "--platform", "linux/amd64", "--entrypoint", "/usr/local/bin/regression-browser-ari",
                data["images"]["vgw"]]
        mid = cmd(args, timeout=25)[1]
        if not re.fullmatch(r"[a-f0-9]{64}", mid):
            raise ValueError("VGW mock launch uncertain")
        data["containers"]["vgw"] = mid
        save(data)
        for _ in range(25):
            _, logs = cmd(["docker", "logs", mid], timeout=4, required=False)
            if "MOCK_WATCHER_READY" in logs.splitlines():
                break
            time.sleep(.2)
        else:
            raise ValueError("ARI watcher unconfirmed; no SIP GO")
        data["phase"] = "invite-intent" # durable BEFORE sending one browser GO
        save(data)
        child.stdin.write(b"GO\n")
        child.stdin.flush()
        stdout, _ = child.communicate(timeout=75)
        response = stdout.decode("ascii", "strict").strip()
        data["browser"] = response if re.fullmatch(r"BROWSER_RESULT phase=invite category=[A-Z0-9_]+", response) else "BROWSER_INVITE_UNKNOWN"
        _, logs = cmd(["docker", "logs", mid], timeout=6, required=False)
        markers = set(logs.splitlines())
        approved = {"MOCK_WATCHER_READY", "MOCK_BROWSER_ADMITTED", "MOCK_ATTACH_OK",
                    "MOCK_PROVIDER_200_ANSWERED", "MOCK_PROVIDER_SETTLED_LOCAL_ONLY"}
        data["mock"] = "MOCK_PROVIDER_SETTLED_LOCAL_ONLY" if approved <= markers else "MOCK_INCOMPLETE"
        ok, channels = cmd(["docker", "exec", data["containers"]["asterisk"],
                            "/usr/sbin/asterisk", "-rx", "core show channels count"], timeout=6, required=False)
        data["phase"] = "passed" if (data["browser"].endswith("SIP_ANSWERED_ENDED") and
            data["mock"] == "MOCK_PROVIDER_SETTLED_LOCAL_ONLY" and ok and "0 active" in channels) else "unknown"
        data["result"] = "synthetic-browser-answered-bye-ari-settled" if data["phase"] == "passed" else "synthetic-unconfirmed"
        save(data)
        say("REGRESSION_" + data["phase"].upper() + "_" + data["result"].upper().replace("-", "_"))
    except (OSError, ValueError, TypeError, subprocess.TimeoutExpired):
        data["phase"] = "unknown"
        save(data)
        raise ValueError("one-use synthetic delivery uncertain") from None
    finally:
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=5)


def rollback() -> None:
    partial = read_stage()
    if partial.get("phase") == "staging":
        if (not re.fullmatch(r"[a-f0-9]{32}", str(partial.get("owner"))) or
                partial.get("sources") != sources() or partial.get("docker") != docker_identity() or
                partial.get("images") != image_ids(partial.get("images")) or
                partial.get("run_id") != RUN_ID or inspect_network() or
                any(container(n) for n in NAMES.values())):
            raise ValueError("incomplete stage ownership changed")
        partial["phase"] = "rolled-back"
        save(partial) # retain incomplete private files for reviewed recovery
        say("INCOMPLETE_PRIVATE_STAGE_RETIRED_NO_NETWORK")
        return
    data = state()
    if data["phase"] == "prepared":
        if inspect_network() or data["containers"] or any(container(n) for n in NAMES.values()):
            raise ValueError("prepared stage has unexpected resource")
        data["phase"] = "rolled-back"
        save(data)
        say("PREPARED_PRIVATE_STAGE_RETIRED_NO_NETWORK")
        return
    if data["phase"] == "rolled-back":
        raise ValueError("no owned regression resources to retire")
    for name, label in NAMES.items():
        item = container(label)
        if item and item[:2] != [data["containers"].get(name), data["owner"]]:
            raise ValueError("foreign regression container; no stop")
    item = inspect_network()
    if item and network(data, allow_unrecorded=not data["network_id"]).get("Containers"):
        attached = set(item.get("Containers") or {})
        if attached - {data["containers"].get("asterisk")}:
            raise ValueError("foreign bridge attachment; no removal")
    data["phase"] = "rollback-intent"
    save(data)
    for role in ("vgw", "helper", "browser", "asterisk"):
        observed = container(NAMES[role])
        if observed:
            if observed[2] == "true":
                cmd(["docker", "stop", "--time", "5", NAMES[role]], timeout=12)
            cmd(["docker", "rm", NAMES[role]], timeout=12)
    if inspect_network():
        if network(data, allow_unrecorded=not data["network_id"]).get("Containers"):
            raise ValueError("owned bridge still attached")
        data["network_id"] = inspect_network()["Id"]
        save(data)
        cmd(["docker", "network", "rm", data["network_id"]], timeout=20)
    if inspect_network():
        raise ValueError("owned internal bridge still exists")
    compare(data)
    data["phase"] = "rolled-back"
    save(data)
    say("ONLY_OWNED_REGRESSION_RESOURCES_RETIRED_HOST_MATCHED")


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    for option in ("stage", "apply", "call", "rollback", "status"):
        group.add_argument("--" + option, action="store_true")
    flags = parser.parse_args()
    if not any(getattr(flags, option) for option in ("stage", "apply", "call", "rollback", "status")):
        say("DRY_RUN_SYNTHETIC_BROWSER_ARI_REGRESSION_NO_NETWORK")
        return 0
    if not re.fullmatch(r"[a-z0-9]{8,12}", RUN_ID):
        say("REGRESSION_REFUSED_INVALID_RUN_ID")
        return 2
    try:
        if flags.stage: stage()
        elif flags.apply: apply()
        elif flags.call: call()
        elif flags.rollback: rollback()
        else:
            data = state()
            say("REGRESSION_PHASE_" + data["phase"].upper().replace("-", "_") + "_NO_ACTION")
        return 0
    except (OSError, ValueError, TypeError, RuntimeError, KeyError):
        say("REGRESSION_REFUSED_SOURCE_OWNER_OR_ONE_USE_NO_RETRY")
        return 2


if __name__ == "__main__":
    sys.exit(main())
