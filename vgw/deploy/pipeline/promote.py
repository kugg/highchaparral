#!/usr/bin/env python3
"""Fail-closed artifact/QEMU evidence gate before any Noll production apply.

The current synthetic Asterisk/Go browser regression is narrower than full
Eventphone SIP/TLS and browser bidirectional media. Until those independent
same-artifact QEMU gates and Noll NIC/identity/rollback contracts exist,
--apply is deliberately refused without touching Noll. Default dry-run.
"""

import argparse
import json
import os
from pathlib import Path
import sys

import release


GATES = ("synthetic_browser_ari", "full_byok_provider", "two_way_browser_media")


def evidence(manifest: dict, manifest_sha: str, report: dict) -> None:
    if (report.get("schema") != 1 or report.get("commit") != manifest["commit"] or
            report.get("artifact_sha") != manifest_sha or
            not isinstance(report.get("images"), dict) or
            set(report["images"]) != {"asterisk", "browser", "vgw"} or
            any(not isinstance(value, str) or not release.IMAGE.fullmatch(value)
                for value in report["images"].values()) or
            any(report.get(name) != "passed" for name in GATES) or
            report.get("production") != "not-tested"):
        raise ValueError("same-artifact/full-provider/media staging proof absent")


def check(root: Path, artifact_id: str, report_path: Path) -> None:
    manifest_path = root / artifact_id / "manifest.json"
    manifest = release.verify(root / artifact_id)
    if report_path.is_symlink() or report_path.stat().st_uid != os.getuid() or report_path.stat().st_mode & 0o077:
        raise ValueError("private staging evidence owner changed")
    release.digest(report_path, 16384)
    report = json.loads(report_path.read_text(encoding="ascii"))
    evidence(manifest, release.digest(manifest_path, 16384), report)


def main() -> int:
    os.umask(0o077)
    cli = argparse.ArgumentParser(description=__doc__)
    group = cli.add_mutually_exclusive_group()
    group.add_argument("--check", action="store_true")
    group.add_argument("--apply", action="store_true")
    cli.add_argument("--state", default="")
    cli.add_argument("--artifact", default="")
    cli.add_argument("--attestation", default="")
    args = cli.parse_args()
    if not args.check and not args.apply:
        print("DRY_RUN_NOLL_PROMOTION_NO_DEVICE_OR_PROVIDER")
        return 0
    try:
        root = release.private_root(args.state)
        if not release.IDENTIFIER.fullmatch(args.artifact):
            raise ValueError("candidate ID invalid")
        report = Path(args.attestation)
        if (not report.is_absolute() or root not in report.parents or
                not report.exists() or root.resolve() not in report.resolve().parents):
            raise ValueError("staging evidence must be private and absolute")
        check(root, args.artifact, report)
        if args.apply:
            # No release-capable VGW provider/ARI/media service, Noll NIC
            # contract or verified production rollback is present in source.
            # Do not start the existing REGISTER-only --serve on the user's
            # production host and call it a voice deployment.
            print("NOLL_APPLY_BLOCKED_PRODUCTION_RUNTIME_NOT_VERIFIED")
            return 2
        print("NOLL_PROMOTION_EVIDENCE_SAME_ARTIFACT_FULL_GATES_PASS_NO_DEPLOYMENT")
        return 0
    except (OSError, ValueError, TypeError, KeyError):
        print("NOLL_PROMOTION_BLOCKED_SOURCE_STAGING_OR_MEDIA")
        return 2


if __name__ == "__main__":
    sys.exit(main())
