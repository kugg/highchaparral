# High Chaparral — AppSec Defense Factory test repository

This repository hosts the VGW penetration-test and remediation demo.

## VGW under test

`vgw/` is imported from the user-designated sanitized source snapshot. [Source provenance and per-file hashes](vgw/DEFENSEFACTORY-SOURCE.json) identify its exact original revision. It is a separate Go module.

The [VGW browser softphone](vgw/softphone/README.md) is a separately
packaged source-only companion for WebRTC PBX testing without a hardware
phone. PBX-extension calls require a WebRTC PBX; Eventphone calls through
the included VGW `--serve-byok` path specifically require Asterisk ARI.
The separate `--serve` mode only registers upstream. The Eventphone
option is disabled in the packaged page pending an owned HTTPS/PBX
integration; this is not an Asterisk-free
client and is not part of the pinned original gateway source snapshot.

The user performs the penetration test. Findings are triaged in [the Defense Factory Linear project](https://linear.app/jerkeby/project/appsec-defense-factory-vgw-demo-20a3edd5d494), then processed through manually invoked Codex skills on the host: intake → assessment → repair → verification → integration → deployment → confirmation → maintenance.

No scheduler or unattended remediation worker is installed for this demo. GitHub Actions runs the full standalone VGW Go race suite and both offline softphone browser cases on every PR. These checks do not deploy, contact a provider or replace the user's manual penetration test. The redacted literal inventory remains available as an optional manual tool, with its package tests included in the Go suite. A baseline import is setup, not a remediation. Same-host verification is explicitly a rehearsal until independent identities and controlled acceptance permissions are evidenced. Merge alone does not establish deployed remediation.

See [VGW testing notes](vgw/DEFENSEFACTORY-TESTING.md) for host commands, known snapshot limitations and safe scope. The full local factory workspace is `~/devel/defensefactory`; reusable skills are installed from its `skills/` directory.
