# VGW host testing and scope

This is the sanitized VGW source selected by the user for a penetration-test-driven Defense Factory demo. Consult `DEFENSEFACTORY-SOURCE.json` for the pinned source revision and file hashes. Subsequent repair PRs must identify their exact candidate revisions.

## Host commands

Requirements: a suitable Go toolchain (module minimum Go 1.23), a C toolchain, pkg-config and the Opus development library. This host has Go and Opus installed.

From `vgw/`:

```sh
go test -race -count=1 -timeout=120s ./...
go build -trimpath -o /tmp/defensefactory-vgw ./cmd/vgw
/tmp/defensefactory-vgw
```

The final command uses VGW's default dry-run behavior. It establishes only executable startup in that mode. It does not establish SIP registration, provider connectivity, media/call behavior, a deployed gateway or remediated production scope. Real provider credentials, registration and attended call commands are outside this baseline import.

## Known baseline gap

The snapshot does not include the parent deployment tree. `internal/serviceconfig.TestTwinAnsibleTemplateRendersTheProductionParserContract` expects `deploy/ansible/templates/voip-gateway.config.j2` at a parent-relative path and fails when that template is absent. The full Go suite therefore does not pass in this standalone import. Do not skip or silently rewrite that check to manufacture green evidence. Treat template/configuration correspondence as unresolved until the relevant source and approved binding are supplied.

Some source README links also point to omitted parent documentation. Missing files are not covered by this import. The tests exercise local/synthetic peers; they are not proof of real provider or physical-device interoperability.

## Finding and evidence flow

Record reported target, revision/artifact, configuration, environment, test window, reproduction, expected legitimate behavior and impact in a real Linear finding. Establish correspondence between the running test target and this snapshot before reusing results.

Repairs must preserve useful behavior and challenge relevant bypass routes and architectural constraints. Verification records exact subjects and scope, preserves counterexamples and distinguishes satisfied-within-scope, violated, inconclusive, stale and unsupported obligations. A model result does not substitute for implementation evidence.

The factory retains raw logs and sensitive pentest captures locally. Publish only reviewed source and summaries; this repository is public. Existing Flask/SAST files remain separate experimental fixtures and are not automatically included in VGW closure.
