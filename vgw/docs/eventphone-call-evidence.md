# Eventphone call-test evidence: final standalone verdict, open integration

## Final verdict

The separately authorized **one-use automated Network Announcement
call** is **PASS at the standalone library-transaction level**. Its
protected source-owner result records authenticated REGISTER, an
answered automated-service INVITE, one PCMA RTP frame returned from
the negotiated SDP source, successful library BYE and Unregister.
The approval and attempt preceded provider network use; the spent
stage is retained. A read-only verifier rechecked owner-0700/0600
stage/file metadata, the pre-network one-use attempt and all fixed
result booleans, without reading the numeric destination, credential,
SIP, SDP, audio or prompt. It returned the fixed category
`AUTOMATED_ANNOUNCEMENT_ONE_USE_REGISTER_ANSWER_PCMA_BYE_UNREGISTER_PASS`.
This finalization placed **no new call** and did not replay an old stage.

| Scope | Evidence | Verdict |
|---|---|---|
| Older readback and Maze stages | One INVITE returned 404; a separate Maze call returned PCMA but BYE was unconfirmed. | Consumed; Maze teardown remains ambiguous. |
| Approved automated Network Announcement, 2026-10-25 | One standalone REGISTER → answered INVITE → SDP-source PCMA → library BYE → Unregister, all fixed result booleans true. | **PASS for that one standalone call only.** |
| VGW development-account connectivity, 2026-11-10 | Fresh separate `vgw` SIP/TLS REGISTER and Unregister; verified TLS 1.3. No INVITE. | PASS for registrar connectivity only. |
| Browser/Asterisk/Go local mock, source-owner V26 | Real browser answer and browser-initiated BYE; synthetic local 200 and owned ARI cleanup. | PASS for local synthetic path only. |
| Same-candidate public VGW browser→Eventphone provider call | No full BYOK/provider SIP/TLS and browser two-direction RTP run in QEMU or on Noll. | **BLOCKED / not run.** |

The successful announcement result does **not** retroactively repair
the older Maze BYE, prove a server-side BYE portal receipt, verify
intelligible speech, connect a browser to Eventphone, or prove Noll/
SPA112 hardware. The operator's development account is distinct from
Noll's planned persistent provider identity. `cmd/vgw --serve` remains
REGISTER-only; the full BYOK/media/CD gates in
[`softphone-twin-e2e-release-plan.md`](softphone-twin-e2e-release-plan.md)
are separate. No production deployment or new numeric call target is
implied by this report.

## Reproducible read-only finalization

In the source-owner twin only, from the Go module's
`cmd/provider-one-shot/` directory:

```sh
python3 -B -m unittest -v test_finalize_evidence.py
python3 -B finalize_evidence.py             # DRY RUN
python3 -B finalize_evidence.py --verify    # fixed outcome, no network
```

The verifier inspects **only** the already-consumed owner-private
announcement stage. Its source and the previous stages are not copied
to this checkout; the public result above is the reviewed conclusion.
Do not invoke `provider-one-shot --run` on a spent target or treat
`eventphone_creds` as a production secret. The next full call test needs
an independently provisioned call-capable VGW/ARI/media candidate,
fresh QEMU staging evidence and separate release authorization.
