# One separate automated Eventphone service attempt (not WebRTC bridge)

The operator permitted a bounded call to a public automated test
service but no person. Eventphone's public Special Extensions page
labels the historical readback service offline and the Maze and
Network Announcement services online (page last changed in 2024).
Its EPVPN page (updated 2026) names the Network Announcement in
the `hg.eventphone.de` dialplan. Earlier one-use readback returned
404; an independently authorized Maze call answered/returned
PCMA but BYE was ambiguous. Do not replay either preserved stage.

`cmd/provider-one-shot` is a **separate Mac standalone diagnostic**,
not the APU `vgw` service and not WebRTC → Eventphone. The code
does not contain a real extension number or credential. It reads
ONLY the existing owner0600, single-linked ignored sibling ATA
DEMO file; real credentials were withheld. With no flags it is
a dry run. `--check-credentials --test-id announcement` validates
its fixed shape without network or a private attempt stage.
`--approve-automated --test-id announcement` requires an operator-
reviewed numeric environment target and writes it into a NEW
Git-ignored owner0700 one-use stage/owner0600 approval file,
fsynced before any network. `--run --test-id announcement` will
only dial that exact previously approved target; a different
number, old stage ID, missing private file or a second attempt
is refused. Keep the approved extension OUT of Git/source/argv/
logs. The prior `first` and `maze` stages are never reused.

The one attempt uses pinned sipgo/diago, IPv4 source selection,
system-CA/hostname-verified SIP/TLS to the reviewed registrar,
Digest REGISTER, one bounded INVITE and PCMA-silence/return-source
check. One BYE and Unregister are attempted with short timeouts.
After a response, the private result has fixed status/boolean
categories but no SIP headers, SDP, credentials or audio. Any
ambiguous BYE, missing ACK, provider rejection or failure leaves
the stage consumed. NEVER retry or redial automatically. A
provider-level pass here still would not prove APU Go integration,
WebRTC↔provider media or intelligible speech.

References: https://eventphone.de/doku/special_extensions and
https://eventphone.de/doku/epvpn (public documentation; service
status may have changed since publication).

**One bounded real result (2026-10-25):** The new private
`announcement` approval was fsynced and independently checked
for owner0700/0600, single-link ownership and no prior attempt.
The Mac-only one-shot reported `category=pass`: authenticated
REGISTER, answered automated announcement INVITE, provider
PCMA RTP returned from the SDP source, one successful library
BYE result and one successful Unregister result. The ignored
attempt/result are retained and cannot be reused. This does
NOT mean a browser call reached Eventphone or that any speech
was intelligible; no audio was stored. Separate read-only APU
checks still found zero calls, ARI auth/negative controls, the
same ATA peer and stopped REGISTER-only `vgw`. Prior Maze BYE
ambiguity is NOT retroactively resolved by this distinct call.

## Authenticated-media capability probes

The separately named `srtp-sdes-v1` and `srtp-dtls-v1` stages measure
provider support for two fixed authenticated-media profiles. They inherit an
already reviewed automated target into distinct owner-private one-use stages;
they never accept a target from ticket prose or source code. Each stage may be
prepared once and attempted once. An ambiguous result is evidence and must not
be retried under the same identity.

The SDES probe requires `RTP/SAVP`, `AES_CM_128_HMAC_SHA1_80` and an inline key
delivered inside the CA/hostname-verified SIP/TLS session. The DTLS-SRTP probe
requires `UDP/TLS/RTP/SAVP` or `SAVPF`, a SHA-256 fingerprint and a valid DTLS
setup role delivered inside that same verified signaling channel. Either probe
rejects plaintext RTP answers before media is admitted. A capability passes
only after the runtime reports the expected secure media mode and decrypted
PCMA media returns from the negotiated source.

The durable result contains only fixed categories: profile, answer transport,
keying family, suite category, signaling binding, downgrade rejection and the
bounded call lifecycle booleans. It never stores SDP, SDES keys, DTLS
fingerprints, credentials, addresses, headers, target numbers or audio. These
probes establish provider capability; they do not implement the production VGW
repair or authorize fallback to plaintext media.
