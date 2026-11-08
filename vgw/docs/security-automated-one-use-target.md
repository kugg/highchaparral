# Automated special-extension one-use review (2026-10-25)

Scope: separate Mac one-shot diagnostic and private approval
stage only. The operator asked for a non-person automated
Eventphone target. The readback target was documented as offline
and previously returned 404; old Maze result had ambiguous BYE.
No APU, browser, QEMU or host network configuration is changed.

- Credential source is one ignored, no-symlink, owner0600,
  single-linked local DEMO file under the user-approved ATA
  workspace. Its three fields are parsed as bounded data,
  host-fixed to the reviewed registrar. No credential leaves a
  process-local byte slice for source, argv, env, stdout, Git,
  HTML/template/SQL, or external review. The public GURU3 web
  site is NOT a SIP authentication endpoint.
- An approved numeric test destination is supplied separately
  via operator/controller environment, written privately to a
  fresh owner0700 stage with owner0600 file and fsync BEFORE
  SIP use. The attempted value must equal that immutable record.
  Only a fresh `announcement` stage can run; the old `first`/
  `maze` identities cannot be live-replayed via this command.
  Fixed error/status categories never echo target, SIP response
  headers, SDP, audio or attacker-controlled server text.
- SIP/TLS checks system CA roots and exact registrar DNS SAN
  with TLS>=1.2. No browser certificate bypass is involved.
  The one-shot media parser accepts only narrow PCMA/8000 and
  the exact response SDP UDP source. It never stores prompts or
  transcriptions. SIP/BYE uncertainties are terminal with no
  automatic replay, even if Asterisk/browser testing later needs
  a distinct approved stage.

Outstanding: successful standalone provider RTP would not
verify integrated WebRTC→Go→provider media, provider-side BYE
completion, remote unregister, intelligibility or a live call
release. The existing APU `cmd/vgw` is REGISTER-only and stopped;
the unattended browser Echo stage was separately consumed.

**Actual reviewed one-use evidence:** Separate authenticated
automated-service diagnostic finished with fixed `pass` category,
answered=true, media_returned=true, bye=true and
unregistered=true. These are the library's transaction results,
not an independent provider portal inspection. Protected
approval/attempt/result metadata passed independent owner/mode/
nlink checks. No second attempt or raw SIP/media inspection was
performed. The APU/WebRTC incumbent remained idle/verified.
