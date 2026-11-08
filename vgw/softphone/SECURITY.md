# Browser softphone source review (2026-11-08)

Scope: new `vgw/softphone/` sources and root README/workflow; the existing
gateway snapshot and Flask fixture are not altered. The page was adapted
from the twin-owned `webrtc/site/` policy, not copied from a private device.
No user account, private config, certificate, generated bundle, audio or
prompt is included. SIP.js 0.21.2, esbuild 0.25.12 and Playwright 1.63.0
are lockfile-pinned; `site/vendor/sip.min.js` and `node_modules/` are ignored.

## Input-to-sink review

- Browser-entered PBX and provider identities are bounded; both dial routes
  accept only numeric extensions (`site/dial.js`). SIP targets cannot include
  caller-supplied URI fragments, CRLF, or headers. The PBX account password
  enters SIP.js authorization only, never config.js, page markup, a URL or
  browser storage (`site/app.js`). SIP.js itself needs separate runtime
  review when deployed; these tests do not audit its parser or logs.
- BYOK provider credentials travel only in a bounded same-origin HTTPS JSON
  POST (`site/byok.js`, `site/app.js`). The SIP header contains only a fresh
  random nonce. Both password inputs are cleared after explicit submission;
  JavaScript strings still reside in process memory until GC. The page
  neither uses `innerHTML` nor renders a server response/error body into
  a log, audit event or DOM status. A synthetic CRLF/password-injected
  server response is ignored by the browser test. The server-side CGI,
  reverse proxy, SIP parser, audit, template and SQL sinks are separate
  inbound-input review gates; this page cannot establish their safety.
- Eventphone remains disabled in the public config (`site/config.js`).
  Turning it on requires an authenticated HTTPS reservation backend,
  strictly matched PBX Stasis/nonce lookup and the included `--serve-byok`
  provider/ARI bridge deployed with its owned config, state and media.
  `--serve` only REGISTERs; neither mode accepts a direct browser
  SIP/WSS/WebRTC call without a PBX. No shared-LAN or WireGuard access
  is treated as browser identity.
  An unproven server-side trust boundary cannot be repaired by hiding a
  browser button.

## Verification and remaining evidence

`npm ci --no-audit --no-fund`, `npm run build`, and `npm test` pass locally:
three offline policy tests and two offline Chromium tests with intercepted
requests, synthetic SIP.js classes and the actual built bundle. The tests
check blocked unconfigured Eventphone access, numeric dialing, same-origin
POST and nonce-only SIP, clearing both inputs, and rejection of an injected
server response without placing another call. `go run ./cmd/literalcheck
--check` and its race test pass; `actionlint` v1.7.7 reports no errors on
the pinned GitHub workflow. None of this is a real PBX, provider SIP call,
DTLS media or browser certificate-trust verification. Provider SRTP mode,
Noll/APU deployment and a physical handset remain separate gates.
