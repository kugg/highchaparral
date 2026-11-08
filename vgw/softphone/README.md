# VGW browser softphone

This is the browser/WebRTC companion to the gateway, adapted from the
source-owner twin's `webrtc/site/` softphone. It is source-only: no private
accounts, site certificate, SIP.js bundle, audio, or production configuration
is in this repository. The original 90-file gateway snapshot in
`../DEFENSEFACTORY-SOURCE.json` predates this independent UI addition.

## Build and try an internal PBX call

Node 20+ and npm are needed to build the pinned SIP.js 0.21.2 browser bundle
using esbuild 0.25.12. From `vgw/softphone/`:

```sh
npm ci
npm run build
npm test
python3 -m http.server 8000 --bind 127.0.0.1 --directory site
```

Open `http://localhost:8000/` **on the same machine** for a local test.
`localhost` is a browser secure context; for other devices host `site/` on
your own trusted HTTPS origin. The generated `site/vendor/sip.min.js` is
ignored; include it when serving the built page, but do not commit it.

Before connecting, provision an **owned** Asterisk/PBX WebRTC SIP account:
an authenticated SIP-over-WSS endpoint, appropriate dialplan and DTLS-SRTP
media. Set the public `site/config.js` `sipDomain` and `wssUrl` to your
PBX's validated names/port, and ensure the browser trusts its WSS TLS
certificate. The defaults target the host serving the page on WSS port
8089; they neither create nor configure a PBX. Enter the PBX extension
and its password in the page and choose **Connect to PBX**. Neither
password is embedded in files or browser storage. Some local PBX fixtures
have an unauthenticated *isolated* guest endpoint, for which the password
input can remain blank; never expose such a fixture to shared networks.

The default route calls another numeric PBX extension (2–6 digits).
Incoming calls can be accepted/rejected; hangup and mute are local
controls. No physical phone is needed for a second WebRTC PBX endpoint.
This is an interactive client, not a call replay/test-automation tool.

## Eventphone prerequisite

The Eventphone option is **disabled** in `site/config.js`. The UI has
the source-owner BYOK flow for a caller's *own* provider identity: on an
explicitly enabled installation it POSTs the password to the same-origin
HTTPS `/cgi-bin/vgw` reservation endpoint, then sends only a short-lived
nonce and numeric `e-` extension through the PBX SIP leg. This requires
an authenticated same-origin reservation handler, a verified PBX route
that extracts the nonce, and a call-capable VGW provider/ARI/media service
with bounded teardown. The current public `cmd/vgw --serve` is
**REGISTER-only**; this repository does not yet provide a turn-key
Eventphone calling deployment. Do not enable `eventphoneEnabled` merely
because the page builds or an internal call works. Eventphone BYOK
requests require HTTPS; plain HTTP localhost cannot be used for them.

The page does not ask the browser to trust arbitrary certificates, store
credentials, or automatically redial. `index.html` loads local assets
only; no CDN or third-party runtime fetch is used. The npm build recipe
uses locked, integrity-checked dependencies; SIP.js and esbuild are MIT
licensed and their generated binaries are kept out of Git.
