# Authenticated local ARI

All five service/probe callers use one HTTPS/WSS transport. Only canonical
`https://127.0.0.1:<port>` is accepted; the default is 8089. The peer must
pass normal TLS verification with the numeric loopback SAN and match the
explicitly provisioned public leaf. There is no HTTP, WS or lab exception,
redirect, proxy, remote destination or trust-on-first-use fallback.

Before starting a service, an operator must configure Asterisk's TLS listener
and securely deliver its public leaf as `ari-peer.pem` beside the selected
private `--config`. Never obtain this trust input from an unverified ARI
listener. The Asterisk private key stays with Asterisk. Existing config files
with an explicit HTTP ARI URL must migrate to HTTPS; absent ARI_BASE_URL uses
the new default. Pin/config/listener must agree before launch.

The public cert follows the existing matched configuration ownership profiles:
root:selected-group directory 0750/file 0640, or selected-user/group directory
0700/file 0600, under trusted canonical ancestors. Mixed profiles, symlinks,
hardlinks, writable ancestors and ambiguous PEM are refused. Rootless UID/GID,
selected ports, state/socket ownership and provider trust remain separate.

`local-ari-lab`, `ari-probe` and `ari-media-probe` require an explicit
`-ari-peer-cert /canonical/private/path/peer.pem` and accept `-ari-port`.
The same protected reader and authenticated transport apply. A public cert
is not a credential, but its integrity determines which peer may receive one.

Rotation is authenticated reprovision and restart: stop the owned service,
stage the new peer/config together through the administrative channel, verify
ownership and identity, restart, then confirm legitimate operation and refusal
of the old identity. An unexpected replacement is refused on new connections.
Rollback must restore matching owned trust/config and must never enable HTTP.

Component construction checks include `go test -race ./...` and the named
transport, provisioning and caller-inventory fences in `claims.json`.
TLS mocks demonstrate transport behavior and owned fixture lifecycle only.
They do not establish a real Asterisk deployment, complete browser/provider
journey, protected independent verification or production remediation.
Use the softphone twin E2E release plan for those downstream gates.
