# JER-13: authenticated ARI peer candidate

This candidate changes the BYOK service and the default ARI constructor. It does not establish that any deployed Asterisk supports this binding, and it does not close JER-13.

## Boundary

`asterisk.New` requires `https://127.0.0.1:<port>` and an explicitly provisioned public leaf certificate. The connection uses TLS 1.2 or newer, normal certificate lifetime/server-usage/IP-SAN verification against that certificate as a trust anchor, and an additional SHA-256 exact-leaf pin. There is no system-root fallback or caller-controlled verification callback.

Both HTTPS requests and the WSS event subscription use the same peer policy and fixed loopback dialer. TLS completes and authenticates the peer before any HTTP Authorization header can be delivered. WebSocket upgrade limits count decoded upgrade bytes rather than TLS records. Redirects, remote addresses and caller-controlled target routes remain prohibited.

The BYOK service reads `/etc/voip-gateway/ari-peer.pem` before opening its ARI connection, and proposes `https://127.0.0.1:8089` as its fixed TLS endpoint. The file must contain exactly one public certificate with an IP SAN for `127.0.0.1`, be root:vgw 0640 and single-linked, in the existing root:vgw 0750 directory. Symlinks, extra PEM blocks and private-key input are rejected. This is separate from the existing eight-line BYOK config; provider trust is unchanged.

The server's private key must remain restricted to the intended ARI peer or authenticated local termination service. Merely placing TLS on a proxy which forwards credentials to an unauthenticated, substitutable backend would leave an architectural obligation open.

## Migration and review decisions

The target's actual authenticated ARI endpoint, TLS configuration, private-key ownership and backend correspondence need separate deployment evidence. Port 8089 here is a proposed candidate binding, not evidence about the existing WSS/browser or ARI setup. Do not reuse an unrelated browser TLS key or infer ARI availability from a port number.

Provision the approved server leaf explicitly, including normal validity and loopback identity. An absent/invalid pin causes refusal; there is no automatic plaintext fallback. Rotate by explicitly reprovisioning the file and restarting the gateway; an unknown replacement peer is refused on both reconnect paths. No CA enrollment, certificate distribution, Asterisk changes, production rollout or provider calls are performed by this patch.

Historical `local-ari-lab` and the three `ari-*-probe` commands retain their existing plaintext behavior through the clearly named `NewLoopbackLab` constructor. That exception authenticates no local peer and is only for isolated synthetic/attended lab use. It is not a remediation of those commands. A production-source AST fence rejects selecting that exception in `cmd/vgw`; future production entry points need equivalent coverage. Review and approve this explicit scope/exception before architectural acceptance. Do not use real service credentials with a lab exception on an untrusted host.

## Checks

Tests challenge plaintext/missing identity, untrusted and expired peers, wrong IP identity, a different leaf signed by a trusted pinned certificate, both credential transports, and replacement/reprovisioning. Positive tests retain valid-peer owned resource lifecycle, browser WSS events and cancellation, alongside the existing lab behavior suite. Provisioning tests challenge file ownership, permissions, links and ambiguous certificate input.

The complete module test suite still has its baseline missing-Ansible-template failure. Same-host verification is a rehearsal; independent policy approval, merge-subject evaluation, deployment correspondence and confirmation remain separate gates.
