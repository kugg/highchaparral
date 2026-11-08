# TLS trust for a future Eventphone testbench

SRTP does **not** pin a SIP registrar's TLS certificate. Client registration
is protected by authenticating the TLS *server*; a SIP digest credential
authenticates the *client* to the SIP service. Client certificates (mTLS)
are a different, optional capability. Not having mTLS does not make it safe
to disable server-certificate verification.

Check with Eventphone whether its registrar uses a publicly trusted CA or
provides an operator-verifiable private CA and expected DNS name. Prefer
normal CA-chain and hostname verification. If a CA is unavailable, a
separately authorized **out-of-band** certificate or SPKI SHA-256 pin can
be reviewed for a future testbench, including rotation, expiry and recovery
rules. Learning a pin from the first unauthenticated connection (TOFU) can
permanently trust an active attacker at first contact; do not silently
capture and store one. A TOCTOU hazard also arises if the certificate is
checked once but subsequent reconnects do not repeat the same validation.
None of these external pinning modes is implemented here; M1 uses an
explicit local mock root and server name with Go's TLS verifier.

DTLS-SRTP can authenticate a media peer using an SDP fingerprint, but only
when the SDP signaling that carries the fingerprint is itself trusted. It
does not authenticate the SIP/TLS registrar or protect REGISTER credentials.
SDES-SRTP puts media keys in SDP and likewise depends on protected signaling.
Eventphone SRTP support, certificate chain, and inbound connection behavior
are all unverified until a user-operated testbench observes them.
