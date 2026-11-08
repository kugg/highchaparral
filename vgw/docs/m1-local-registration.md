# M1 local registrar boundary

The registration adapter is intentionally separate from the M0 echo service.
It opens one **outbound** SIP-over-TLS connection to `127.0.0.1:<configured
port>` for the duration of a local test. There is no server listener, no
provider DNS lookup, no real credential file and no Asterisk operation. The
mock registrar's certificate and its trusted root are generated in memory;
tests never enable `InsecureSkipVerify` or fallback to UDP/TCP.

Diago v0.32.2 supplies REGISTER, digest challenge, refresh (`Qualify`) and
unregister transactions. sipgo v1.4.3 supplies the TLS transport; the user
agent receives explicit `MinVersion: TLS1.2`, `RootCAs` and `ServerName`.
Default sipgo logging is disabled at registration-package initialization
because some internal parse/error paths bypass per-UA loggers. This is a
process-wide setting: a future integrated gateway must own its complete
logging policy at startup, before importing or initializing other SIP paths.
The optional sipgo packet-debug path writes raw SIP directly to stderr;
the package also installs a process-global discard tracer before creating
any UA. The test binary enables SIPDebug *before* launching any goroutine
and verifies registrations without packet output. Another integrating
package could explicitly replace these global sinks; prevent that before
using real credentials. Do not toggle sipgo's unsynchronized SIPDebug flag
while connections are active.

The adapter bounds each operation to 10 seconds at most, restricts refresh
to less than the requested expiry, caps exponential backoff at the configured
maximum, stops after six consecutive failures, and attempts unregister once
with a separate bounded shutdown context after any successful registration.
At most one Run call can be active in this single-identity adapter. A
configured username is restricted to 1–64 ASCII letters, digits, dot,
underscore or hyphen before constructing the SIP URI, rejecting CR/LF and
URI delimiters; this restriction may need a separately reviewed policy for
any real account name.
Unregister failure is not proof of deregistration: the server may retain the
binding until its expiry. The server-returned Expires value is not currently
available from Diago's public transaction API, so a shorter registrar expiry
than requested could cause a refresh after expiration. A real endpoint
requires a separately checked refresh policy and observed expiry behavior.

The mock proves only local TLS/digest behavior. It does not establish that
Eventphone accepts this Contact, expires, digest algorithm, transport reuse,
incoming INVITE routing, media/NAT, or password. Treat incoming INVITEs on a
different connection as an open testbench question. Do not read adjacent
`eventphone_creds` or register externally based on this local test.
