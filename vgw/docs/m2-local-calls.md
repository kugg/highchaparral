# M2: local-only one-call SIP signaling

Run a standalone, development-only SIP user agent:

```sh
go run ./cmd/local-inbound -port 5080 -ack-timeout 5s
go test -v ./internal/calls -count=1
```

Only IPv4 `127.0.0.1:<port>/udp` is bound. No registration, external dial,
Asterisk, ARI or provider credentials are used. A single configured dialed
user (`desk` in the demo) maps to the typed internal `Desk` target. The
service emits only `Incoming`, `Ringing`, `Answered`, `Ended` with a new
128-bit locally generated ID; it never exports SIP Call-ID, From/To, raw
SDP, RTP, or a caller-supplied destination. The test client uses a separate
Diago user agent and real loopback UDP transactions.

Diago/sipgo own INVITE, 100/180, final response, ACK, CANCEL, BYE and
dialog correlation. The application checks the request URI, narrow local
PCMA offer and single active call, rejects in-dialog re-INVITE, REFER,
INFO, NOTIFY, OPTIONS and UPDATE, bounds a pending answer decision and
ends confirmed calls after a configured maximum duration. The offer guard
is shared with M0; it requires one loopback IPv4 media address. There is
no media copy or internal SIP leg at M2.

The service owns a four-event channel exposed receive-only to consumers.
Delivery is nonblocking; an undrained/full channel rejects new calls (503)
rather than holding call cleanup. Consumers cannot close the channel.
A future ARI adapter must consume these events and reconcile ambiguous
delivery before using them for irreversible side effects. `ACKTimeout` is
required in the `calls.Config` (25ms–10s and no longer than `MaxCall`);
the local executable defaults to `-ack-timeout 5s`. `MaxCall` is an
absolute deadline from admission, including the pending decision and ACK
wait, not a fresh timer started after ACK. The missing-ACK watchdog sends
a fail-closed error and disables new admission. The executable **exits**
with a nonzero status when it receives that error: the OS then reclaims
the listener, RTP sockets and blocked library goroutine. No automatic
restart, redial or replay occurs. A child-process test deliberately omits
ACK and verifies that the worker exits and its UDP port can be rebound.

This is process-level containment, **not** SIP transaction cancellation.
Pinned sipgo v1.4.3 `DialogServerSession.WriteResponse` has no caller
context and re-creates its 64*T1 timeout inside the 2xx retransmission
loop; v1.6.0 and Diago v0.41.0 still expose no cancelable `Answer` that
was verified here. If an embedding application consumes `Service.Failure`
but does not exit the process, its in-flight Answer goroutine may remain;
it must not restart this Service. An upstream absolute ACK deadline or
reviewed compatible library cancellation fix remains necessary for
graceful in-process recovery and any external listener. SIP TLS
certificate validation and registration are separate M1 outbound concerns;
inbound connection reuse was not assumed or tested.
