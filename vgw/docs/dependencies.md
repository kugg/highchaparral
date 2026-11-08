# M0 pinned library selection

- Diago `github.com/emiago/diago` **v0.32.2**, upstream tag commit
  `0cae371f33e4760487f17c6caeacbf576f12cfe6`.
- sipgo `github.com/emiago/sipgo` **v1.4.3**, upstream tag commit
  `769e4bc958376e2363566c8f7042202b410becdc` (Diago v0.32.2's
  declared dependency).

The pinned Diago implementation supplies `NewDiago`, `WithTransport`,
`WithMediaConfig`, `Serve`/`ServeBackground`, `DialogServerSession.Trying`,
`Answer`, `Echo` and dialog hangup. The test uses `Diago.Invite` and
`DialogClientSession.Hangup`; sipgo supplies `NewUA` and `sip.Uri`. The APIs
were inspected in the v0.32.2 tag, not inferred from the current README.
`go.mod` and `go.sum` are the reproducible dependency record.

M1 uses the same pinned versions: `diago.RegisterTransaction`, `Register`,
`Qualify`, `Unregister` and `sipgo.WithUserAgenTLSConfig`. These methods
were checked against the pinned module's `register_transaction.go` and
`diago.go` before adding local-only tests. The library's convenience
`Diago.Register` is not used: its built-in retry loop lacks the M1
per-attempt timeout, finite failure cap and backoff policy.

M2 uses Diago's pinned `ServeBackground`/`Serve`, `DialogServerSession.Trying`,
`Ringing`, `Answer`, `Context` and `Hangup` and sipgo's server request
middleware plus `OnUpdate` only to deny unsupported methods before Diago's
handlers. SIP transaction matching, CANCEL and BYE remain library-owned.
