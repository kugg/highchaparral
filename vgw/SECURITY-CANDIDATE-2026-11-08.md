# VGW security-testing candidate — source review, not remediation

This public snapshot is a **test target**. No reported security behavior
was repaired as part of this import. Manual penetration testing and
independent production acceptance remain separate work. The exact 79
copied source files are pinned in `DEFENSEFACTORY-SOURCE.json` version 2
(tree SHA-256 `09199a7e257f15402643bf354e010e193d20a783a23ff05d575f4414ac9aa211`,
computed over lexicographically sorted relative-path/NUL/file-hash/newline records).
The original source worktree was uncommitted at base `ddecc13b`; file
hashes, **not** that base commit alone, identify the candidate.

## Scope and verification

- Only reviewed Go, Markdown, module and Dockerfile files were copied.
  The standalone copy has 79 regular files, no symlinks, private-key
  markers, `secrets/`, runtime state, provider credential file, image,
  firmware, prompts or audio. An in-memory comparison against the
  owner-only development account
  confirmed that neither its password nor its account identifier
  appears in any of the 79 copied files. No account bytes were printed.
- In `vgw/`, a sequential `go test -race -count=1 -timeout=120s ./...`
  **fails** only at
  `internal/serviceconfig/config_test.go:129-135`: the parent Ansible
  template omitted from this standalone import is unavailable. This
  is the pre-existing baseline gap, **not** a green full-suite result.
  A first pair of concurrently run suites also hit a transient
  `internal/asterisk/ari_test.go:1151` loopback-bind timeout; the ARI
  test passed when the suites were rerun sequentially. Neither
  failure was patched away.
- Sequential `go test -race -count=1 -timeout=120s -skip
  '^TestTwinAnsibleTemplateRendersTheProductionParserContract$' ./...`,
  `go vet ./...`, a cgo-disabled linux/amd64 vgw build, and the default
  `go run ./cmd/vgw` **passed**. The last command is a dry run: no
  credentials, registration or provider packet. No Docker image was
  built from this candidate and no Noll/APU device was touched.
- Five race-test runs of the candidate office, registration and vgw
  packages passed. The copied workspace has no private credential file;
  the offline `go run ./cmd/vgw --test-register-check` correctly refused
  with a fixed error category. No live test account was copied or used.
  Initial manifest verification found a generator ordering mismatch
  between path-component order and lexicographic manifest-key order;
  the *metadata hash* was corrected before publication. All 79 copied
  file hashes and the corrected sorted-path tree digest then verified.

## Cases for the manual security pass — preserve the candidate

1. **Development-account path and replay boundary:**
   `cmd/vgw/test_registration.go:25-28,135-149` uses working-directory-
   relative credential and one-use stage paths. Assess alternate
   working directories, symlinks and ownership/concurrent replacement
   without any real credential or provider call. The copied snapshot
   has no test account file; its default command remains no-network.
   A source-owner live REGISTER/Unregister test is historical evidence,
   not permission to repeat it from this repository.
2. **SIP/SDP before admission:** `internal/office/admission.go:83-105`
   bounds the body and checks a TLS *claim* and exact destination after
   sipgo has already parsed the request. Confirm actual verified-flow
   binding, header limits, Contact/To handling and malformed-message
   logging before any office listener or dialog handler is enabled.
   The same-flow 486/ACK and 200/PCMA/BYE tests are synthetic only.
   Attempt log/audit/template/SQL injection through all inbound paths;
   `internal/safesip/log.go:13-26` suppresses SIP debug traces but does
   not itself establish parser-level resource bounds.
3. **Media authentication:** `internal/office/admission.go:103-192`
   allowlists SDP media addresses; that does not prove that real RTP
   packets are source authenticated. No Eventphone SDES/DTLS-SRTP
   key-negotiation profile is established by SIP/TLS or plain
   RTP/AVP/PCMA. See `docs/jer-13-15-trust-decisions.md:3-20`.
4. **Browser reservations and ARI:** `docs/jer-13-15-trust-decisions.md:22-68`
   records that origin/nonce/per-caller SIP credentials do not prove a
   separate browser login. `internal/asterisk/ari.go:146-185` pins a
   Basic-auth ARI client to HTTP IPv4 loopback; APU HTTPS REST auth was
   observed separately, while Noll ARI TLS/WSS is unverified. Test
   spoofed browser/proxy identity, stale or duplicated reservations
   and wrong ARI credentials without exposing the shared office WAN.
5. **Release scope:** `Dockerfile.noll:1-24` labels this a development
   REGISTER-only image. Missing parent deployment config, persistent
   office INVITE/media/ARI journal, authenticated provider media and
   physical SPA112 behavior remain explicit gates. A source or mock
   result cannot be a deployed remediation or successful handset call.

Record actual reproduction, expected behavior, impacted candidate
commit/hash and counterexample in the Defense Factory finding flow.
Keep raw logs, credentials and captures private; publish only sanitized
observations. This document intentionally makes no security-pass claim.
