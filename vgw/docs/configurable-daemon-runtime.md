# VGW runtime values versus security invariants

`st.Uid` and `st.Gid` are **user/group IDs**, not a process PID. The kernel
assigns the process PID; the optional *PID-file name* is an operational
choice. A supervisor normally tracks the process itself, so the default
PID-file setting is empty. An explicitly requested file is created once
under the already-owned runtime directory, fsynced, never overwritten,
and removed only if its inode is still the one the process created.

## Authority and selection

Deployment-specific paths and identity come from one bounded
`RuntimeOptions` bootstrap owned by the launching user or service
manager, **before** any private provider config is read. The same flag
set is used by the service and its diagnostic/browser-ARI probe. UID/GID
default to the effective process identity; an explicit override must
match that effective identity and needs no `/etc/passwd`/shadow entry.
These startup flags are not accepted from SIP, browser headers, ARI
events or provider SDP. A private config must not nominate its own
owner or move its own trust boundary.

| Option | Current default | Validated constraint |
|---|---|---|
| `--run-uid`, `--run-gid` | Effective UID/GID of the running process | Optional canonical decimal selectors; if specified they must match effective IDs. Root as the BYOK service UID remains refused. No compiled-in 34567/34568 or passwd/shadow lookup is needed. |
| `--config` | `/etc/voip-gateway/config` for REGISTER, `/etc/voip-gateway/byok.config` for BYOK, `/etc/voip-gateway-office/office-account.config` for office-only check | Clean canonical absolute path with trusted ancestors. Accept **either** a process-owned 0700 directory and 0600 regular file for rootless testing **or** the existing root:selected-GID 0750 directory and 0640 file; no symlink/hardlink or concurrently replaced inode. Never interpolate SIP/browser input into this flag. |
| Office `--office-port` | 5061 | Numeric 1–65535. Fixed reviewed office registrar and `hg.eventphone.de` TLS identity are not arbitrary substitutions. Its separate config still has the four strict credential fields. |
| `--runtime-dir`, `--state-dir`, `--socket-name` | `/run/voip-gateway`, `/var/lib/voip-gateway/byok-v1`, `byok.sock` | Canonical absolute directories with trusted ancestors, owned by effective UID/GID and 0700; socket is a single safe basename with mode 0600. A rootless local test can use private user-owned directories. Never unlink a pre-existing or concurrently replaced socket. |
| `--pid-file` | empty (supervisor owns PID) | Optional safe basename below the owned runtime directory, distinct from the socket; exclusive 0600 create, fsynced directory, no stale-file deletion on startup. |
| `ARI_BASE_URL` in the private service/BYOK config | Existing loopback `http://127.0.0.1:8088` for an eight-key legacy file | The **parsed config struct**, not a literal at `asterisk.New`, supplies a numeric 1–65535 port. Scheme and host stay constrained to authenticated `http://127.0.0.1`; neither arbitrary URI nor LAN/WireGuard ARI exposure is permitted. |
| `UPSTREAM_HOST`, `UPSTREAM_PORT`, `UPSTREAM_USERNAME`, `ARI_USER` | Already strict provider/BYOK config fields | Reviewed SIP destination, 1–65535 port and bounded identities. No real credential in argv or static web assets. |
| `SIP_BIND_IPV4`, `SIP_BIND_PORT` in the private config | Auto-select current IPv4 egress address and ephemeral port 0 | Explicit IPv4 bind and canonical source port 0–65535 are checked before any provider network access. IPv6/routes are never changed. |
| `ERROR_LOG_PATH` in the private config | empty: fixed-category stderr | Optional absolute file under a process-owned private log directory (e.g. one pre-provisioned for `/var/log/vgw_error.log`); no arbitrary overwrite, symlink or raw SIP/secret logging. |

For local offline testing, create an owner-0700 private directory and an
owner-0600 synthetic config file under a *canonical* absolute path.
From the Go module, `go run ./cmd/vgw --check-config --config
/absolute/private/vgw.config` uses the actual process UID/GID and does
not contact a provider. The office-only check has `--no-network`.
The old eight-key service/BYOK profiles still parse; new profiles can
add the four validated optional ARI/bind/log keys above. A daemon PID
is never chosen by a flag, and a client-provided provider or ARI
identity cannot change the trusted launch identity.

The old paths and ports remain **defaults**, so an existing reviewed APU
stage does not silently change behavior. An existing root:vgw 0750/0640
config remains accepted under the process's actual GID. A different
container or host can run rootless with private owner0700/0600 config
and runtime directories without recompiling. Production execution
must pass matching Docker/supervisor user:group and owner-provisioned
config/state. No flag
changes host interfaces, routes, DNS, packet filters or VPN.

## Fail-closed sequence

1. Parse canonical flags and check all path/port/name syntax with no
   file or network access (including default dry-run). Reject extra
   positional args and any unrecognized option without echoing argv.
2. For service modes, check effective UID/GID and exact trusted
   ancestor, config, runtime and state paths. Read private config
   with a nofollow descriptor, same inode, bounded size and fixed key
   schema. The office profile remains separate from browser BYOK.
3. Refuse an existing PID file/socket and unresolved call journal; write
   the optional PID file once *before* service network or listener,
   retaining a stale file as evidence after a crash. Close/remove only
   owned inode(s), never foreign or changed files.
4. Construct ARI from the parsed config's validated loopback base URL. Preserve
   exact upstream TLS reference identity, one-call ownership, fixed
   categories and bounded cleanup. Configurability cannot turn a
   test-only vgw into an approved provider call release.

Synthetic fixtures may pin test SIP ports and certificate/identity
trust anchors deliberately; those are test vectors rather than service
deployment parameters. The historical provider one-shot has a spent
call stage and is not retargeted by this runtime bootstrap. Tests
must cover alternate UID/GID, file/runtime/office paths, loopback port,
bad paths/ports, stale PID/socket and concurrent inode replacement,
while preserving default dry-run and secret-redacted outcomes. The
historical security-test snapshot omitted its parent Ansible template;
the current module bundles the reviewed eight-field template at
`deploy/ansible/templates/voip-gateway.config.j2` and the full
unskipped Go race suite passes in a standalone checkout. This does
not establish a real Ansible deployment or media call.

## Hardcoded-literal inventory and CI contract

`go run ./cmd/literalcheck --list` inventories **every Go AST basic
literal** (strings, numbers and runes) plus Dockerfile `USER`, `EXPOSE`
and deployment-named `ENV`/`ARG` directives, by file, line, owning
function/directive, kind, length and SHA-256. Language keywords such
as `true`, `false` and `nil` are not deployment values. It prints
small numeric deployment values (UIDs and ports), never raw string
literals or test credentials. `--operational` narrows to heuristic
deployment candidates: paths, loopback URLs, source ports/UID fields
and nontrivial numeric limits. `--draft-policy` emits a skeleton which
**cannot** pass as-is: each entry needs a manual classification and
reason. `docs/runtime-literals-policy.json` records reviewed per-file
counts and a sorted hash of the literal kind, owning function/directive and value
digest. `go run ./cmd/literalcheck --check` and the package's test fail
on new, moved-between-functions, duplicated, removed or unreviewed
deployment literals.
CI runs both checks in the public code-test project. Test files and
the linter's own source appear in the complete list but are not
deployment defaults; fixed protocol bounds/ownership modes and
historical one-use lab fixtures have explicit policy reasons.

The heuristic is not a substitute for code review: an arbitrary
ordinary string or a new encoding of a port may need manual
classification. Never refresh the policy automatically in CI or treat
an allowlist reason as proof of a safe network configuration. In
particular the spent provider one-shot, local-ari-lab's pinned jailed
fixture and the development test-registration path remain visible
historical exceptions, not generic production configuration.
