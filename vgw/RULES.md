# Component security rules

This file is owned with this component, like its source, dependencies and
CODEOWNERS rules. Developers and agents may amend it through normal repository
review. It is not a security-team lock file.

The reserved block below is the human review surface for the adjacent
`claims.json`. It must contain exactly the same schema-2 object. Edit the claim,
bug-class, fence and control definitions together; run `claim-rules.py --check`
before review. The factory refuses divergent definitions. Computed hashes,
execution verdicts, model output and ticket journals belong in receipts, not in
this file.

## Exact claim shape

| Object | Required fields | Meaning |
| --- | --- | --- |
| Catalog | `schema_version`, `component`, `claims`, `fences`, `bug_classes` | One portable definition at the owning component root. |
| Claim | `id`, `statement`, `preserves`, `bug_classes`, `fences` | The security property, legitimate behavior, mapped failure classes and enforcing fences. |
| Bug class | `id`, `definition` | A recurring failure mechanism; optional `cwe` is descriptive, not coverage proof. |
| Fence | `id`, `kind`, `mechanism`, `controls` | A hard deterministic check or complementary soft intent. Hard fences also require `check`. |
| Control | `path`, `selector`, `introduced` | Current component-relative control and its stable selector. |
| Introduction | `repository`, `ref`, `path` | Original repository, full introducing commit and original path; optional `selector` records a reviewed rename. |

<!-- defensefactory-claims:start -->
```json
{
  "bug_classes": [
    {
      "definition": "A sensitive operation trusts a peer whose identity has not been authenticated.",
      "id": "unauthenticated-peer"
    },
    {
      "definition": "A one-use authorization is replayed or rebound to a different operation.",
      "id": "replayed-authorization"
    },
    {
      "definition": "Secret credential material crosses an unauthorized observation or data boundary.",
      "id": "credential-exposure"
    },
    {
      "definition": "An untrusted origin or local socket principal obtains reservation authority.",
      "id": "cross-origin-reservation"
    },
    {
      "definition": "Unvalidated event data is treated as control authority.",
      "id": "untrusted-event-admission"
    },
    {
      "definition": "Negotiated or received media is routed through an unvalidated address or codec boundary.",
      "id": "unvalidated-media-address"
    },
    {
      "definition": "Concurrent or stale reservation transitions grant conflicting ownership.",
      "id": "non-atomic-reservation"
    },
    {
      "definition": "Recovery reuses a resource while a previous operation may still own it.",
      "id": "unsafe-recovery"
    },
    {
      "definition": "An unsettled operation holds admission indefinitely without bounded recovery.",
      "id": "stuck-call-state"
    },
    {
      "cwe": "CWE-250",
      "definition": "The credential-holding service process runs with a privileged identity (root UID/GID 0) because the service identity gate lacks a non-zero lower bound.",
      "id": "privileged-service-identity"
    },
    {
      "definition": "A failed browser SIP registration retains a credential-bearing agent or prevents safe manual retry.",
      "id": "failed-registration-lifecycle"
    },
    {
      "definition": "Call-affecting state is allocated on the authority of client-controlled headers or unauthenticated claims instead of a server-verified session/principal.",
      "id": "unverified-session-allocation"
    }
  ],
  "claims": [
    {
      "bug_classes": [
        "unauthenticated-peer"
      ],
      "fences": [
        "VGW-FENCE-ARI-TRANSPORT",
        "VGW-FENCE-ARI-PROVISION",
        "VGW-FENCE-ARI-CALLERS",
        "VGW-FENCE-INTENT"
      ],
      "id": "VGW-ARI-PEER-001",
      "preserves": [
        "Valid peer subscription, call lifecycle and owned cleanup remain reachable."
      ],
      "statement": "Every credential-bearing ARI HTTP/WSS request authenticates the intended peer through the canonical transport before credentials are released; trust provisioning cannot introduce a downgrade."
    },
    {
      "bug_classes": [
        "replayed-authorization",
        "unauthenticated-peer"
      ],
      "fences": [
        "VGW-FENCE-RESERVATION",
        "VGW-FENCE-COORDINATOR",
        "VGW-FENCE-INTENT"
      ],
      "id": "VGW-BYOK-NONCE-001",
      "preserves": [
        "A valid bound reservation can complete its intended call."
      ],
      "statement": "A reservation nonce authorizes exactly one call to its bound destination; authoritative readback comes from authenticated ARI, never Stasis arguments."
    },
    {
      "bug_classes": [
        "credential-exposure"
      ],
      "fences": [
        "VGW-FENCE-RESERVATION",
        "VGW-FENCE-COORDINATOR",
        "VGW-FENCE-PROVIDER",
        "VGW-FENCE-INTENT"
      ],
      "id": "VGW-BYOK-CRED-001",
      "preserves": [
        "Legitimate provider authentication uses the credential only through SIP/TLS."
      ],
      "statement": "Provider credentials stay out of logs, browser SIP messages, ARI variables and errors; transient secrets are cleared after use."
    },
    {
      "bug_classes": [
        "cross-origin-reservation"
      ],
      "fences": [
        "VGW-FENCE-ORIGIN",
        "VGW-FENCE-COORDINATOR",
        "VGW-FENCE-INTENT"
      ],
      "id": "VGW-BYOK-ORIGIN-001",
      "preserves": [
        "Legitimate same-origin reservations remain available."
      ],
      "statement": "Reservations require the configured HTTPS Origin/Host and client header; their Unix socket is owner-only 0600 with verified identity/link count and stale-socket refusal."
    },
    {
      "bug_classes": [
        "untrusted-event-admission",
        "unauthenticated-peer"
      ],
      "fences": [
        "VGW-FENCE-ARI-ADMISSION",
        "VGW-FENCE-ARI-TRANSPORT",
        "VGW-FENCE-ARI-CALLERS",
        "VGW-FENCE-INTENT"
      ],
      "id": "VGW-ARI-ADMISSION-001",
      "preserves": [
        "Valid Stasis events and legitimate browser calls are admitted."
      ],
      "statement": "ARI uses the fixed IPv4 loopback destination and canonical authenticated transport, and validates all browser/Stasis admission fields before granting control."
    },
    {
      "bug_classes": [
        "unauthenticated-peer"
      ],
      "fences": [
        "VGW-FENCE-TLS",
        "VGW-FENCE-PROVIDER",
        "VGW-FENCE-INTENT"
      ],
      "id": "VGW-PROVIDER-TLS-001",
      "preserves": [
        "Valid provider TLS calls proceed."
      ],
      "statement": "Provider transport requires TLS 1.2 or newer, trusted roots, hostname and host-allowlist validation; insecure verification cannot be enabled."
    },
    {
      "bug_classes": [
        "unvalidated-media-address"
      ],
      "fences": [
        "VGW-FENCE-MEDIA",
        "VGW-FENCE-PROVIDER",
        "VGW-FENCE-INTENT"
      ],
      "id": "VGW-PROVIDER-SDP-001",
      "preserves": [
        "Valid public single-PCMA media remains usable."
      ],
      "statement": "Provider media accepts only the permitted public PCMA answer, rejects private/loopback/multicast/unspecified addresses and multiple codecs, and admits RTP only from the negotiated source."
    },
    {
      "bug_classes": [
        "non-atomic-reservation",
        "unsafe-recovery"
      ],
      "fences": [
        "VGW-FENCE-RESERVATION",
        "VGW-FENCE-COORDINATOR",
        "VGW-FENCE-INTENT"
      ],
      "id": "VGW-BYOK-STATE-001",
      "preserves": [
        "A settled call releases its slot; any bounded recovery preserves exclusive call ownership."
      ],
      "statement": "Reservation consumption and ownership transitions are atomic, prevent double-spend/TOCTOU grants, and retain exclusivity while teardown is unsettled."
    },
    {
      "bug_classes": [
        "stuck-call-state",
        "unsafe-recovery"
      ],
      "fences": [
        "VGW-FENCE-RECOVERY",
        "VGW-FENCE-INTENT"
      ],
      "id": "VGW-BYOK-RECOVERY-001",
      "preserves": [
        "Calls remain exclusive during the recovery bound and new legitimate reservations can eventually proceed."
      ],
      "statement": "An ambiguous call cannot monopolize admission indefinitely; bounded recovery must exclude a still-live prior provider leg before the slot is reused."
    },
    {
      "bug_classes": [
        "privileged-service-identity"
      ],
      "fences": [
        "VGW-FENCE-IDENTITY"
      ],
      "id": "VGW-IDENTITY-NONROOT-001",
      "preserves": [
        "Legitimate non-zero service identities start and operate unchanged; the --run-uid/--run-gid pin cannot select root."
      ],
      "statement": "Every VGW service mode refuses to run with UID or GID 0: the canonical RuntimeOptions.Valid() lower bound rejects a root service identity for the static REGISTER path, BYOK, office and flag-bootstrap guards, matching the BYOK non-root posture."
    },
    {
      "bug_classes": [
        "failed-registration-lifecycle"
      ],
      "fences": [
        "VGW-FENCE-SOFTPHONE-REG",
        "VGW-FENCE-INTENT"
      ],
      "id": "VGW-SOFTPHONE-REG-001",
      "preserves": [
        "A valid PBX registration and numeric call remain reachable without automatic retry."
      ],
      "statement": "A failed browser SIP start or registration stops its credential-bearing agent before enabling manual retry; uncertain cleanup prevents a second agent."
    },
    {
      "bug_classes": [
        "unverified-session-allocation",
        "cross-origin-reservation"
      ],
      "fences": [
        "VGW-FENCE-BYOK-ADMISSION"
      ],
      "id": "VGW-BYOK-ADMISSION-001",
      "preserves": [
        "A logged-in caller can reserve and complete exactly one BYOK call."
      ],
      "statement": "A BYOK reservation is allocated only after a server-verified expiring session assertion proves the calling principal; per-principal admission attempts are bounded and a store without a verifier fails closed."
    }
  ],
  "component": "VGW",
  "fences": [
    {
      "check": "vgw-ari-transport",
      "controls": [
        {
          "introduced": {
            "path": "vgw/internal/asterisk/peer_test.go",
            "ref": "365f72c039661349ce0dd41262b2d9eec8824c0b",
            "repository": "kugg/highchaparral"
          },
          "path": "internal/asterisk/peer_test.go",
          "selector": "func TestAuthenticatedARIRejectsImpostorsOnHTTPAndWebSocket("
        }
      ],
      "id": "VGW-FENCE-ARI-TRANSPORT",
      "kind": "hard",
      "mechanism": "test"
    },
    {
      "check": "vgw-ari-provision",
      "controls": [
        {
          "introduced": {
            "path": "vgw/internal/serviceconfig/ari_peer_test.go",
            "ref": "6c79e387cfcac019b38f55c77a6ba5d639c8402c",
            "repository": "kugg/highchaparral"
          },
          "path": "internal/serviceconfig/ari_peer_test.go",
          "selector": "func TestARIPeerProvisioningUsesRootlessRuntimeIdentityAndProtectedFiles("
        }
      ],
      "id": "VGW-FENCE-ARI-PROVISION",
      "kind": "hard",
      "mechanism": "test"
    },
    {
      "check": "vgw-ari-callers",
      "controls": [
        {
          "introduced": {
            "path": "vgw/internal/asterisk/caller_policy_test.go",
            "ref": "6c79e387cfcac019b38f55c77a6ba5d639c8402c",
            "repository": "kugg/highchaparral"
          },
          "path": "internal/asterisk/caller_policy_test.go",
          "selector": "func TestAllARICallersProvideExplicitPeerIdentity("
        }
      ],
      "id": "VGW-FENCE-ARI-CALLERS",
      "kind": "hard",
      "mechanism": "test"
    },
    {
      "check": "vgw-reservation-contract",
      "controls": [
        {
          "introduced": {
            "path": "vgw/internal/byok/reservation_test.go",
            "ref": "d1bdbeadbcbd8ea542c4fc5588a462c830c360f3",
            "repository": "kugg/highchaparral"
          },
          "path": "internal/byok/reservation_test.go",
          "selector": "func TestBYOKReservationIsEphemeralOneCallAndNeverEchoesCredential("
        }
      ],
      "id": "VGW-FENCE-RESERVATION",
      "kind": "hard",
      "mechanism": "test"
    },
    {
      "check": "vgw-coordinator-contract",
      "controls": [
        {
          "introduced": {
            "path": "vgw/internal/softphone/coordinator_test.go",
            "ref": "d1bdbeadbcbd8ea542c4fc5588a462c830c360f3",
            "repository": "kugg/highchaparral"
          },
          "path": "internal/softphone/coordinator_test.go",
          "selector": "func TestBrowserCallConsumesOneBYOKCredentialAfterReadbackAndDefiniteCleanup("
        }
      ],
      "id": "VGW-FENCE-COORDINATOR",
      "kind": "hard",
      "mechanism": "test"
    },
    {
      "check": "vgw-origin-contract",
      "controls": [
        {
          "introduced": {
            "path": "vgw/internal/byok/reservation_test.go",
            "ref": "d1bdbeadbcbd8ea542c4fc5588a462c830c360f3",
            "repository": "kugg/highchaparral"
          },
          "path": "internal/byok/reservation_test.go",
          "selector": "func TestBYOKOriginCannotDowngradeToPlaintextOrExternalPath("
        }
      ],
      "id": "VGW-FENCE-ORIGIN",
      "kind": "hard",
      "mechanism": "test"
    },
    {
      "check": "vgw-ari-admission-contract",
      "controls": [
        {
          "introduced": {
            "path": "vgw/internal/asterisk/ari_test.go",
            "ref": "d1bdbeadbcbd8ea542c4fc5588a462c830c360f3",
            "repository": "kugg/highchaparral"
          },
          "path": "internal/asterisk/ari_test.go",
          "selector": "func TestRejectRemoteOrRedirectARI("
        },
        {
          "introduced": {
            "path": "vgw/internal/asterisk/browser_event_test.go",
            "ref": "d1bdbeadbcbd8ea542c4fc5588a462c830c360f3",
            "repository": "kugg/highchaparral"
          },
          "path": "internal/asterisk/browser_event_test.go",
          "selector": "func TestBrowserAdmissionRefusesForeignEndpointsAndInboundInjection("
        }
      ],
      "id": "VGW-FENCE-ARI-ADMISSION",
      "kind": "hard",
      "mechanism": "test"
    },
    {
      "check": "vgw-provider-contract",
      "controls": [
        {
          "introduced": {
            "path": "vgw/internal/provider/leg_test.go",
            "ref": "d1bdbeadbcbd8ea542c4fc5588a462c830c360f3",
            "repository": "kugg/highchaparral"
          },
          "path": "internal/provider/leg_test.go",
          "selector": "func TestBYOKProviderBridgesOwnedPCMAAndConfirmsTeardown("
        }
      ],
      "id": "VGW-FENCE-PROVIDER",
      "kind": "hard",
      "mechanism": "test"
    },
    {
      "check": "vgw-tls-contract",
      "controls": [
        {
          "introduced": {
            "path": "vgw/internal/registration/registration_test.go",
            "ref": "d1bdbeadbcbd8ea542c4fc5588a462c830c360f3",
            "repository": "kugg/highchaparral"
          },
          "path": "internal/registration/registration_test.go",
          "selector": "func TestInvalidTLSAndCredential("
        },
        {
          "introduced": {
            "path": "vgw/internal/registration/registration_test.go",
            "ref": "d1bdbeadbcbd8ea542c4fc5588a462c830c360f3",
            "repository": "kugg/highchaparral"
          },
          "path": "internal/registration/registration_test.go",
          "selector": "func TestExpiredCertificateAndOldTLS("
        }
      ],
      "id": "VGW-FENCE-TLS",
      "kind": "hard",
      "mechanism": "test"
    },
    {
      "check": "vgw-media-contract",
      "controls": [
        {
          "introduced": {
            "path": "vgw/internal/asterisk/media_test.go",
            "ref": "d1bdbeadbcbd8ea542c4fc5588a462c830c360f3",
            "repository": "kugg/highchaparral"
          },
          "path": "internal/asterisk/media_test.go",
          "selector": "func TestSeparateMediaRelayRejectsUnownedAndMalformedRTP("
        }
      ],
      "id": "VGW-FENCE-MEDIA",
      "kind": "hard",
      "mechanism": "test"
    },
    {
      "check": "vgw-recovery-contract",
      "controls": [
        {
          "introduced": {
            "path": "vgw/internal/byok/reservation_test.go",
            "ref": "0a99b49b4d293a42b7679958a016519af1a98b0e",
            "repository": "kugg/highchaparral"
          },
          "path": "internal/byok/reservation_test.go",
          "selector": "func TestBYOKActiveSlotAutoRecoversAfterTTL("
        }
      ],
      "id": "VGW-FENCE-RECOVERY",
      "kind": "hard",
      "mechanism": "test"
    },
    {
      "controls": [
        {
          "introduced": {
            "path": "vgw/AGENTS.md",
            "ref": "f78145c1acf746d9cd17801ebc4fb9b608a523cf",
            "repository": "kugg/highchaparral"
          },
          "path": "AGENTS.md",
          "selector": "Developers and agents maintain"
        }
      ],
      "id": "VGW-FENCE-INTENT",
      "kind": "soft",
      "mechanism": "guidance"
    },
    {
      "check": "vgw-identity-nonroot-contract",
      "controls": [
        {
          "introduced": {
            "path": "vgw/internal/serviceconfig/runtime.go",
            "ref": "6d80f6db004cbfb2a20179db14928e417a1e21eb",
            "repository": "kugg/highchaparral"
          },
          "path": "internal/serviceconfig/runtime.go",
          "selector": "r.UID != 0 && r.GID != 0"
        },
        {
          "introduced": {
            "path": "vgw/internal/serviceconfig/root_refusal_test.go",
            "ref": "6d80f6db004cbfb2a20179db14928e417a1e21eb",
            "repository": "kugg/highchaparral"
          },
          "path": "internal/serviceconfig/root_refusal_test.go",
          "selector": "func TestValidRejectsRootUIDAndGID("
        },
        {
          "introduced": {
            "path": "vgw/internal/serviceconfig/root_refusal_test.go",
            "ref": "6d80f6db004cbfb2a20179db14928e417a1e21eb",
            "repository": "kugg/highchaparral"
          },
          "path": "internal/serviceconfig/root_refusal_test.go",
          "selector": "func TestRunUIDZeroRefusedByLaunchFlags("
        }
      ],
      "id": "VGW-FENCE-IDENTITY",
      "kind": "hard",
      "mechanism": "test"
    },
    {
      "check": "vgw-softphone-registration-contract",
      "controls": [
        {
          "introduced": {
            "path": "vgw/softphone/test/browser.test.mjs",
            "ref": "36354f49c59a6b36b8c97527fcf84651ef1bd070",
            "repository": "kugg/highchaparral"
          },
          "path": "softphone/test/browser.test.mjs",
          "selector": "test(\"failed REGISTER stops the agent and permits an explicit retry\""
        }
      ],
      "id": "VGW-FENCE-SOFTPHONE-REG",
      "kind": "hard",
      "mechanism": "test"
    },
    {
      "check": "vgw-admission-contract",
      "controls": [
        {
          "introduced": {
            "path": "vgw/internal/byok/admission.go",
            "ref": "bd0a5093c93df28d4bf2868d8fc275af966fd38e",
            "repository": "kugg/highchaparral"
          },
          "path": "internal/byok/admission.go",
          "selector": "func (a *HMACAdmission) Principal("
        },
        {
          "introduced": {
            "path": "vgw/internal/byok/admission_challenge_test.go",
            "ref": "bd0a5093c93df28d4bf2868d8fc275af966fd38e",
            "repository": "kugg/highchaparral"
          },
          "path": "internal/byok/admission_challenge_test.go",
          "selector": "func TestBYOKAdmissionRejectsHeaderOnlyFloodBeforeState("
        }
      ],
      "id": "VGW-FENCE-BYOK-ADMISSION",
      "kind": "hard",
      "mechanism": "test"
    }
  ],
  "schema_version": 2
}
```
<!-- defensefactory-claims:end -->
