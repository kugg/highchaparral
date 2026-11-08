Feature: VGW-BYOK-NONCE-001 single use nonce authorization
  Scenario: security-byok-nonce-001
    Given the single-use-nonce-authorization property VGW-BYOK-NONCE-001
    When the security obligation predicate consumed_nonce_implies_authorized_single_call is evaluated
    Then checks nonce-replay, nonce-cross-binding must all pass
  Scenario: business-byok-nonce-001
    Given the single-use-nonce-authorization property VGW-BYOK-NONCE-001
    When the business obligation predicate valid_reservation_completes_exactly_one_call is evaluated
    Then checks nonce-positive must all pass
  Scenario: architecture-byok-nonce-001
    Given the single-use-nonce-authorization property VGW-BYOK-NONCE-001
    When the architecture obligation predicate nonce_authoritative_only_from_authenticated_ari_readback is evaluated
    Then checks nonce-source-binding must all pass
