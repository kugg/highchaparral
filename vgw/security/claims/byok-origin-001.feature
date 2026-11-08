Feature: VGW-BYOK-ORIGIN-001 reservation origin and socket boundary
  Scenario: security-byok-origin-001
    Given the reservation-origin-and-socket-boundary property VGW-BYOK-ORIGIN-001
    When the security obligation predicate exact_https_origin_and_client_header_required is evaluated
    Then checks origin-mismatch-reject, client-header-reject must all pass
  Scenario: business-byok-origin-001
    Given the reservation-origin-and-socket-boundary property VGW-BYOK-ORIGIN-001
    When the business obligation predicate legitimate_same_origin_reservation_accepted is evaluated
    Then checks origin-positive must all pass
  Scenario: architecture-byok-origin-001
    Given the reservation-origin-and-socket-boundary property VGW-BYOK-ORIGIN-001
    When the architecture obligation predicate unix_socket_owner_only_0600_verified is evaluated
    Then checks socket-perms must all pass
