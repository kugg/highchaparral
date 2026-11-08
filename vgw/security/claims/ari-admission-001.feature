Feature: VGW-ARI-ADMISSION-001 ari loopback and stasis event validation
  Scenario: security-ari-admission-001
    Given the ari-loopback-and-stasis-event-validation property VGW-ARI-ADMISSION-001
    When the security obligation predicate ari_target_pinned_loopback_and_events_validated is evaluated
    Then checks ari-loopback-pin, stasis-event-validation must all pass
  Scenario: business-ari-admission-001
    Given the ari-loopback-and-stasis-event-validation property VGW-ARI-ADMISSION-001
    When the business obligation predicate valid_stasis_event_admitted is evaluated
    Then checks stasis-positive must all pass
  Scenario: architecture-ari-admission-001
    Given the ari-loopback-and-stasis-event-validation property VGW-ARI-ADMISSION-001
    When the architecture obligation predicate single_canonical_authenticated_ari_constructor is evaluated
    Then checks ari-boundary must all pass
