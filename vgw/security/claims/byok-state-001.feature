Feature: VGW-BYOK-STATE-001 byok atomic state transitions
  Scenario: security-byok-state-001
    Given the byok-atomic-state-transitions property VGW-BYOK-STATE-001
    When the security obligation predicate atomic_consume_prevents_double_spend_and_toctou is evaluated
    Then checks state-consume-atomic, state-toctou must all pass
  Scenario: business-byok-state-001
    Given the byok-atomic-state-transitions property VGW-BYOK-STATE-001
    When the business obligation predicate one_call_completes_and_releases_slot is evaluated
    Then checks state-positive must all pass
  Scenario: architecture-byok-state-001
    Given the byok-atomic-state-transitions property VGW-BYOK-STATE-001
    When the architecture obligation predicate fail_closed_on_ambiguous_teardown is evaluated
    Then checks state-failclosed must all pass
