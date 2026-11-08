Feature: VGW-PROVIDER-TLS-001 provider tls and host validation
  Scenario: security-provider-tls-001
    Given the provider-tls-and-host-validation property VGW-PROVIDER-TLS-001
    When the security obligation predicate tls_min12_roots_hostname_and_host_allowlist_enforced is evaluated
    Then checks provider-tls-negative must all pass
  Scenario: business-provider-tls-001
    Given the provider-tls-and-host-validation property VGW-PROVIDER-TLS-001
    When the business obligation predicate valid_provider_tls_call_proceeds is evaluated
    Then checks provider-tls-positive must all pass
  Scenario: architecture-provider-tls-001
    Given the provider-tls-and-host-validation property VGW-PROVIDER-TLS-001
    When the architecture obligation predicate insecure_skip_verify_structurally_rejected is evaluated
    Then checks provider-tls-invariant must all pass
