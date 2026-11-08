Feature: VGW-BYOK-CRED-001 provider credential confidentiality
  Scenario: security-byok-cred-001
    Given the provider-credential-confidentiality property VGW-BYOK-CRED-001
    When the security obligation predicate credential_never_reaches_logs_sip_ari_or_errors is evaluated
    Then checks cred-redaction, cred-sip-absence, cred-ari-absence must all pass
  Scenario: business-byok-cred-001
    Given the provider-credential-confidentiality property VGW-BYOK-CRED-001
    When the business obligation predicate provider_call_completes_with_tls_only_password is evaluated
    Then checks cred-positive must all pass
  Scenario: architecture-byok-cred-001
    Given the provider-credential-confidentiality property VGW-BYOK-CRED-001
    When the architecture obligation predicate credential_memory_zeroized_after_use is evaluated
    Then checks cred-zeroization must all pass
