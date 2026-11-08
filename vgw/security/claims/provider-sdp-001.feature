Feature: VGW-PROVIDER-SDP-001 provider sdp rtp address validation
  Scenario: security-provider-sdp-001
    Given the provider-sdp-rtp-address-validation property VGW-PROVIDER-SDP-001
    When the security obligation predicate reject_private_loopback_multicast_unspecified_rtp_and_non_pcma is evaluated
    Then checks sdp-rtp-negative must all pass
  Scenario: business-provider-sdp-001
    Given the provider-sdp-rtp-address-validation property VGW-PROVIDER-SDP-001
    When the business obligation predicate valid_public_pcma_answer_accepted is evaluated
    Then checks sdp-rtp-positive must all pass
  Scenario: architecture-provider-sdp-001
    Given the provider-sdp-rtp-address-validation property VGW-PROVIDER-SDP-001
    When the architecture obligation predicate rtp_source_must_match_sdp_address is evaluated
    Then checks sdp-source-match must all pass
