Feature: VGW-ARI-PEER-001 Authenticate before credential release
  Scenario: peer-authentication
    Given a connected ARI peer
    When the gateway releases credentials
    Then the peer must be authenticated
  Scenario: legitimate-peer
    Given a legitimate ARI peer
    When the peer is authenticated
    Then the gateway can subscribe and clean up
  Scenario: no-plaintext-bypass
    Given every ARI caller
    When it constructs an ARI client
    Then the same authenticated transport is required
