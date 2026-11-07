package serviceconfig

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
)

// TLSClient always requires Go's ordinary CA chain and DNS-name checks.
// A leaf thumbprint is optional only when the owner explicitly selected
// ca-only in the private config; CA/hostname verification is never disabled.
func TLSClient(c Config, roots *x509.CertPool) (*tls.Config, error) {
	hasPin := c.CertSHA256 != [sha256.Size]byte{}
	if roots == nil || !validHost(c.UpstreamHost) || !validHost(c.UpstreamTLSName) ||
		c.UpstreamPort == 0 || (c.CAOnly && hasPin) || (!c.CAOnly && !hasPin) {
		return nil, errors.New("voip-gateway TLS trust unavailable")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		RootCAs:    roots,
		ServerName: c.UpstreamTLSName,
		VerifyConnection: func(state tls.ConnectionState) error {
			// VerifyConnection runs during the handshake, before Go sets
			// HandshakeComplete. VerifiedChains is the actual CA/name evidence.
			if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 {
				return errors.New("voip-gateway TLS peer not CA/host verified")
			}
			if !c.CAOnly {
				actual := sha256.Sum256(state.PeerCertificates[0].Raw)
				if subtle.ConstantTimeCompare(actual[:], c.CertSHA256[:]) != 1 {
					return errors.New("voip-gateway TLS certificate pin mismatch")
				}
			}
			return nil
		},
	}, nil
}
