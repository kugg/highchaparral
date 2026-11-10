package serviceconfig

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"time"
)

const maxARIPeerBytes = 32768

// ParseARIPeerCertificate accepts one provisioned public leaf, never a key,
// bundle, fetched identity or trust-on-first-use input.
func ParseARIPeerCertificate(raw []byte) (*x509.Certificate, error) {
	if len(raw) == 0 || len(raw) > maxARIPeerBytes {
		return nil, reject()
	}
	raw = bytes.TrimSpace(raw)
	if !bytes.HasPrefix(raw, []byte("-----BEGIN CERTIFICATE-----")) {
		return nil, reject()
	}
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, reject()
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || cert.VerifyHostname("127.0.0.1") != nil {
		return nil, reject()
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	if _, err = cert.Verify(x509.VerifyOptions{Roots: roots, DNSName: "127.0.0.1", CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return nil, reject()
	}
	return cert, nil
}

// ReadARIPeerCertificateWithOptions shares the private configuration reader's
// matched root/group or rootless ownership, parent, inode and link checks.
// Launch arguments select the config path/identity; private bytes cannot.
func ReadARIPeerCertificateWithOptions(options RuntimeOptions) (*x509.Certificate, error) {
	if !options.Valid() || options.UID != uint32(os.Geteuid()) || options.GID != uint32(os.Getegid()) {
		return nil, reject()
	}
	raw, err := readProtected(filepath.Join(filepath.Dir(options.ConfigPath), "ari-peer.pem"), options.UID, options.GID, maxARIPeerBytes)
	if err != nil {
		return nil, err
	}
	return ParseARIPeerCertificate(raw)
}

// Lab provisioning changes only the public-cert path, never transport policy.
func ReadLabARIPeerCertificate(path string) (*x509.Certificate, error) {
	if !validAbs(path) {
		return nil, reject()
	}
	raw, err := readProtected(path, uint32(os.Geteuid()), uint32(os.Getegid()), maxARIPeerBytes)
	if err != nil {
		return nil, err
	}
	return ParseARIPeerCertificate(raw)
}
