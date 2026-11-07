package serviceconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

func testCertificate(t *testing.T, name string) (tls.Certificate, *x509.CertPool, [sha256.Size]byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("test certificate key generation failed")
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(43), Subject: pkix.Name{CommonName: name},
		DNSNames: []string{name}, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if address := net.ParseIP(name); address != nil {
		template.IPAddresses = []net.IP{address}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal("test certificate creation failed")
	}
	pemKey, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal("test certificate encoding failed")
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: pemKey})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal("test TLS keypair invalid")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("synthetic test CA unavailable")
	}
	return cert, roots, sha256.Sum256(der)
}

func dialFixture(t *testing.T, server tls.Certificate, client *tls.Config) error {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{server}, MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal("local test TLS listener failed")
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		peer, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = peer.(*tls.Conn).Handshake()
			_ = peer.Close()
		}
	}()
	dialer := &net.Dialer{Timeout: time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", listener.Addr().String(), client)
	if err == nil {
		_ = conn.Close()
	}
	<-done
	return err
}

func TestCAHostnameAndExactLeafMustAllPass(t *testing.T) {
	cert, roots, thumbprint := testCertificate(t, "edge.provider.test")
	conf := Config{UpstreamHost: "sip.provider.test", UpstreamPort: 5071,
		UpstreamTLSName: "edge.provider.test", CertSHA256: thumbprint}
	client, err := TLSClient(conf, roots)
	if err != nil || client.InsecureSkipVerify || client.ServerName != "edge.provider.test" {
		t.Fatal("ordinary CA and hostname validation not enabled")
	}
	if err := dialFixture(t, cert, client); err != nil {
		t.Fatal("synthetic pinned CA/hostname/cert handshake rejected")
	}
	badPin := conf
	badPin.CertSHA256[0] ^= 1
	wrongPin, err := TLSClient(badPin, roots)
	if err != nil || dialFixture(t, cert, wrongPin) == nil {
		t.Fatal("wrong leaf fingerprint accepted")
	}
	untrusted, err := TLSClient(conf, x509.NewCertPool())
	if err != nil || dialFixture(t, cert, untrusted) == nil {
		t.Fatal("fingerprint bypassed CA trust")
	}
	mismatched := client.Clone()
	mismatched.ServerName = "other.invalid"
	if dialFixture(t, cert, mismatched) == nil {
		t.Fatal("pinned, CA-trusted certificate bypassed hostname check")
	}
	if _, err := TLSClient(Config{UpstreamHost: "sip.provider.test/invalid", UpstreamPort: 5061,
		UpstreamTLSName: "edge.provider.test", CertSHA256: thumbprint}, roots); err == nil {
		t.Fatal("config selected malformed provider address")
	}
	if _, err := TLSClient(Config{UpstreamHost: "sip.other-provider.test", UpstreamPort: 5061,
		UpstreamTLSName: "edge.provider.test", CertSHA256: thumbprint}, roots); err != nil {
		t.Fatal("valid alternate SIP provider refused")
	}
	ipCert, ipRoots, ipPin := testCertificate(t, "127.0.0.1")
	ipConfig, err := TLSClient(Config{UpstreamHost: "127.0.0.1", UpstreamPort: 5061,
		UpstreamTLSName: "127.0.0.1", CertSHA256: ipPin}, ipRoots)
	if err != nil || dialFixture(t, ipCert, ipConfig) != nil {
		t.Fatal("pinned localhost provider test cert IP SAN refused")
	}
	caOnly := conf
	caOnly.CertSHA256 = [sha256.Size]byte{}
	caOnly.CAOnly = true
	caClient, err := TLSClient(caOnly, roots)
	if err != nil || caClient.InsecureSkipVerify || caClient.VerifyConnection == nil ||
		caClient.ServerName != "edge.provider.test" || dialFixture(t, cert, caClient) != nil {
		t.Fatal("explicit CA-only trust did not validate chain and hostname")
	}
	if wrongRoots, err := TLSClient(caOnly, x509.NewCertPool()); err != nil ||
		dialFixture(t, cert, wrongRoots) == nil {
		t.Fatal("CA-only policy accepted an untrusted provider certificate")
	}
	badHost := caClient.Clone()
	badHost.ServerName = "mismatch.invalid"
	if dialFixture(t, cert, badHost) == nil {
		t.Fatal("CA-only policy accepted a mismatched DNS identity")
	}
	if _, err := TLSClient(Config{UpstreamHost: "sip.provider.test", UpstreamPort: 5061,
		UpstreamTLSName: "edge.provider.test"}, roots); err == nil {
		t.Fatal("missing pin silently selected CA-only trust")
	}
	wrongCombination := conf
	wrongCombination.CAOnly = true
	if _, err := TLSClient(wrongCombination, roots); err == nil {
		t.Fatal("simultaneous CA-only and leaf pin accepted")
	}
}
