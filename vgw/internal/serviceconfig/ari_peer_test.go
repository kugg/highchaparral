package serviceconfig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func syntheticARIPeer(t *testing.T, loopback bool) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if loopback {
		cert.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		cert.DNSNames = []string{"wrong.invalid"}
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestARIPeerProvisioningRejectsAmbiguousOrWrongIdentity(t *testing.T) {
	valid := syntheticARIPeer(t, true)
	if _, err := ParseARIPeerCertificate(valid); err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{nil, []byte("not a certificate"), syntheticARIPeer(t, false), append(append([]byte{}, valid...), valid...), append(append([]byte{}, valid...), []byte("extra")...), append([]byte("comment\n"), valid...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("test-only")})} {
		if _, err := ParseARIPeerCertificate(raw); err == nil {
			t.Fatal("unreviewed ARI peer input accepted")
		}
	}
}

func TestARIPeerFileRequiresOwnedDirectoryAndSingleRegularFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "ari-peer.pem")
	if err := os.WriteFile(path, syntheticARIPeer(t, true), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if _, err := readARIPeerCertificate(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	if _, err := readARIPeerCertificate(path, uid+1, gid); err == nil {
		t.Fatal("wrong owner accepted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readARIPeerCertificate(path, uid, gid); err == nil {
		t.Fatal("unreviewed file mode accepted")
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "peer-link.pem")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readARIPeerCertificate(link, uid, gid); err == nil {
		t.Fatal("symlink accepted")
	}
	hard := filepath.Join(dir, "peer-hard.pem")
	if err := os.Link(path, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := readARIPeerCertificate(path, uid, gid); err == nil {
		t.Fatal("hardlink accepted")
	}
	if err := os.Remove(hard); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0770); err != nil {
		t.Fatal(err)
	}
	if _, err := readARIPeerCertificate(path, uid, gid); err == nil {
		t.Fatal("group-writable directory accepted")
	}
}
