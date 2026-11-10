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
	"strings"
	"testing"
	"time"
)

func syntheticARIPeer(t *testing.T, variant string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	switch variant {
	case "wrong-san":
		cert.IPAddresses = nil
		cert.DNSNames = []string{"wrong.invalid"}
	case "expired":
		cert.NotAfter = time.Now().Add(-time.Minute)
	case "future":
		cert.NotBefore = time.Now().Add(time.Minute)
	case "wrong-usage":
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestARIPeerProvisioningRejectsAmbiguousOrWrongIdentity(t *testing.T) {
	valid := syntheticARIPeer(t, "")
	if _, err := ParseARIPeerCertificate(valid); err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"wrong-san", "expired", "future", "wrong-usage"} {
		t.Run(variant, func(t *testing.T) {
			if _, err := ParseARIPeerCertificate(syntheticARIPeer(t, variant)); err == nil {
				t.Fatal("invalid identity accepted")
			}
		})
	}
	for _, raw := range [][]byte{nil, []byte("not PEM"), append(append([]byte{}, valid...), valid...), append(append([]byte{}, valid...), []byte("extra")...), append([]byte("comment\n"), valid...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("synthetic")}), []byte(strings.Repeat("x", maxARIPeerBytes+1))} {
		if _, err := ParseARIPeerCertificate(raw); err == nil {
			t.Fatal("ambiguous provisioning accepted")
		}
	}
}

func TestARIPeerProvisioningUsesRootlessRuntimeIdentityAndProtectedFiles(t *testing.T) {
	dir := privateRoot(t)
	path := filepath.Join(dir, "ari-peer.pem")
	raw := syntheticARIPeer(t, "")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	options := DefaultBYOKRuntimeOptions()
	options.ConfigPath = filepath.Join(dir, "case.config")
	read := func() error { _, err := ReadARIPeerCertificateWithOptions(options); return err }
	if err := read(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadLabARIPeerCertificate(path); err != nil {
		t.Fatal(err)
	}
	options.UID++
	if read() == nil {
		t.Fatal("foreign runtime identity accepted")
	}
	options.UID--
	for _, mode := range []os.FileMode{0644, 0640, 0666} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if read() == nil {
			t.Fatal("unsafe or mixed ownership profile accepted")
		}
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(dir, "hard.pem")
	if err := os.Link(path, hard); err != nil {
		t.Fatal(err)
	}
	if read() == nil {
		t.Fatal("hardlink accepted")
	}
	if err := os.Remove(hard); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".real"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path+".real", path); err != nil {
		t.Fatal(err)
	}
	if read() == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".real", path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0770); err != nil {
		t.Fatal(err)
	}
	if read() == nil {
		t.Fatal("writable parent accepted")
	}
	if _, err := ReadLabARIPeerCertificate("peer.pem"); err == nil {
		t.Fatal("relative path accepted")
	}
}
