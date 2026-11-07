package serviceconfig

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

const ARIPeerPath = Directory + "/ari-peer.pem"
const maxARIPeerBytes = 32768

// ParseARIPeerCertificate accepts one public leaf certificate for the numeric
// loopback TLS peer. No keys, extra blocks, implicit CA or environment input.
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
	return cert, nil
}

// ReadARIPeerCertificate uses a fixed root:vgw 0640 single-linked file in the
// existing root:vgw 0750 directory. Pin rotation is explicit reprovision+restart.
func ReadARIPeerCertificate() (*x509.Certificate, error) {
	group, err := user.LookupGroup(GroupName)
	if err != nil {
		return nil, reject()
	}
	gid, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil {
		return nil, reject()
	}
	return readARIPeerCertificate(ARIPeerPath, 0, uint32(gid))
}

func readARIPeerCertificate(path string, uid, gid uint32) (*x509.Certificate, error) {
	dir, err := os.Lstat(filepath.Dir(path))
	if err != nil || !owned(dir, uid, gid, 0750, false) {
		return nil, reject()
	}
	entry, err := os.Lstat(path)
	if err != nil || !owned(entry, uid, gid, 0640, true) || entry.Size() > maxARIPeerBytes {
		return nil, reject()
	}
	fd, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, reject()
	}
	defer fd.Close()
	opened, err := fd.Stat()
	if err != nil || !os.SameFile(entry, opened) || !owned(opened, uid, gid, 0640, true) || opened.Size() > maxARIPeerBytes {
		return nil, reject()
	}
	raw, err := io.ReadAll(io.LimitReader(fd, maxARIPeerBytes+1))
	if err != nil {
		return nil, reject()
	}
	return ParseARIPeerCertificate(raw)
}
