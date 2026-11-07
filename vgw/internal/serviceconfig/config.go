// Package serviceconfig specifies the future voip-gateway (vgw) service's
// bounded, private configuration. It is NOT used by the twin-only
// local-ari-lab-v4 fixture or the attended provider-one-shot binary.
package serviceconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

const (
	ServiceName = "voip-gateway"
	ShortName   = "vgw"
	GroupName   = "vgw"
	Path        = "/etc/voip-gateway/config"
	Directory   = "/etc/voip-gateway"
	maxBytes    = 4096
)

var (
	ariName  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	ariPass  = regexp.MustCompile(`^[A-Za-z0-9_-]{16,256}$`)
	sipName  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	pinHex   = regexp.MustCompile(`^[a-f0-9]{64}$`)
	keys     = [...]string{"ARI_USER", "ARI_PASSWORD", "UPSTREAM_HOST", "UPSTREAM_PORT", "UPSTREAM_TLS_NAME", "UPSTREAM_USERNAME", "UPSTREAM_PASSWORD", "UPSTREAM_CERT_SHA256"}
)

// Config contains independent local ARI and remote SIP trust/identity.
// Secrets are process-local; accidental fmt/slog rendering is redacted.
type Config struct {
	ARIUser          string
	ARIPassword      string
	UpstreamHost     string
	UpstreamPort     uint16
	UpstreamTLSName  string
	UpstreamUsername string
	UpstreamPassword string
	CertSHA256       [sha256.Size]byte // SHA256 of the DER-encoded leaf cert.
	CAOnly           bool              // explicit "ca-only" policy, never an implicit missing pin.
}

func (Config) String() string { return "voip-gateway configuration [redacted]" }

func (Config) GoString() string { return "serviceconfig.Config{redacted}" }

func (Config) LogValue() slog.Value {
	return slog.StringValue("voip-gateway configuration [redacted]")
}

func (Config) MarshalJSON() ([]byte, error) {
	return nil, errors.New("voip-gateway configuration serialization refused")
}

func reject() error { return errors.New("voip-gateway configuration invalid") }

func validHost(host string) bool {
	if len(host) == 0 || len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsUnspecified() && !ip.IsMulticast()
	}
	for _, label := range strings.Split(host, ".") {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// Parse treats the config as DATA, never as an executable shell env file.
// Exactly eight fixed keys are required. Values are one bounded printable
// ASCII line each; upstream passwords may include '=' because SplitN is used.
func Parse(raw []byte) (Config, error) {
	var result Config
	if len(raw) < 140 || len(raw) > maxBytes || bytes.IndexAny(raw, "\r\x00") >= 0 {
		return result, reject()
	}
	text := string(raw)
	if !strings.HasSuffix(text, "\n") || strings.Contains(text, "\n\n") {
		return result, reject()
	}
	items := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(items) != len(keys) {
		return result, reject()
	}
	values := make(map[string]string, len(keys))
	for _, line := range items {
		name, value, ok := strings.Cut(line, "=")
		if !ok || name == "" || value == "" {
			return result, reject()
		}
		allowed := false
		for _, key := range keys {
			allowed = allowed || key == name
		}
		if !allowed || values[name] != "" || len(value) > 256 {
			return result, reject()
		}
		for _, character := range value {
			if character < 0x21 || character > 0x7e {
				return result, reject()
			}
		}
		values[name] = value
	}
	port, err := strconv.Atoi(values["UPSTREAM_PORT"])
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != values["UPSTREAM_PORT"] ||
		!ariName.MatchString(values["ARI_USER"]) || !ariPass.MatchString(values["ARI_PASSWORD"]) ||
		!validHost(values["UPSTREAM_HOST"]) || !validHost(values["UPSTREAM_TLS_NAME"]) ||
		!sipName.MatchString(values["UPSTREAM_USERNAME"]) ||
		len(values["UPSTREAM_PASSWORD"]) < 1 ||
		(values["UPSTREAM_CERT_SHA256"] != "ca-only" && !pinHex.MatchString(values["UPSTREAM_CERT_SHA256"])) {
		return result, reject()
	}
	if values["UPSTREAM_CERT_SHA256"] == "ca-only" {
		result.CAOnly = true
	} else {
		pin, err := hex.DecodeString(values["UPSTREAM_CERT_SHA256"])
		if err != nil || len(pin) != sha256.Size {
			return result, reject()
		}
		copy(result.CertSHA256[:], pin)
	}
	result.ARIUser = values["ARI_USER"]
	result.ARIPassword = values["ARI_PASSWORD"]
	result.UpstreamHost = values["UPSTREAM_HOST"]
	result.UpstreamPort = uint16(port)
	result.UpstreamTLSName = values["UPSTREAM_TLS_NAME"]
	result.UpstreamUsername = values["UPSTREAM_USERNAME"]
	result.UpstreamPassword = values["UPSTREAM_PASSWORD"]
	return result, nil
}

func owned(info os.FileInfo, uid, gid uint32, mode os.FileMode, regular bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid && stat.Gid == gid &&
		info.Mode().Perm() == mode &&
		((regular && info.Mode().IsRegular() && stat.Nlink == 1) ||
			(!regular && info.IsDir()))
}

// Read uses a service-named, fixed path, never an environment-supplied
// location. The directory/file must be root:vgw, 0750/0640, with
// no symlink or hardlink; validation is repeated on the opened inode.
func Read() (Config, error) {
	var empty Config
	group, err := user.LookupGroup(GroupName)
	if err != nil {
		return empty, reject()
	}
	parsed, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil {
		return empty, reject()
	}
	gid := uint32(parsed)
	if filepath.Clean(Path) != Path {
		return empty, reject()
	}
	dir, err := os.Lstat(Directory)
	if err != nil || !owned(dir, 0, gid, 0750, false) {
		return empty, reject()
	}
	entry, err := os.Lstat(Path)
	if err != nil || !owned(entry, 0, gid, 0640, true) || entry.Size() > maxBytes {
		return empty, reject()
	}
	fd, err := os.OpenFile(Path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return empty, reject()
	}
	defer fd.Close()
	opened, err := fd.Stat()
	if err != nil || !os.SameFile(entry, opened) || !owned(opened, 0, gid, 0640, true) || opened.Size() > maxBytes {
		return empty, reject()
	}
	raw, err := io.ReadAll(io.LimitReader(fd, maxBytes+1))
	if err != nil || len(raw) > maxBytes {
		return empty, reject()
	}
	return Parse(raw)
}
