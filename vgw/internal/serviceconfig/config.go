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
	ARIBaseURL       string
	BindIPv4         string
	BindPort         uint16
	ErrorLogPath     string
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
// Eight fixed keys are required; four bounded runtime values are optional
// for compatibility with the old reviewed profile. Provider passwords may
// include '=' because Cut splits only the first equals sign.
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
	if len(items) < len(keys) || len(items) > len(keys)+4 {
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
		allowed = allowed || name == "ARI_BASE_URL" || name == "SIP_BIND_IPV4" ||
			name == "SIP_BIND_PORT" || name == "ERROR_LOG_PATH"
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
	baseURL := DefaultARIBaseURL
	if values["ARI_BASE_URL"] != "" {
		baseURL = values["ARI_BASE_URL"]
	}
	if !validARIURL(baseURL) {
		return result, reject()
	}
	bindPort, err := parseBindPort(values["SIP_BIND_PORT"])
	if err != nil || (values["SIP_BIND_IPV4"] != "" &&
		(net.ParseIP(values["SIP_BIND_IPV4"]) == nil || net.ParseIP(values["SIP_BIND_IPV4"]).To4() == nil)) ||
		(values["ERROR_LOG_PATH"] != "" && !validAbs(values["ERROR_LOG_PATH"])) {
		return result, reject()
	}
	result.ARIUser = values["ARI_USER"]
	result.ARIPassword = values["ARI_PASSWORD"]
	result.UpstreamHost = values["UPSTREAM_HOST"]
	result.UpstreamPort = uint16(port)
	result.UpstreamTLSName = values["UPSTREAM_TLS_NAME"]
	result.UpstreamUsername = values["UPSTREAM_USERNAME"]
	result.UpstreamPassword = values["UPSTREAM_PASSWORD"]
	result.ARIBaseURL = baseURL
	result.BindIPv4 = values["SIP_BIND_IPV4"]
	result.BindPort = bindPort
	result.ErrorLogPath = values["ERROR_LOG_PATH"]
	return result, nil
}

func owned(info os.FileInfo, uid, gid uint32, mode os.FileMode, regular bool) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uid && stat.Gid == gid &&
		info.Mode().Perm() == mode &&
		((regular && info.Mode().IsRegular() && stat.Nlink == 1) ||
			(!regular && info.IsDir()))
}

// readProtected accepts either the legacy root:selected-group 0750/0640
// pair or a rootless selected-user 0700/0600 pair under trusted parents.
// Private config bytes never select their own file path or owner.
func readProtected(path string, uid, gid uint32, max int) ([]byte, error) {
	directory := filepath.Dir(path)
	if !TrustedAncestors(directory, uid) {
		return nil, reject()
	}
	dir, err := os.Lstat(directory)
	if err != nil || (!owned(dir, 0, gid, 0750, false) && !owned(dir, uid, gid, 0700, false)) {
		return nil, reject()
	}
	entry, err := os.Lstat(path)
	if err != nil {
		return nil, reject()
	}
	rootManaged := owned(dir, 0, gid, 0750, false) && owned(entry, 0, gid, 0640, true)
	selfManaged := owned(dir, uid, gid, 0700, false) && owned(entry, uid, gid, 0600, true)
	if (!rootManaged && !selfManaged) || entry.Size() > int64(max) {
		return nil, reject()
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, reject()
	}
	defer file.Close()
	opened, err := file.Stat()
	currentDir, dirErr := os.Lstat(directory)
	if err != nil || dirErr != nil || !os.SameFile(dir, currentDir) ||
		!TrustedAncestors(directory, uid) || !os.SameFile(entry, opened) ||
		(rootManaged && !owned(opened, 0, gid, 0640, true)) ||
		(selfManaged && !owned(opened, uid, gid, 0600, true)) || opened.Size() > int64(max) {
		return nil, reject()
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(max)+1))
	if err != nil || len(raw) > max {
		return nil, reject()
	}
	return raw, nil
}

// ReadWithOptions uses a trusted supervisor-selected path and GID.
// Private config bytes can never select their own owner or location.
func ReadWithOptions(options RuntimeOptions) (Config, error) {
	if !options.Valid() || options.UID != uint32(os.Geteuid()) || options.GID != uint32(os.Getegid()) {
		return Config{}, reject()
	}
	raw, err := readProtected(options.ConfigPath, options.UID, options.GID, maxBytes)
	if err != nil {
		return Config{}, err
	}
	return Parse(raw)
}

// Read retains the historical defaults for reviewed deployments.
func Read() (Config, error) {
	return ReadWithOptions(DefaultRuntimeOptions())
}
