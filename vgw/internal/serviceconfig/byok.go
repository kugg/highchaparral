package serviceconfig

import (
	"bytes"
	"errors"
	"io"
	"net/url"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
)

const BYOKPath = "/etc/voip-gateway/byok.config"

var byokKeys = [...]string{"ARI_USER", "ARI_PASSWORD", "UPSTREAM_HOST", "UPSTREAM_PORT",
	"UPSTREAM_TLS_NAME", "UPSTREAM_CERT_SHA256", "SITE_ORIGIN_LAN", "SITE_ORIGIN_WG"}

// BYOKConfig has NO upstream SIP username/password. Callers supply their
// own through a bounded HTTPS reservation in volatile process memory.
type BYOKConfig struct {
	ARIUser, ARIPassword string
	Host, TLSName        string
	Port                 uint16
	Origins              [2]string
}

func (BYOKConfig) String() string   { return "BYOK gateway config [redacted]" }
func (BYOKConfig) GoString() string { return "serviceconfig.BYOKConfig{redacted}" }
func (BYOKConfig) MarshalJSON() ([]byte, error) {
	return nil, errors.New("BYOK config serialization refused")
}

func parseOrigin(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil &&
		u.Path == "" && u.RawQuery == "" && u.Fragment == "" && u.String() == value
}

// ParseBYOK accepts exactly eight fixed printable lines and requires an
// explicit CA/hostname-only trust policy. No shared provider credential
// key or extra field can be smuggled into the static service config.
func ParseBYOK(raw []byte) (BYOKConfig, error) {
	var empty BYOKConfig
	if len(raw) < 140 || len(raw) > 2048 || bytes.IndexAny(raw, "\r\x00") >= 0 ||
		!bytes.HasSuffix(raw, []byte("\n")) || bytes.Contains(raw, []byte("\n\n")) {
		return empty, reject()
	}
	rows := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(rows) != len(byokKeys) {
		return empty, reject()
	}
	values := make(map[string]string, len(byokKeys))
	for _, row := range rows {
		key, value, found := strings.Cut(row, "=")
		if !found || value == "" || len(value) > 256 || values[key] != "" {
			return empty, reject()
		}
		allowed := false
		for _, want := range byokKeys {
			allowed = allowed || key == want
		}
		if !allowed {
			return empty, reject()
		}
		for _, ch := range value {
			if ch < '!' || ch > '~' {
				return empty, reject()
			}
		}
		values[key] = value
	}
	port, err := strconv.Atoi(values["UPSTREAM_PORT"])
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != values["UPSTREAM_PORT"] ||
		!ariName.MatchString(values["ARI_USER"]) || !ariPass.MatchString(values["ARI_PASSWORD"]) ||
		!validHost(values["UPSTREAM_HOST"]) || !validHost(values["UPSTREAM_TLS_NAME"]) ||
		values["UPSTREAM_HOST"] != values["UPSTREAM_TLS_NAME"] ||
		values["UPSTREAM_CERT_SHA256"] != "ca-only" ||
		!parseOrigin(values["SITE_ORIGIN_LAN"]) || !parseOrigin(values["SITE_ORIGIN_WG"]) ||
		values["SITE_ORIGIN_LAN"] == values["SITE_ORIGIN_WG"] {
		return empty, reject()
	}
	return BYOKConfig{ARIUser: values["ARI_USER"], ARIPassword: values["ARI_PASSWORD"],
		Host: values["UPSTREAM_HOST"], TLSName: values["UPSTREAM_TLS_NAME"], Port: uint16(port),
		Origins: [2]string{values["SITE_ORIGIN_LAN"], values["SITE_ORIGIN_WG"]}}, nil
}

// ReadBYOK requires the existing root:vgw 0750 directory, a root:vgw
// 0640 single-linked fixed config and no symlink. No path comes from env.
func ReadBYOK() (BYOKConfig, error) {
	var empty BYOKConfig
	group, err := user.LookupGroup(GroupName)
	if err != nil {
		return empty, reject()
	}
	parsed, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil {
		return empty, reject()
	}
	gid := uint32(parsed)
	dir, err := os.Lstat(Directory)
	if err != nil || !owned(dir, 0, gid, 0750, false) {
		return empty, reject()
	}
	entry, err := os.Lstat(BYOKPath)
	if err != nil || !owned(entry, 0, gid, 0640, true) || entry.Size() > 2048 {
		return empty, reject()
	}
	fd, err := os.OpenFile(BYOKPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return empty, reject()
	}
	defer fd.Close()
	opened, err := fd.Stat()
	if err != nil || !os.SameFile(entry, opened) || !owned(opened, 0, gid, 0640, true) || opened.Size() > 2048 {
		return empty, reject()
	}
	raw, err := io.ReadAll(io.LimitReader(fd, 2049))
	if err != nil || len(raw) > 2048 {
		return empty, reject()
	}
	return ParseBYOK(raw)
}
