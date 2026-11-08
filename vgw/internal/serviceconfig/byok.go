package serviceconfig

import (
	"bytes"
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

const BYOKPath = "/etc/voip-gateway/byok.config"

var byokKeys = [...]string{"ARI_USER", "ARI_PASSWORD", "UPSTREAM_HOST", "UPSTREAM_PORT",
	"UPSTREAM_TLS_NAME", "UPSTREAM_CERT_SHA256", "SITE_ORIGIN_LAN", "SITE_ORIGIN_WG"}

// BYOKConfig has NO upstream SIP username/password. Callers supply their
// own through a bounded HTTPS reservation in volatile process memory.
type BYOKConfig struct {
	ARIUser, ARIPassword string
	ARIBaseURL           string
	Host, TLSName        string
	Port                 uint16
	BindIPv4             string
	BindPort             uint16
	ErrorLogPath         string
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
	if len(rows) < len(byokKeys) || len(rows) > len(byokKeys)+4 {
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
		allowed = allowed || key == "ARI_BASE_URL" || key == "SIP_BIND_IPV4" ||
			key == "SIP_BIND_PORT" || key == "ERROR_LOG_PATH"
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
	baseURL := DefaultARIBaseURL
	if values["ARI_BASE_URL"] != "" {
		baseURL = values["ARI_BASE_URL"]
	}
	if !validARIURL(baseURL) {
		return empty, reject()
	}
	bindPort, err := parseBindPort(values["SIP_BIND_PORT"])
	if err != nil || (values["SIP_BIND_IPV4"] != "" &&
		(!validHost(values["SIP_BIND_IPV4"]) || net.ParseIP(values["SIP_BIND_IPV4"]).To4() == nil)) ||
		(values["ERROR_LOG_PATH"] != "" && !validAbs(values["ERROR_LOG_PATH"])) {
		return empty, reject()
	}
	return BYOKConfig{ARIUser: values["ARI_USER"], ARIPassword: values["ARI_PASSWORD"],
		Host: values["UPSTREAM_HOST"], TLSName: values["UPSTREAM_TLS_NAME"], Port: uint16(port),
		ARIBaseURL: baseURL, BindIPv4: values["SIP_BIND_IPV4"], BindPort: bindPort,
		ErrorLogPath: values["ERROR_LOG_PATH"],
		Origins:      [2]string{values["SITE_ORIGIN_LAN"], values["SITE_ORIGIN_WG"]}}, nil
}

// ReadBYOKWithOptions enforces the reviewed root:selected-GID path and
// inode boundary before private config bytes are interpreted.
func ReadBYOKWithOptions(options RuntimeOptions) (BYOKConfig, error) {
	if !options.Valid() || options.UID != uint32(os.Geteuid()) || options.GID != uint32(os.Getegid()) {
		return BYOKConfig{}, reject()
	}
	raw, err := readProtected(options.ConfigPath, options.UID, options.GID, 2048)
	if err != nil {
		return BYOKConfig{}, err
	}
	return ParseBYOK(raw)
}

func ReadBYOK() (BYOKConfig, error) {
	return ReadBYOKWithOptions(DefaultBYOKRuntimeOptions())
}
