package serviceconfig

// RuntimeOptions are trusted process-launch arguments. Identity defaults
// to the *actual* process, never to a compiled-in UID/GID or passwd entry.

import (
	"errors"
	"flag"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
)

const DefaultOfficePort uint16 = 5061
const DefaultARIBaseURL = "http://127.0.0.1:8088"

type RuntimeOptions struct {
	UID, GID    uint32
	ConfigPath  string
	RuntimeDir  string
	StateDir    string
	SocketName  string
	PIDFileName string // empty means the service manager tracks the PID
	OfficePort  uint16
}

func DefaultRuntimeOptions() RuntimeOptions {
	return RuntimeOptions{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid()),
		ConfigPath: Path, RuntimeDir: "/run/voip-gateway",
		StateDir: "/var/lib/voip-gateway/byok-v1", SocketName: "byok.sock",
		OfficePort: DefaultOfficePort}
}

func DefaultBYOKRuntimeOptions() RuntimeOptions {
	result := DefaultRuntimeOptions()
	result.ConfigPath = BYOKPath
	return result
}

func DefaultOfficeRuntimeOptions() RuntimeOptions {
	result := DefaultRuntimeOptions()
	result.ConfigPath = OfficePath
	return result
}

func (RuntimeOptions) String() string   { return "vgw runtime options [redacted]" }
func (RuntimeOptions) GoString() string { return "serviceconfig.RuntimeOptions{redacted}" }
func (RuntimeOptions) MarshalJSON() ([]byte, error) {
	return nil, errors.New("vgw runtime options serialization refused")
}

var decimalID = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,9})$`)
var localName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$`)

func validAbs(path string) bool {
	if len(path) < 3 || len(path) > 192 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	for _, ch := range path {
		if ch < '!' || ch > '~' {
			return false
		}
	}
	return localName.MatchString(filepath.Base(path))
}

func validARIURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" ||
		u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.String() != raw {
		return false
	}
	port, ok := decimal(u.Port(), 65535)
	return ok && port > 0
}

func parseBindPort(value string) (uint16, error) {
	if value == "" {
		return 0, nil // existing, kernel-assigned ephemeral source port
	}
	port, ok := decimal(value, 65535)
	if !ok {
		return 0, errors.New("invalid SIP bind port")
	}
	return uint16(port), nil
}

// Valid enforces the non-root service identity lower bound: no service
// mode may pin or default to UID/GID 0, matching the BYOK posture.
func (r RuntimeOptions) Valid() bool {
	return r.UID != 0 && r.GID != 0 &&
		r.UID <= 2147483647 && r.GID <= 2147483647 &&
		validAbs(r.ConfigPath) && validAbs(r.RuntimeDir) && validAbs(r.StateDir) &&
		r.RuntimeDir != r.StateDir && localName.MatchString(r.SocketName) &&
		(r.PIDFileName == "" || (localName.MatchString(r.PIDFileName) && r.PIDFileName != r.SocketName)) &&
		r.OfficePort != 0
}

// TrustedAncestors permits root-owned or process-owned non-writable
// ancestors. A root-owned sticky parent (e.g. /tmp) is acceptable only
// when its child is independently checked as a private owned directory.
// Symlink paths, including /var -> /private/var, must first be expressed
// canonically by the trusted launch configuration.
func TrustedAncestors(child string, uid uint32) bool {
	if !filepath.IsAbs(child) || filepath.Clean(child) != child {
		return false
	}
	for parent := filepath.Dir(child); ; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		meta, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (meta.Uid != 0 && meta.Uid != uid) {
			return false
		}
		if info.Mode().Perm()&0022 != 0 && !(meta.Uid == 0 && info.Mode()&os.ModeSticky != 0) {
			return false
		}
		if parent == "/" {
			return true
		}
	}
}

type RuntimeFlags struct {
	defaults                                          RuntimeOptions
	uid, gid, config, run, state, socket, pid, office *string
}

func BindRuntimeFlags(flags *flag.FlagSet, defaults RuntimeOptions) *RuntimeFlags {
	result := &RuntimeFlags{defaults: defaults}
	result.uid = flags.String("run-uid", strconv.FormatUint(uint64(defaults.UID), 10), "optional effective daemon UID (canonical decimal)")
	result.gid = flags.String("run-gid", strconv.FormatUint(uint64(defaults.GID), 10), "optional effective daemon GID (canonical decimal)")
	result.config = flags.String("config", "", "canonical absolute private config path")
	result.run = flags.String("runtime-dir", defaults.RuntimeDir, "owner-only runtime directory")
	result.state = flags.String("state-dir", defaults.StateDir, "owner-only call-state directory")
	result.socket = flags.String("socket-name", defaults.SocketName, "Unix socket basename inside runtime-dir")
	result.pid = flags.String("pid-file", defaults.PIDFileName, "optional PID-file basename; not a chosen PID")
	result.office = flags.String("office-port", strconv.Itoa(int(defaults.OfficePort)), "verified office registrar TLS port")
	return result
}

func decimal(value string, limit uint64) (uint64, bool) {
	if !decimalID.MatchString(value) {
		return 0, false
	}
	number, err := strconv.ParseUint(value, 10, 32)
	return number, err == nil && number <= limit && strconv.FormatUint(number, 10) == value
}

func (f *RuntimeFlags) OptionsFor(defaultPath string) (RuntimeOptions, error) {
	if f == nil {
		return RuntimeOptions{}, errors.New("invalid runtime bootstrap")
	}
	uid, uok := decimal(*f.uid, 2147483647)
	gid, gok := decimal(*f.gid, 2147483647)
	office, ook := decimal(*f.office, 65535)
	result := f.defaults
	result.UID, result.GID, result.OfficePort = uint32(uid), uint32(gid), uint16(office)
	result.ConfigPath, result.RuntimeDir, result.StateDir = *f.config, *f.run, *f.state
	if result.ConfigPath == "" {
		result.ConfigPath = defaultPath
	}
	result.SocketName, result.PIDFileName = *f.socket, *f.pid
	if !uok || !gok || !ook || !result.Valid() {
		return RuntimeOptions{}, errors.New("invalid runtime bootstrap")
	}
	return result, nil
}

func (f *RuntimeFlags) Options() (RuntimeOptions, error) {
	if f == nil {
		return RuntimeOptions{}, errors.New("invalid runtime bootstrap")
	}
	return f.OptionsFor(f.defaults.ConfigPath)
}

func (r RuntimeOptions) SocketPath() string {
	return filepath.Join(r.RuntimeDir, r.SocketName)
}

func (r RuntimeOptions) PIDPath() string {
	if r.PIDFileName == "" {
		return ""
	}
	return filepath.Join(r.RuntimeDir, r.PIDFileName)
}
