package serviceconfig

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func privateRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(dir, 0700) != nil {
		t.Fatal("private canonical test directory unavailable")
	}
	return dir
}

func TestRootlessConfigPathReadsAllThreePrivateSchemas(t *testing.T) {
	dir := privateRoot(t)
	options := DefaultRuntimeOptions()
	for _, tc := range []struct {
		name, content string
		read          func(RuntimeOptions) error
	}{
		{"service", fixture, func(r RuntimeOptions) error { _, err := ReadWithOptions(r); return err }},
		{"byok", syntheticBYOK, func(r RuntimeOptions) error { _, err := ReadBYOKWithOptions(r); return err }},
		{"office", syntheticOffice, func(r RuntimeOptions) error { account, err := ReadOfficeWithOptions(r); account.Clear(); return err }},
	} {
		path := filepath.Join(dir, tc.name+".config")
		if err := os.WriteFile(path, []byte(tc.content), 0600); err != nil || os.Chmod(path, 0600) != nil {
			t.Fatal("synthetic private config unavailable")
		}
		options.ConfigPath = path
		if err := tc.read(options); err != nil {
			t.Fatalf("rootless %s config refused: %v", tc.name, err)
		}
	}
	path := filepath.Join(dir, "byok.config")
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	options.ConfigPath = path
	if _, err := ReadBYOKWithOptions(options); err == nil {
		t.Fatal("group-readable rootless config accepted")
	}
	options.GID++
	if _, err := ReadBYOKWithOptions(options); err == nil {
		t.Fatal("wrong runtime GID accepted")
	}
}

func TestRuntimeFlagsRootlessDefaultsAndInvalidOverrides(t *testing.T) {
	dir := privateRoot(t)
	fs := flag.NewFlagSet("runtime", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	flags := BindRuntimeFlags(fs, DefaultBYOKRuntimeOptions())
	if err := fs.Parse([]string{"--config=" + filepath.Join(dir, "byok.config"),
		"--runtime-dir=" + filepath.Join(dir, "runtime"),
		"--state-dir=" + filepath.Join(dir, "state"),
		"--socket-name=local.sock", "--pid-file=vgw.pid", "--office-port=15061"}); err != nil {
		t.Fatal(err)
	}
	options, err := flags.Options()
	if err != nil || options.UID != uint32(os.Geteuid()) || options.GID != uint32(os.Getegid()) ||
		options.ConfigPath != filepath.Join(dir, "byok.config") || options.SocketPath() != filepath.Join(dir, "runtime/local.sock") ||
		options.PIDPath() != filepath.Join(dir, "runtime/vgw.pid") || options.OfficePort != 15061 {
		t.Fatal("rootless runtime selectors did not produce reviewed paths")
	}
	if strings.Contains(fmt.Sprintf("%+v", options), dir) {
		t.Fatal("private runtime path leaked through formatter")
	}
	if data, err := json.Marshal(options); err == nil || len(data) != 0 {
		t.Fatal("private runtime options serialized")
	}
	for caseID, bad := range [][]string{
		{"--run-uid=0001"}, {"--run-uid=-1"}, {"--run-gid=9999999999"},
		{"--config=relative"}, {"--config=" + dir + "/../elsewhere"},
		{"--runtime-dir=/tmp/unreviewed/../dir"}, {"--state-dir=state"},
		{"--socket-name=../../escape"}, {"--pid-file=local.sock", "--socket-name=local.sock"},
		{"--office-port=0"}, {"--office-port=65536"},
	} {
		candidate := flag.NewFlagSet("bad", flag.ContinueOnError)
		candidate.SetOutput(io.Discard)
		selected := BindRuntimeFlags(candidate, DefaultRuntimeOptions())
		if candidate.Parse(bad) != nil {
			t.Fatal("flag parse unexpectedly rejected synthetic test input")
		}
		if _, err := selected.Options(); err == nil {
			t.Fatalf("unsafe runtime selector accepted case=%d", caseID)
		}
	}
}

func TestPrivateARIAndBindOptionsRejectUnsafeOverrides(t *testing.T) {
	defaultBYOK, err := ParseBYOK([]byte(syntheticBYOK))
	if err != nil || defaultBYOK.ARIBaseURL != DefaultARIBaseURL || defaultBYOK.BindPort != 0 {
		t.Fatal("legacy BYOK profile lost secure defaults")
	}
	augmented := syntheticBYOK + "ARI_BASE_URL=https://127.0.0.1:18088\n" +
		"SIP_BIND_IPV4=127.0.0.1\nSIP_BIND_PORT=15061\n" +
		"ERROR_LOG_PATH=/var/log/vgw_error.log\n"
	parsed, err := ParseBYOK([]byte(augmented))
	if err != nil || parsed.ARIBaseURL != "https://127.0.0.1:18088" ||
		parsed.BindIPv4 != "127.0.0.1" || parsed.BindPort != 15061 ||
		parsed.ErrorLogPath != "/var/log/vgw_error.log" {
		t.Fatal("private BYOK runtime overrides not parsed")
	}
	for _, bad := range []string{
		strings.Replace(augmented, "https://127.0.0.1:18088", "https://192.0.2.1:18088", 1),
		strings.Replace(augmented, "https://127.0.0.1:18088", "https://user:pass@127.0.0.1:18088", 1),
		strings.Replace(augmented, "SIP_BIND_PORT=15061", "SIP_BIND_PORT=015061", 1),
		strings.Replace(augmented, "ERROR_LOG_PATH=/var/log/vgw_error.log", "ERROR_LOG_PATH=../../escape", 1),
		augmented + "ARI_BASE_URL=https://127.0.0.1:18088\n",
	} {
		if _, err := ParseBYOK([]byte(bad)); err == nil {
			t.Fatal("unsafe ARI, bind or log selector accepted")
		}
	}
	service := fixture + "ARI_BASE_URL=https://127.0.0.1:18088\nSIP_BIND_PORT=15061\n"
	parsedService, err := Parse([]byte(service))
	if err != nil || parsedService.ARIBaseURL != "https://127.0.0.1:18088" || parsedService.BindPort != 15061 {
		t.Fatal("service config did not produce ARI/bind settings")
	}
}

func TestOwnedPIDAndLogFilesRejectStaleOrUntrustedInput(t *testing.T) {
	base := privateRoot(t)
	runtime := filepath.Join(base, "runtime")
	if os.Mkdir(runtime, 0700) != nil {
		t.Fatal("runtime test directory unavailable")
	}
	r := DefaultRuntimeOptions()
	r.RuntimeDir, r.PIDFileName = runtime, "vgw.pid"
	remove, err := OpenPIDFile(r)
	if err != nil {
		t.Fatal("owner-only PID file refused")
	}
	raw, err := os.ReadFile(r.PIDPath())
	if err != nil || strings.TrimSpace(string(raw)) != strconv.Itoa(os.Getpid()) {
		t.Fatal("PID file does not describe kernel-assigned process")
	}
	if _, err := OpenPIDFile(r); err == nil {
		t.Fatal("stale PID file was overwritten")
	}
	if remove() != nil {
		t.Fatal("exact owned PID file could not be released")
	}
	logPath := filepath.Join(runtime, "vgw_error.log")
	log, err := OpenErrorLog(logPath, r.UID, r.GID)
	if err != nil || WriteLogCategory(log, "VGW_READY") != nil {
		t.Fatal("rootless fixed-category log unavailable")
	}
	if WriteLogCategory(log, "Password: synthetic\r\nX-Audit: forged") == nil {
		t.Fatal("untrusted log/audit input accepted")
	}
	_ = log.Close()
	content, err := os.ReadFile(logPath)
	if err != nil || !strings.Contains(string(content), "VGW_READY") || strings.Contains(string(content), "Password") {
		t.Fatal("fixed-category log leaked untrusted text")
	}
	if os.Chmod(logPath, 0644) != nil {
		t.Fatal("log mode test unavailable")
	}
	if _, err := OpenErrorLog(logPath, r.UID, r.GID); err == nil {
		t.Fatal("broad error log inode accepted")
	}
}
