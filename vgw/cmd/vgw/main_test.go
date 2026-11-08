package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDefaultDryRunAndBadArgumentsDoNotEchoCredentials(t *testing.T) {
	var stdout bytes.Buffer
	if err := run(nil, &stdout); err != nil || !strings.Contains(stdout.String(), "DRY RUN") {
		t.Fatal("default vgw command should not read config or open network")
	}
	stdout.Reset()
	for _, args := range [][]string{
		{"--password=synthetic-secret-only"},
		{"--serve", "--check-config"},
		{"--serve", "--serve-byok"},
		{"--check-config", "--serve-byok"},
		{"--serve", "unexpected"},
	} {
		err := run(args, &stdout)
		if err == nil || strings.Contains(err.Error(), "synthetic-secret-only") || stdout.Len() != 0 {
			t.Fatal("untrusted argv accepted or secret echoed")
		}
	}
}

func TestCheckConfigFromRootlessPrivatePathWithoutEtcOrProvider(t *testing.T) {
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(directory, 0700) != nil {
		t.Fatal("synthetic rootless config directory unavailable")
	}
	path := filepath.Join(directory, "vgw.config")
	logPath := filepath.Join(directory, "vgw_error.log")
	content := "ARI_USER=synthetic\nARI_PASSWORD=synthetic_secure_ari_password\n" +
		"UPSTREAM_HOST=sip.provider.test\nUPSTREAM_PORT=15061\n" +
		"UPSTREAM_TLS_NAME=sip.provider.test\nUPSTREAM_USERNAME=synthetic\n" +
		"UPSTREAM_PASSWORD=unit-only\nUPSTREAM_CERT_SHA256=ca-only\n" +
		"ARI_BASE_URL=http://127.0.0.1:18088\nSIP_BIND_IPV4=127.0.0.1\nSIP_BIND_PORT=15062\n" +
		"ERROR_LOG_PATH=" + logPath + "\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil || os.Chmod(path, 0600) != nil {
		t.Fatal("synthetic rootless config unavailable")
	}
	args := []string{"--check-config", "--config=" + path,
		"--run-uid=" + strconv.Itoa(os.Geteuid()), "--run-gid=" + strconv.Itoa(os.Getegid())}
	var out bytes.Buffer
	if err := run(args, &out); err != nil || !strings.Contains(out.String(), "syntax PASS") {
		t.Fatal("local config check required /etc or refused reviewed rootless options")
	}
	if _, err := os.Lstat(logPath); !os.IsNotExist(err) {
		t.Fatal("offline config check opened a log or listener")
	}
	out.Reset()
	if err := run(append(args, "--run-uid=0001"), &out); err == nil || out.Len() != 0 {
		t.Fatal("ambiguous runtime identity accepted or reflected")
	}
	link := filepath.Join(directory, "config-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"--check-config", "--config=" + link}, &out); err == nil || out.Len() != 0 {
		t.Fatal("rootless config symlink accepted or reflected")
	}
}

func TestBYOKServiceRefusesWrongIdentityBeforeOpeningAnySocket(t *testing.T) {
	var stdout bytes.Buffer
	if err := run([]string{"--serve-byok"}, &stdout); err == nil || stdout.Len() != 0 {
		t.Fatal("unowned BYOK service started without a vgw user, owned dirs and private config")
	}
}

func TestSourceAddressProbeNeverNeedsProviderConnection(t *testing.T) {
	selected, err := onlySourceAddress(context.Background(), "127.0.0.1", 5061)
	if err != nil || selected != "127.0.0.1" {
		t.Fatal("source address probe failed for synthetic local provider")
	}
	if _, err := onlySourceAddress(context.Background(), "%%invalid", 5061); err == nil {
		t.Fatal("malformed provider name accepted")
	}
}
