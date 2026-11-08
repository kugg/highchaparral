package main

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestOfficeCheckRootlessPrivateConfigWithoutProviderNetwork(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil || os.Chmod(dir, 0700) != nil {
		t.Fatal("synthetic office config directory unavailable")
	}
	path := filepath.Join(dir, "office-account.config")
	content := "Server/Registrar: pbx-epvpn-voip.eventphone.de\n" +
		"AuthUser: synthetic-only\nPassword: OnlyForUnitTests!\nExtension: 1234\n"
	if os.WriteFile(path, []byte(content), 0600) != nil || os.Chmod(path, 0600) != nil {
		t.Fatal("synthetic office config unavailable")
	}
	args := []string{"--config=" + path, "--no-network", "--office-port=15061",
		"--run-uid=" + strconv.Itoa(os.Geteuid()), "--run-gid=" + strconv.Itoa(os.Getegid())}
	if got := check(args); got != "OFFICE_GO_FORMAT_OWNER_POLICY_OK_NO_NETWORK" {
		t.Fatal("owner-only office check required /etc or contacted provider")
	}
	if got := check(append(args, "--office-port=65536")); got != "OFFICE_GO_IDENTITY_REFUSED" {
		t.Fatal("invalid office TLS port accepted")
	}
}
