package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const demoFixture = "Server/Registrar: hg.eventphone.de\nAuthUser: synthetic\nPassword: only-for-tests\n"

func TestDevelopmentCredentialShapeRejectsInjectedOrRedirectedFields(t *testing.T) {
	good, err := parseDevCredentials([]byte(demoFixture))
	if err != nil || good.user != "synthetic" || good.password != "only-for-tests" {
		t.Fatal("synthetic private account shape refused")
	}
	if strings.Contains(fmt.Sprint(good), "only-for-tests") ||
		strings.Contains(fmt.Sprintf("%#v", good), "only-for-tests") {
		t.Fatal("credential formatted without redaction")
	}
	for _, bad := range []string{
		strings.ReplaceAll(demoFixture, "hg.eventphone.de", "other.invalid"),
		strings.ReplaceAll(demoFixture, "synthetic", "xx\r\nAuthorization: injected"),
		strings.ReplaceAll(demoFixture, "Password:", "Unknown:"),
		strings.ReplaceAll(demoFixture, "only-for-tests", "has space"),
		strings.ReplaceAll(demoFixture, "only-for-tests", "escape\x1b[31m"),
		demoFixture + "Password: extra\n",
		demoFixture + "\n",
	} {
		_, err := parseDevCredentials([]byte(bad))
		if err == nil || strings.Contains(err.Error(), "only-for-tests") {
			t.Fatal("injected or redirected provider account accepted/leaked")
		}
	}
}

func TestDevelopmentCredentialRequiresOwnerOnlyRegularFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test-account")
	if err := os.WriteFile(path, []byte(demoFixture), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readDevCredentials(path); err != nil {
		t.Fatal("owner-only synthetic file refused")
	}
	link := path + "-link"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readDevCredentials(link); err == nil {
		t.Fatal("symlink accepted as private test credential")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readDevCredentials(path); err == nil {
		t.Fatal("group/world-readable test credential accepted")
	}
}

func TestDevelopmentOneUseStageCannotReplay(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(parent, "register-once")
	if err := reserveTestRegister(dir); err != nil {
		t.Fatal(err)
	}
	if err := reserveTestRegister(dir); err == nil {
		t.Fatal("second registration would reuse first attempt stage")
	}
	if err := privateJSON(dir, "result.json", struct {
		Category string `json:"category"`
	}{"register-unconfirmed"}); err != nil {
		t.Fatal(err)
	}
	if err := privateJSON(dir, "result.json", struct {
		Category string `json:"category"`
	}{"registered-and-unregistered"}); err == nil {
		t.Fatal("ambiguous result could be overwritten with success")
	}
	if err := run([]string{"--test-register-once", "--serve"}, io.Discard); err == nil {
		t.Fatal("conflicting live provider actions accepted")
	}
}
