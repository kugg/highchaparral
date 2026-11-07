package serviceconfig

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const fixture = "ARI_USER=gateway_lab\nARI_PASSWORD=synthetic_secure_ari_password\n" +
	"UPSTREAM_HOST=sip.provider.test\nUPSTREAM_PORT=5071\n" +
	"UPSTREAM_TLS_NAME=edge.provider.test\nUPSTREAM_USERNAME=synthetic_lab\n" +
	"UPSTREAM_PASSWORD=sample=synthetic:only!\n" +
	"UPSTREAM_CERT_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"

func TestSixFieldServiceNamedConfigRejectsInputInjection(t *testing.T) {
	if Path != "/etc/voip-gateway/config" || Directory != "/etc/voip-gateway" ||
		ServiceName != "voip-gateway" || ShortName != "vgw" || GroupName != "vgw" {
		t.Fatal("gateway config pathname does not name its service")
	}
	c, err := Parse([]byte(fixture))
	if err != nil || c.ARIUser != "gateway_lab" || c.UpstreamHost != "sip.provider.test" ||
		c.UpstreamPort != 5071 || c.UpstreamTLSName != "edge.provider.test" ||
		c.UpstreamPassword != "sample=synthetic:only!" || c.CertSHA256[0] != 0xaa {
		t.Fatal("synthetic service config rejected or changed")
	}
	caOnly := strings.Replace(fixture, strings.Repeat("a", 64), "ca-only", 1)
	approved, err := Parse([]byte(caOnly))
	if err != nil || !approved.CAOnly || approved.CertSHA256 != [32]byte{} {
		t.Fatal("explicit CA-only upstream TLS config rejected")
	}
	withIssuedShortPassword := strings.Replace(caOnly, "sample=synthetic:only!", "short-test", 1)
	if _, err := Parse([]byte(withIssuedShortPassword)); err != nil {
		t.Fatal("printable provider-issued short password refused")
	}
	var log bytes.Buffer
	slog.New(slog.NewTextHandler(&log, nil)).Info("config", "config", c)
	for _, rendered := range []string{fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c),
		fmt.Sprintf("%#v", c), log.String()} {
		if strings.Contains(rendered, "synthetic_secure_ari_password") ||
			strings.Contains(rendered, "sample=synthetic:only!") {
			t.Fatal("synthetic credential rendered into log")
		}
	}
	if data, err := json.Marshal(c); err == nil || len(data) != 0 ||
		strings.Contains(err.Error(), "synthetic_secure_ari_password") {
		t.Fatal("private service configuration serialized into JSON")
	}
	for _, bad := range []string{
		strings.Replace(fixture, "sip.provider.test", "evil.invalid/path", 1),
		strings.Replace(fixture, "UPSTREAM_PORT=5071", "UPSTREAM_PORT=0", 1),
		strings.Replace(fixture, "UPSTREAM_PORT=5071", "UPSTREAM_PORT=65536", 1),
		strings.Replace(fixture, "UPSTREAM_PORT=5071", "UPSTREAM_PORT=05071", 1),
		strings.Replace(fixture, "edge.provider.test", "bad..provider.test", 1),
		strings.Replace(fixture, "UPSTREAM_USERNAME=synthetic_lab", "UPSTREAM_USERNAME=user@domain", 1),
		strings.Replace(fixture, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", strings.Repeat("A", 64), 1),
		strings.Replace(fixture, "ARI_USER=", "WRONG_USER=", 1),
		fixture + "UPSTREAM_PASSWORD=duplicate\n",
		strings.Replace(fixture, "UPSTREAM_USERNAME=synthetic_lab", "UPSTREAM_USERNAME=synthetic\r\nInjected=true", 1),
		strings.Replace(fixture, "sample=synthetic:only!", "bad password with spaces", 1),
		strings.Replace(fixture, strings.Repeat("a", 64), "none", 1),
		strings.Replace(fixture, strings.Repeat("a", 64), "", 1),
		strings.Replace(fixture, "sample=synthetic:only!", "synthetic\nUPSTREAM_HOST=evil.invalid", 1),
		strings.TrimSuffix(fixture, "\n"),
		fixture + strings.Repeat("x", 4096),
	} {
		if _, err := Parse([]byte(bad)); err == nil || strings.Contains(err.Error(), "synthetic_secure_ari_password") {
			t.Fatal("malformed/untrusted config accepted or secret reflected")
		}
	}
}

func TestDirectoryAndFileOwnershipPredicatesRejectLinks(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "voip-gateway")
	if err := os.Mkdir(dir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0750); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte(fixture), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	// The production Read function requires uid=0/gid=450. Tests model
	// that predicate with the test process' actual ids; no chown needed.
	uid, gid := uint32(os.Getuid()), uint32(os.Getgid())
	details, err := os.Lstat(dir)
	if err != nil || !owned(details, uid, gid, 0750, false) {
		t.Fatal("synthetic owner-only service directory rejected")
	}
	details, err = os.Lstat(path)
	if err != nil || !owned(details, uid, gid, 0640, true) {
		t.Fatal("synthetic owner-only service config rejected")
	}
	if owned(details, uid, gid, 0660, true) || owned(details, uid, gid+1, 0640, true) {
		t.Fatal("changed group or writable config accepted")
	}
	link := filepath.Join(dir, "config-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	linked, err := os.Lstat(link)
	if err != nil || owned(linked, uid, gid, 0640, true) {
		t.Fatal("symlink accepted for private service file")
	}
	second := filepath.Join(dir, "config-hardlink")
	if err := os.Link(path, second); err != nil {
		t.Fatal(err)
	}
	hardlinked, err := os.Lstat(path)
	if err != nil || owned(hardlinked, uid, gid, 0640, true) {
		t.Fatal("hardlinked credential accepted")
	}
	if _, ok := hardlinked.Sys().(*syscall.Stat_t); !ok {
		t.Fatal("production ownership check cannot inspect inode metadata")
	}
}

func TestTwinAnsibleTemplateRendersTheProductionParserContract(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "..", "deploy", "ansible",
		"templates", "voip-gateway.config.j2")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("service-named Ansible template unavailable")
	}
	text := string(data)
	for key, value := range map[string]string{
		"vgw_ari_user":             "gateway_lab",
		"vgw_ari_password":         "synthetic_secure_ari_password",
		"vgw_upstream_host":        "sip.provider.test",
		"vgw_upstream_port":        "5071",
		"vgw_upstream_tls_name":    "edge.provider.test",
		"vgw_upstream_username":    "synthetic_lab",
		"vgw_upstream_password":    "sample=synthetic:only!",
		"vgw_upstream_cert_sha256": strings.Repeat("a", 64),
	} {
		text = strings.ReplaceAll(text, "{{ "+key+" }}", value)
	}
	if strings.Contains(text, "{{") {
		t.Fatal("unexpected template input variable")
	}
	parsed, err := Parse([]byte(text))
	if err != nil || parsed.UpstreamHost != "sip.provider.test" || parsed.UpstreamPort != 5071 ||
		parsed.UpstreamTLSName != "edge.provider.test" || parsed.CertSHA256[0] != 0xaa {
		t.Fatal("rendered Ansible config does not match strict gateway schema")
	}
}
