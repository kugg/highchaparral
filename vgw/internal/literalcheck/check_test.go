package literalcheck

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sourceFixture = `package sample
type owner struct { Uid uint32 }
func run(st owner) {
  if st.Uid == 7 {}
  const listenPort = 80
  _ = listenPort
  _ = "/etc/vgw-private/config"
  _ = "Password: NEVER-PRINT-THIS-SYNTHETIC-TEXT"
}`

func TestInventoryRedactsStringsAndPolicyRejectsAddedLiterals(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "sample.go")
	if err := os.WriteFile(file, []byte(sourceFixture), 0600); err != nil {
		t.Fatal(err)
	}
	literals, err := Scan(root)
	if err != nil {
		t.Fatal(err)
	}
	var listed bytes.Buffer
	if Report(&listed, literals, false) != nil ||
		strings.Contains(listed.String(), "NEVER-PRINT-THIS-SYNTHETIC-TEXT") ||
		!strings.Contains(listed.String(), "number=7") || !strings.Contains(listed.String(), "number=80") {
		t.Fatal("literal inventory leaked a string or missed numeric identity/port")
	}
	group := Groups(literals)["sample.go"]
	policy := Policy{Version: 1, Allow: []Rule{{File: "sample.go", SHA256: group.SHA256,
		Count: group.Count, Classification: "default", Reason: "reviewed fixture default"}}}
	if group.Count != 3 || Check(literals, policy) != nil {
		t.Fatal("reviewed literal policy did not accept exactly three inputs")
	}
	if err := os.WriteFile(file, []byte(sourceFixture+"\nconst logPath = \"/var/log/new-vgw.log\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	changed, err := Scan(root)
	if err != nil || Check(changed, policy) == nil {
		t.Fatal("new unreviewed logfile literal did not break CI policy")
	}
	policy.Allow = nil
	if Check(literals, policy) == nil {
		t.Fatal("missing reviewed rule was ignored")
	}
}

func TestPolicyRejectsSymlinkAndTrailingJSON(t *testing.T) {
	root := t.TempDir()
	policy := filepath.Join(root, "review.json")
	good, err := json.Marshal(Policy{Version: 1, Allow: []Rule{}})
	if err != nil || os.WriteFile(policy, good, 0600) != nil {
		t.Fatal("synthetic policy unavailable")
	}
	if _, err := ReadPolicy(policy); err != nil {
		t.Fatal("clean policy refused")
	}
	link := filepath.Join(root, "symlink.json")
	if err := os.Symlink(policy, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPolicy(link); err == nil {
		t.Fatal("symlink policy accepted")
	}
	if err := os.WriteFile(policy, append(good, []byte(`{"version":2}`)...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPolicy(policy); err == nil {
		t.Fatal("trailing JSON policy accepted")
	}
}

func TestDockerUserAndExposureDriftCannotBypassPolicy(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "Dockerfile.noll")
	if os.WriteFile(path, []byte("FROM scratch\nUSER nobody\n"), 0600) != nil {
		t.Fatal("synthetic Dockerfile unavailable")
	}
	baseline, err := Scan(root)
	if err != nil {
		t.Fatal("synthetic image identity unavailable")
	}
	group := Groups(baseline)["Dockerfile.noll"]
	policy := Policy{Version: 1, Allow: []Rule{{File: "Dockerfile.noll", Count: 1,
		SHA256: group.SHA256, Classification: "default", Reason: "reviewed unprivileged image user"}}}
	if Check(baseline, policy) != nil {
		t.Fatal("reviewed nonroot Docker identity refused")
	}
	if os.WriteFile(path, []byte("FROM scratch\nUSER 34567\nEXPOSE 5060\n"), 0600) != nil {
		t.Fatal("synthetic changed Dockerfile unavailable")
	}
	changed, err := Scan(root)
	if err != nil || Check(changed, policy) == nil {
		t.Fatal("changed image UID or published SIP port bypassed CI")
	}
}

func TestCurrentModuleMatchesReviewedDeploymentLiteralPolicy(t *testing.T) {
	root := filepath.Join("..", "..")
	literals, err := Scan(root)
	if err != nil {
		t.Fatal("module literal inventory unavailable")
	}
	policy, err := ReadPolicy(filepath.Join(root, "docs", "runtime-literals-policy.json"))
	if err != nil || Check(literals, policy) != nil {
		t.Fatal("new or stale deployment literal; inspect redacted operational inventory")
	}
}
