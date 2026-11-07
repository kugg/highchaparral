package byok

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMilestonesAreOneUseFixedCategoryAndPrivate(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	m, err := OpenMilestones(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenMilestones(dir); err == nil {
		t.Fatal("a second process reused the one-use milestone file")
	}
	if m.Mark(AdmissionReady) != nil || m.Mark(ByeOK) != nil {
		t.Fatal("fixed call milestones were not durable")
	}
	if m.Mark(Milestone("bye-ok\nX-Password: forged")) == nil {
		t.Fatal("untrusted data entered a fixed-category record")
	}
	if m.Close() != nil {
		t.Fatal("owned milestone fd was not closed")
	}
	file := filepath.Join(dir, "call-milestones-v1")
	info, err := os.Lstat(file)
	if err != nil || info.Mode().Perm() != 0600 || info.Sys() == nil {
		t.Fatal("milestone permissions changed")
	}
	data, err := os.ReadFile(file)
	if err != nil || strings.Count(string(data), "\n") != 2 ||
		strings.Contains(string(data), "forged") || strings.Contains(string(data), "Password") {
		t.Fatal("milestone leaked caller input or omitted fixed markers")
	}
}

func TestMilestonesRefuseUnsafeDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenMilestones(dir); err == nil {
		t.Fatal("public milestone directory accepted")
	}
}
