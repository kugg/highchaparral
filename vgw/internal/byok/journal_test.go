package byok

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testNonce = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestJournalRetainsOneAttemptAndBlocksInterruptedPowerLoss(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	j, err := OpenJournal(dir)
	if err != nil {
		t.Fatal("private journal failed to initialize")
	}
	if _, err := OpenJournal(dir); err == nil {
		t.Fatal("second gateway acquired the same journal")
	}
	if err := j.Begin(testNonce); err != nil {
		t.Fatal("one call was not durably reserved")
	}
	if err := j.Begin(strings.Repeat("b", 32)); err == nil {
		t.Fatal("concurrent call reservation accepted")
	}
	if err := j.End(strings.Repeat("b", 32)); err == nil {
		t.Fatal("wrong call ended an owned attempt")
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(dir); err == nil {
		t.Fatal("interrupted call journal was silently replayed")
	}
	content, err := os.ReadFile(filepath.Join(dir, "calls.journal"))
	if err != nil || strings.Contains(string(content), testNonce) || strings.Contains(string(content), "password") {
		t.Fatal("journal leaked untrusted call or credential data")
	}
}

func TestSettledJournalReopensAndNeverStoresTargetOrPassword(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	j, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Begin(testNonce); err != nil {
		t.Fatal(err)
	}
	if err := j.End(testNonce); err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	opened, err := OpenJournal(dir)
	if err != nil {
		t.Fatal("settled call blocked all future reviewed calls")
	}
	defer opened.Close()
	data, err := os.ReadFile(filepath.Join(dir, "calls.journal"))
	if err != nil || strings.Count(string(data), "begin ") != 1 ||
		strings.Count(string(data), "end ") != 1 || strings.Contains(string(data), testNonce) {
		t.Fatal("owned journal was overwritten or stored a raw caller token")
	}
	if err := opened.Begin(strings.Repeat("b", 32)); err != nil {
		t.Fatal("fresh nonce refused after settled call")
	}
}

func TestJournalRejectsForeignModeAndInvalidNonceBeforeWrites(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(dir); err == nil {
		t.Fatal("world-readable call journal parent accepted")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	j, err := OpenJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	if err := j.Begin("../bad"); err == nil {
		t.Fatal("injected nonce entered journal")
	}
	data, err := os.ReadFile(filepath.Join(dir, "calls.journal"))
	if err != nil || len(data) != 0 {
		t.Fatal("invalid nonce modified the journal")
	}
}
