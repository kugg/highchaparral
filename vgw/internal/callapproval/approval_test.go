package callapproval

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var testKey = []byte("synthetic-one-use-approval-key")

func approvedDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "attempts")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestReserveCommitIsDurableOneUse(t *testing.T) {
	dir := approvedDir(t)
	const number = "123456"
	path, err := Reserve(dir, "first-call-01", number, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Reserve(dir, "first-call-01", number, testKey); err == nil {
		t.Fatal("attempt ID unexpectedly reused")
	}
	stage, err := Read(path)
	if err != nil || !matchTarget(stage, number, testKey) || matchTarget(stage, "123457", testKey) ||
		matchTarget(stage, "123456\r\nVia: injected", testKey) {
		t.Fatal("approved numeric target guard failed")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(contents, []byte(number)) || bytes.Contains(contents, testKey) {
		t.Fatal("stage contains sensitive input")
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("stage file permissions are not private")
	}
	if err := Commit(path, "123457", testKey); err == nil {
		t.Fatal("different target committed")
	}
	if _, err := os.Lstat(path + ".spent"); !os.IsNotExist(err) {
		t.Fatal("wrong target burned the attempt")
	}
	if err := Commit(path, number, testKey); err != nil {
		t.Fatal(err)
	}
	if err := Commit(path, number, testKey); err == nil {
		t.Fatal("spent attempt reused")
	}
	info, err := os.Lstat(path + ".spent")
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() != 0 {
		t.Fatal("spent marker is missing, nonempty or exposed")
	}
}

func TestCommitConcurrentExactlyOnce(t *testing.T) {
	path, err := Reserve(approvedDir(t), "first-call-02", "224466", testKey)
	if err != nil {
		t.Fatal(err)
	}
	results := make(chan bool, 24)
	var wg sync.WaitGroup
	for range 24 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- Commit(path, "224466", testKey) == nil
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for success := range results {
		if success {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("want one committed attempt, got %d", successes)
	}
}

func TestCommitRefusesExpiredOrFutureApproval(t *testing.T) {
	dir := approvedDir(t)
	for _, created := range []time.Time{time.Now().Add(-30 * time.Minute), time.Now().Add(time.Hour)} {
		id := "first-call-04"
		if created.After(time.Now()) {
			id = "first-call-05"
		}
		path, err := Reserve(dir, id, "224466", testKey)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var stage Stage
		if err := json.Unmarshal(data, &stage); err != nil {
			t.Fatal(err)
		}
		stage.CreatedUTC = created.UTC().Format(time.RFC3339)
		changed, err := json.Marshal(stage)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, changed, 0600); err != nil {
			t.Fatal(err)
		}
		if err := Commit(path, "224466", testKey); err == nil {
			t.Fatal("committed approval outside attended window")
		}
		if _, err := os.Lstat(path + ".spent"); !os.IsNotExist(err) {
			t.Fatal("invalid approval burned the attempt")
		}
	}
}

func TestReadRefusesMalformedAndInjectedStages(t *testing.T) {
	dir := approvedDir(t)
	path, err := Reserve(dir, "first-call-03", "224466", testKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{"", ".", dir, filepath.Join(dir, "x"), filepath.Join(dir, "attempt-.json"),
		filepath.Join(dir, "attempt-first-call-03.json.backup")} {
		if _, err := Read(invalid); err == nil {
			t.Fatalf("accepted malformed path: %q", invalid)
		}
	}
	base, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var stage Stage
	if err := json.Unmarshal(base, &stage); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(string) string{
		"trailing-object": func(s string) string { return s + "{}" },
		"duplicate-state": func(s string) string {
			return strings.Replace(s, `"state":`, `"state":"used","state":`, 1)
		},
		"unknown-field": func(s string) string { return strings.Replace(s, `"schema":`, `"extra":"x","schema":`, 1) },
		"control-in-created": func(s string) string {
			return strings.Replace(s, stage.CreatedUTC, `bad\nlog`, 1)
		},
		"wrong-state": func(s string) string {
			return strings.Replace(s, "reserved-before-network", "sent", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(mutate(string(base))), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Read(path); err == nil {
				t.Fatal("accepted malformed approval stage")
			}
		})
	}
	if err := os.WriteFile(path, base, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err == nil {
		t.Fatal("accepted broad file mode")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(dir, "attempt-second-link-01.json")
	if err := os.Link(path, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err == nil {
		t.Fatal("accepted hard-linked stage")
	}
	if err := os.Remove(linked); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(linked); err == nil {
		t.Fatal("accepted symlink stage")
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err == nil {
		t.Fatal("accepted broad directory mode")
	}
}
