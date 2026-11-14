package byok

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func line(action, nonce string, ts string) string {
	sum := sha256.Sum256([]byte(nonce))
	return action + " " + hex.EncodeToString(sum[:]) + " " + ts + "\n"
}

// FuzzJournalRecovery fuzzes serialized and partially written BYOK journal
// inputs against the recovery parser. Synthetic bytes only; no provider call,
// credential or production state. Invariants: corrupt input never panics;
// malformed or ambiguous durable state never opens for slot reuse; rejection
// never erases the bytes needed for manual reconciliation; recovery is
// deterministic and idempotent; errors stay bounded.
func FuzzJournalRecovery(f *testing.F) {
	n := strings.Repeat("a", 32)
	m := strings.Repeat("b", 32)
	f.Add([]byte(""))
	f.Add([]byte(line("begin", n, "1700000000") + line("end", n, "1700000001")))
	f.Add([]byte(line("begin", n, "1700000000")))
	f.Add([]byte(line("end", n, "1700000000")))
	f.Add([]byte(line("begin", n, "1700000000") + line("begin", m, "1700000001")))
	f.Add([]byte(line("begin", n, "1700000000") + line("end", m, "1700000001")))
	f.Add([]byte("begin " + strings.Repeat("z", 64) + " 1700000000\n"))
	f.Add([]byte("begin " + strings.Repeat("0", 64) + " 99999999999999\n"))
	f.Add([]byte(line("begin", n, "1700000000") + "\n" + line("end", n, "1700000001")))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > maxJournal+16 {
			t.Skip()
		}
		dir := t.TempDir()
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "calls.journal")
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		first, errFirst := OpenJournal(dir)
		if first != nil {
			_ = first.Close()
		}
		second, errSecond := OpenJournal(dir)
		if (errFirst == nil) != (errSecond == nil) {
			t.Fatal("recovery is not deterministic across opens")
		}
		if errFirst != nil {
			if errFirst.Error() != "BYOK reservation refused" {
				t.Fatal("journal rejection leaked an unbounded error category")
			}
			after, readErr := os.ReadFile(path)
			if readErr != nil || !bytes.Equal(after, raw) {
				t.Fatal("journal rejection erased evidence needed for recovery")
			}
			return
		}
		defer func() { _ = second.Close() }()
		nonce := strings.Repeat("c", 32)
		if err := second.Begin(nonce); err != nil {
			t.Fatal("a reconciled journal refused a first Begin")
		}
		if err := second.Begin(nonce); err == nil {
			t.Fatal("double begin permitted unsafe slot reuse")
		}
		if err := second.End(nonce); err != nil {
			t.Fatal("end failed on an open journal call")
		}
		if err := second.End(nonce); err == nil {
			t.Fatal("double end permitted")
		}
	})
}
