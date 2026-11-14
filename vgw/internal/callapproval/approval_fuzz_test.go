package callapproval

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fuzzAttemptID = "seedattempt0"

func fuzzStagePath(t *testing.T, contents []byte) string {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "attempt-"+fuzzAttemptID+".json")
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// FuzzApprovalStageRead fuzzes one-use call-approval stage records:
// malformed encodings, duplicate fields, invalid state combinations,
// extreme timestamps, incomplete writes and boundary-sized content.
// Invariants: parsing fails closed; duplicate or contradictory security
// fields are rejected; no invalid record authorizes a call; rejection is
// deterministic; raw secrets or destinations are never reflected.
func FuzzApprovalStageRead(f *testing.F) {
	valid := `{"schema":1,"state":"reserved-before-network","attempt_id":"` + fuzzAttemptID +
		`","target_hmac_sha256":"` + strings.Repeat("a", 64) +
		`","created_utc":"2026-11-14T12:00:00Z"}`
	f.Add([]byte(valid))
	f.Add([]byte(strings.Replace(valid, `"schema":1`, `"schema":2`, 1)))
	f.Add([]byte(strings.Replace(valid, `"reserved-before-network"`, `"committed"`, 1)))
	f.Add([]byte(`{"schema":1,"schema":1,"state":"reserved-before-network","attempt_id":"` + fuzzAttemptID +
		`","target_hmac_sha256":"` + strings.Repeat("a", 64) + `","created_utc":"2026-11-14T12:00:00Z"}`))
	f.Add([]byte(strings.Replace(valid, strings.Repeat("a", 64), strings.Repeat("z", 64), 1)))
	f.Add([]byte(strings.Replace(valid, "2026-11-14T12:00:00Z", "not-a-time", 1)))
	f.Add([]byte(`{"schema":1`))
	f.Add([]byte(valid + `{"extra":true}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 2048 {
			t.Skip()
		}
		path := fuzzStagePath(t, raw)
		stage, err := Read(path)
		again, errAgain := Read(path)
		if (err == nil) != (errAgain == nil) || (err == nil && stage != again) {
			t.Fatal("approval stage parsing is not deterministic")
		}
		if err != nil {
			if err.Error() != "vgw one-use approved call stage invalid" {
				t.Fatal("approval parser leaked an unreviewed error category")
			}
			return
		}
		if stage.Schema != 1 || stage.State != "reserved-before-network" ||
			!hexPattern.MatchString(stage.TargetHMAC) || stage.AttemptID != fuzzAttemptID {
			t.Fatal("approval parser accepted a record that fails its own contract")
		}
		if err := Commit(path, "555", []byte(strings.Repeat("k", 32))); err == nil {
			t.Fatal("a fuzzed stage record authorized a call with a non-matching key")
		}
	})
}
