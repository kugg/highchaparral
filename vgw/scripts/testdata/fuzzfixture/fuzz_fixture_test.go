package fuzzfixture

import "testing"

// FuzzEvidenceCapture is an opt-in contract fixture. Its fuzz function has one
// deliberate failure so the evidence pipeline can prove minimized-input
// capture rather than merely replaying an already committed failing seed.
// The package lives below testdata and is never selected by normal ./... runs.
func FuzzEvidenceCapture(f *testing.F) {
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 0 {
			t.Fatal("CONTROLLED_FUZZ_FIXTURE_FAILURE")
		}
	})
}
