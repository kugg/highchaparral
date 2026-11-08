package security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
)

// This verifier closes OPLANE_REQ-00005006 (digest integrity),
// OPLANE_REQ-00005008 (claim/code drift) and the registry-consistency
// portion of OPLANE_REQ-00005007. It recomputes every stored digest from
// the files on disk and fails on any mismatch, malformed/missing digest,
// binding-set drift, or unreachable git ref.

type claimRef struct {
	Path      string   `json:"path"`
	Resources []string `json:"resources"`
}

type registry struct {
	SchemaVersion int        `json:"schema_version"`
	Claims        []claimRef `json:"claims"`
}

type obligation struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	Predicate string   `json:"predicate"`
	Checks    []string `json:"checks"`
}

type claim struct {
	SchemaVersion  int                    `json:"schema_version"`
	ID             string                 `json:"id"`
	Version        int                    `json:"version"`
	Owner          string                 `json:"owner"`
	Property       string                 `json:"property"`
	Obligations    []obligation           `json:"obligations"`
	Bindings       []string               `json:"bindings"`
	BindingDigests map[string]string      `json:"binding_digests"`
	CheckSpecs     string                 `json:"check_specs_sha256"`
	Formal         formal                 `json:"formal"`
	Evaluator      string                 `json:"evaluator_manifest_sha256"`
	Verification   verification           `json:"verification"`
}

type formal struct {
	Required     bool   `json:"required"`
	ProfileSHA   string `json:"profile_sha256"`
	SourceSHA    string `json:"source_sha256"`
	Scope        string `json:"scope"`
}

type verification struct {
	OplaneThreatModel string   `json:"oplane_threat_model"`
	OplaneRequest     string   `json:"oplane_requirement"`
	Verdict           string   `json:"verdict"`
	GitRef            string   `json:"git_ref"`
	Evidence          []string `json:"evidence"`
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test file")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
}

func readRepo(t *testing.T, root, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return b
}

func digest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func validHex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// sourceDigest reproduces the generator derivation: for each bound file in
// sorted order, hash "<path>\x00<content>\x00".
func sourceDigest(root string, files []string) (string, error) {
	h := sha256.New()
	sorted := append([]string(nil), files...)
	sort.Strings(sorted)
	for _, f := range sorted {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f)))
		if err != nil {
			return "", err
		}
		h.Write([]byte(f))
		h.Write([]byte{0})
		h.Write(b)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func loadRegistry(t *testing.T, root string) registry {
	t.Helper()
	var r registry
	if err := json.Unmarshal(readRepo(t, root, "vgw/security/claim-registry.json"), &r); err != nil {
		t.Fatalf("parse claim-registry.json: %v", err)
	}
	return r
}

func loadClaim(t *testing.T, root, path string) claim {
	t.Helper()
	var c claim
	if err := json.Unmarshal(readRepo(t, root, path), &c); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return c
}

func TestSecurityClaimDigestIntegrity(t *testing.T) {
	root := repoRoot(t)
	reg := loadRegistry(t, root)
	if len(reg.Claims) == 0 {
		t.Fatal("registry lists no claims")
	}
	evManifest := readRepo(t, root, "vgw/security/evaluator-requirements.json")
	evDigest := digest(evManifest)

	for _, ref := range reg.Claims {
		c := loadClaim(t, root, ref.Path)
		t.Run(c.ID, func(t *testing.T) {
			// 5006 case 6: required digest fields present and well-formed.
			for name, v := range map[string]string{
				"check_specs_sha256":         c.CheckSpecs,
				"formal.source_sha256":       c.Formal.SourceSHA,
				"evaluator_manifest_sha256":  c.Evaluator,
			} {
				if !validHex(v) {
					t.Errorf("%s: %s is not a 64-hex digest: %q", c.ID, name, v)
				}
			}
			// 5006 case 1: recompute check_specs over the feature resource.
			if len(ref.Resources) == 0 {
				t.Fatalf("%s: no resources", c.ID)
			}
			feature := readRepo(t, root, ref.Resources[0])
			if got := digest(feature); got != c.CheckSpecs {
				t.Errorf("%s: check_specs_sha256 mismatch (stored %s, recomputed %s over %s)", c.ID, c.CheckSpecs, got, ref.Resources[0])
			}
			// 5006 case 3: evaluator manifest digest matches the shared file.
			if c.Evaluator != evDigest {
				t.Errorf("%s: evaluator_manifest_sha256 mismatch (stored %s, file %s)", c.ID, c.Evaluator, evDigest)
			}
			// 5008 case 1: aggregate source digest matches bound files.
			sd, err := sourceDigest(root, c.Bindings)
			if err != nil {
				t.Fatalf("%s: %v", c.ID, err)
			}
			if sd != c.Formal.SourceSHA {
				t.Errorf("%s: source_sha256 mismatch (stored %s, recomputed %s)", c.ID, c.Formal.SourceSHA, sd)
			}
		})
	}
}

func TestSecurityClaimBindingDrift(t *testing.T) {
	root := repoRoot(t)
	reg := loadRegistry(t, root)
	for _, ref := range reg.Claims {
		c := loadClaim(t, root, ref.Path)
		t.Run(c.ID, func(t *testing.T) {
			// 5008 case 4: binding set == binding_digests key set.
			if len(c.Bindings) != len(c.BindingDigests) {
				t.Errorf("%s: bindings (%d) and binding_digests (%d) differ in size", c.ID, len(c.Bindings), len(c.BindingDigests))
			}
			for _, f := range c.Bindings {
				want, ok := c.BindingDigests[f]
				if !ok {
					t.Errorf("%s: binding %s has no recorded digest", c.ID, f)
					continue
				}
				if !validHex(want) {
					t.Errorf("%s: binding %s digest malformed: %q", c.ID, f, want)
					continue
				}
				// 5008 case 2: per-file content matches the recorded digest.
				b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f)))
				if err != nil {
					t.Errorf("%s: bound file unreadable %s: %v", c.ID, f, err)
					continue
				}
				if got := digest(b); got != want {
					t.Errorf("%s: DRIFT in %s (recorded %s, current %s)", c.ID, f, want, got)
				}
			}
			for f := range c.BindingDigests {
				if !contains(c.Bindings, f) {
					t.Errorf("%s: binding_digests has %s not present in bindings", c.ID, f)
				}
			}
		})
	}
}

func TestSecurityClaimRegistryConsistency(t *testing.T) {
	root := repoRoot(t)
	reg := loadRegistry(t, root)
	seen := map[string]bool{}
	for _, ref := range reg.Claims {
		if seen[ref.Path] {
			t.Errorf("duplicate claim path in registry: %s", ref.Path)
		}
		seen[ref.Path] = true
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(ref.Path))); err != nil {
			t.Errorf("registry lists missing claim file: %s", ref.Path)
		}
		for _, res := range ref.Resources {
			if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(res))); err != nil {
				t.Errorf("claim %s lists missing resource: %s", ref.Path, res)
			}
		}
	}
	// Every claim file on disk must be listed in the registry (no orphans).
	matches, _ := filepath.Glob(filepath.Join(root, "vgw/security/claims", "*.v1.json"))
	for _, m := range matches {
		rel, _ := filepath.Rel(root, m)
		if !seen[filepath.ToSlash(rel)] {
			t.Errorf("claim file on disk not listed in registry: %s", filepath.ToSlash(rel))
		}
	}
}

func TestSecurityClaimGitRefReachable(t *testing.T) {
	root := repoRoot(t)
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available; skipping commit-existence check")
	}
	reg := loadRegistry(t, root)
	for _, ref := range reg.Claims {
		c := loadClaim(t, root, ref.Path)
		t.Run(c.ID, func(t *testing.T) {
			if c.Verification.GitRef == "" {
				t.Errorf("%s: verification.git_ref empty", c.ID)
				return
			}
			cmd := exec.Command("git", "-C", root, "cat-file", "-e", c.Verification.GitRef+"^{commit}")
			if err := cmd.Run(); err != nil {
				var ee *exec.ExitError
				if errors.As(err, &ee) {
					t.Errorf("%s: git_ref %s not reachable in this checkout (exit %d); fetch full history (actions/checkout fetch-depth: 0)", c.ID, c.Verification.GitRef, ee.ExitCode())
				} else {
					t.Errorf("%s: git check failed: %v", c.ID, err)
				}
			}
		})
	}
}

func contains(s []string, x string) bool {
	for _, v := range s {
		if v == x {
			return true
		}
	}
	return false
}
