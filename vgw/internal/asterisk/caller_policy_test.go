package asterisk

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// This inventory fence complements behavioral TLS checks. Adding a caller
// requires an explicit inventory update and provisioned trust, never a lab bypass.
func TestAllARICallersProvideExplicitPeerIdentity(t *testing.T) {
	expected := map[string]int{"cmd/vgw/byok.go": 1, "cmd/ari-browser-probe/main.go": 1, "cmd/ari-probe/main.go": 1, "cmd/ari-media-probe/main.go": 1, "cmd/local-ari-lab/main.go": 1}
	root := filepath.Join("..", "..")
	seen := map[string]int{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		aliases := map[string]bool{}
		for _, i := range f.Imports {
			p, _ := strconv.Unquote(i.Path.Value)
			if p == "example.com/ata/voip-gateway/internal/asterisk" {
				name := "asterisk"
				if i.Name != nil {
					name = i.Name.Name
				}
				if name == "." {
					t.Error("dot ARI import bypasses caller inventory")
				}
				aliases[name] = true
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			s, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := s.X.(*ast.Ident)
			if !ok || !aliases[id.Name] {
				return true
			}
			if s.Sel.Name == "NewLoopbackLab" {
				t.Error("plaintext lab exception is forbidden")
			}
			if s.Sel.Name != "New" {
				return true
			}
			rel, _ := filepath.Rel(root, path)
			seen[filepath.ToSlash(rel)]++
			hasPeer := false
			if len(call.Args) == 1 {
				if literal, ok := call.Args[0].(*ast.CompositeLit); ok {
					for _, e := range literal.Elts {
						kv, ok := e.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						key, ok := kv.Key.(*ast.Ident)
						if ok && key.Name == "PeerCertificate" {
							value, nilID := kv.Value.(*ast.Ident)
							hasPeer = !(nilID && value.Name == "nil")
						}
					}
				}
			}
			if !hasPeer {
				t.Errorf("%s: constructor lacks explicit provisioned peer", rel)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != len(expected) {
		t.Fatalf("ARI caller inventory changed: %v", seen)
	}
	for p, n := range expected {
		if seen[p] != n {
			t.Errorf("%s: expected %d calls; got %d", p, n, seen[p])
		}
	}
}
