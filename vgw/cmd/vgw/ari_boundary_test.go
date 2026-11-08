package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// No ARI command has a plaintext exception. This fence rejects a service
// endpoint downgrade or reintroduction of the retired lab escape.
func TestServiceRequiresAuthenticatedARIBinding(t *testing.T) {
	files, err := parser.ParseDir(token.NewFileSet(), ".", func(info os.FileInfo) bool { return !strings.HasSuffix(info.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range files {
		for name, file := range pkg.Files {
			ast.Inspect(file, func(node ast.Node) bool {
				if selector, ok := node.(*ast.SelectorExpr); ok && selector.Sel.Name == "NewLoopbackLab" {
					t.Errorf("%s: production service selected the lab peer-authentication exception", name)
				}
				if literal, ok := node.(*ast.BasicLit); ok && strings.Contains(literal.Value, "http://127.0.0.1:") {
					t.Errorf("%s: production service configured plaintext ARI", name)
				}
				return true
			})
		}
	}
}
