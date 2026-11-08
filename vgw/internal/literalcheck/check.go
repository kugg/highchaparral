// Package literalcheck inventories Go literals without printing secret
// strings. An explicit reviewed policy permits deployment defaults and
// protocol invariants; new unreviewed deployment literals fail CI.
package literalcheck

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

type Literal struct {
	File, Kind, Class, Context, SHA256 string
	Line, Column, Length               int
	Number                             string // only bounded deployment integers
}

type Rule struct {
	File           string `json:"file"`
	SHA256         string `json:"sha256"`
	Classification string `json:"classification"`
	Reason         string `json:"reason"`
	Count          int    `json:"count"`
}

type Policy struct {
	Version int    `json:"version"`
	Allow   []Rule `json:"allow"`
}

var reasonPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9 -]{5,120}$`)
var deploymentName = regexp.MustCompile(`(?i)(uid|gid|pid|port|socket|path|logfile|listen|bind)`)

func isSpecialDirectory(name string) bool {
	switch name {
	case ".git", "vendor", "secrets", "state", "node_modules", ".cache":
		return true
	}
	return false
}

func isOperationalText(value string) bool {
	for _, prefix := range []string{"/etc/", "/run/", "/var/lib/", "/var/log/", "http://127.0.0.1:", "https://127.0.0.1:", "../"} {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return strings.HasSuffix(value, ".sock") || strings.HasSuffix(value, ".pid") ||
		strings.HasSuffix(value, ".config") || strings.Contains(value, "eventphone_creds")
}

func selectorIdentity(node ast.Node) bool {
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if member, ok := n.(*ast.SelectorExpr); ok {
			found = found || member.Sel.Name == "Uid" || member.Sel.Name == "Gid" || member.Sel.Name == "Pid"
		}
		return true
	})
	return found
}

func numericContext(parent ast.Node) bool {
	switch node := parent.(type) {
	case *ast.BinaryExpr:
		return selectorIdentity(node)
	case *ast.ValueSpec:
		for _, name := range node.Names {
			if deploymentName.MatchString(name.Name) {
				return true
			}
		}
	case *ast.KeyValueExpr:
		if name, ok := node.Key.(*ast.Ident); ok {
			return deploymentName.MatchString(name.Name)
		}
	case *ast.CallExpr:
		if len(node.Args) > 0 {
			if name, ok := node.Args[0].(*ast.BasicLit); ok && name.Kind == token.STRING {
				text, err := strconv.Unquote(name.Value)
				return err == nil && deploymentName.MatchString(text)
			}
		}
	}
	return false
}

func classify(path string, node *ast.BasicLit, parent ast.Node) (string, string, int, string) {
	value := node.Value
	if node.Kind == token.STRING || node.Kind == token.CHAR {
		decoded, err := strconv.Unquote(value)
		if err != nil {
			return "invalid", "", 0, ""
		}
		value = decoded
	}
	class := "ordinary"
	if strings.HasSuffix(path, "_test.go") {
		class = "test-fixture"
	} else if strings.HasPrefix(path, "internal/literalcheck/") || strings.HasPrefix(path, "cmd/literalcheck/") {
		class = "lint-tool"
	} else if (node.Kind == token.STRING && isOperationalText(value)) ||
		(node.Kind == token.INT && numericContext(parent)) {
		class = "deployment"
	}
	number := ""
	if node.Kind == token.INT {
		parsed, err := strconv.ParseUint(node.Value, 0, 64)
		if err == nil {
			if class == "ordinary" && parsed > 255 {
				class = "deployment" // requires explicit protocol/buffer rationale
			}
			if class == "deployment" && parsed <= 65535 {
				number = strconv.FormatUint(parsed, 10)
			}
		}
	}
	digest := sha256.Sum256([]byte(node.Kind.String() + "\x00" + value))
	return class, hex.EncodeToString(digest[:]), len(value), number
}

// Scan returns every source literal, including test vectors, with all
// strings represented only by length and SHA-256. No symlink is followed.
func Scan(root string) ([]Literal, error) {
	var result []Literal
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("literal source traversal unavailable")
		}
		if entry.IsDir() {
			if path != root && isSpecialDirectory(entry.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		goSource := strings.HasSuffix(path, ".go")
		dockerfile := strings.HasPrefix(entry.Name(), "Dockerfile")
		if !goSource && !dockerfile {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || entry.Type()&os.ModeSymlink != 0 || info.Size() > 2*1024*1024 {
			return errors.New("unreviewed Go source file")
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return errors.New("unreviewed Go source path")
		}
		rel = filepath.ToSlash(rel)
		if dockerfile && !goSource {
			data, readErr := os.ReadFile(path)
			if readErr != nil || len(data) > 100000 || strings.ContainsAny(string(data), "\r\x00") {
				return errors.New("Dockerfile literal read unavailable")
			}
			for index, row := range strings.Split(string(data), "\n") {
				fields := strings.Fields(row)
				if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
					continue
				}
				directive := strings.ToUpper(fields[0])
				kind := ""
				switch directive {
				case "USER", "EXPOSE":
					kind = "DOCKER_" + directive
				case "ENV", "ARG":
					if deploymentName.MatchString(fields[1]) {
						kind = "DOCKER_" + directive
					}
				}
				if kind == "" {
					continue
				}
				value := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(row), fields[0]))
				sum := sha256.Sum256([]byte(kind + "\x00" + value))
				result = append(result, Literal{File: rel, Kind: kind, Class: "deployment",
					Context: "dockerfile:" + strings.ToLower(directive), SHA256: hex.EncodeToString(sum[:]),
					Line: index + 1, Column: 1, Length: len(value)})
			}
			return nil
		}
		positions := token.NewFileSet()
		parsed, err := parser.ParseFile(positions, path, nil, parser.AllErrors)
		if err != nil {
			return errors.New("Go source parse unavailable")
		}
		var stack []ast.Node
		ast.Inspect(parsed, func(n ast.Node) bool {
			if n == nil {
				if len(stack) != 0 {
					stack = stack[:len(stack)-1]
				}
				return true
			}
			if lit, ok := n.(*ast.BasicLit); ok {
				var parent ast.Node
				if len(stack) != 0 {
					parent = stack[len(stack)-1]
				}
				class, digest, length, number := classify(rel, lit, parent)
				contextName := "package"
				for i := len(stack) - 1; i >= 0; i-- {
					if function, ok := stack[i].(*ast.FuncDecl); ok {
						contextName = function.Name.Name
						break
					}
					if value, ok := stack[i].(*ast.ValueSpec); ok && len(value.Names) != 0 {
						contextName = "global:" + value.Names[0].Name
					}
				}
				location := positions.Position(lit.Pos())
				result = append(result, Literal{File: rel, Kind: lit.Kind.String(), Class: class,
					Context: contextName,
					SHA256:  digest, Line: location.Line, Column: location.Column,
					Length: length, Number: number})
			}
			stack = append(stack, n)
			return true
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].File != result[j].File {
			return result[i].File < result[j].File
		}
		if result[i].Line != result[j].Line {
			return result[i].Line < result[j].Line
		}
		return result[i].Column < result[j].Column
	})
	return result, nil
}

type Group struct {
	Count  int
	SHA256 string
}

// Groups calculates a source-position-independent, per-file checksum of
// every deployment literal's type, sanitized value and owning function.
func Groups(literals []Literal) map[string]Group {
	parts := make(map[string][]string)
	for _, literal := range literals {
		if literal.Class == "deployment" {
			parts[literal.File] = append(parts[literal.File],
				literal.Kind+"\x00"+literal.Context+"\x00"+literal.SHA256)
		}
	}
	result := make(map[string]Group, len(parts))
	for file, values := range parts {
		sort.Strings(values)
		sum := sha256.Sum256([]byte(strings.Join(values, "\n")))
		result[file] = Group{Count: len(values), SHA256: hex.EncodeToString(sum[:])}
	}
	return result
}

// Check refuses new or duplicated operational literals, invalid policy
// reasons and stale allowances. Ordinary/test literals remain inventoried
// but cannot become accepted deployment configuration by accident.
func Check(literals []Literal, policy Policy) error {
	if policy.Version != 1 {
		return errors.New("literal policy version refused")
	}
	groups := Groups(literals)
	seen := make(map[string]bool)
	for _, rule := range policy.Allow {
		match, exists := groups[rule.File]
		if seen[rule.File] || !exists || rule.Count < 1 || match.Count != rule.Count || match.SHA256 != rule.SHA256 ||
			!reasonPattern.MatchString(rule.Reason) ||
			(rule.Classification != "default" && rule.Classification != "security-invariant" && rule.Classification != "historical-fixture") {
			return errors.New("reviewed literal allowance invalid or stale")
		}
		seen[rule.File] = true
	}
	if len(seen) != len(groups) {
		return errors.New("new unreviewed deployment literal")
	}
	return nil
}

func ReadPolicy(path string) (Policy, error) {
	var policy Policy
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 20 || before.Size() > 128*1024 {
		return policy, errors.New("literal policy unavailable")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return policy, errors.New("literal policy unavailable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() {
		return Policy{}, errors.New("literal policy changed")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 128*1024))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&policy) != nil {
		return Policy{}, errors.New("literal policy invalid")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return Policy{}, errors.New("literal policy trailing input")
	}
	return policy, nil
}

func Report(out io.Writer, literals []Literal, operationalOnly bool) error {
	for _, literal := range literals {
		if operationalOnly && literal.Class != "deployment" {
			continue
		}
		if _, err := fmt.Fprintf(out, "%s:%d:%d context=%s class=%s kind=%s bytes=%d sha256=%s",
			literal.File, literal.Line, literal.Column, literal.Context, literal.Class, literal.Kind, literal.Length, literal.SHA256); err != nil {
			return errors.New("literal inventory output unavailable")
		}
		if literal.Number != "" {
			if _, err := fmt.Fprintf(out, " number=%s", literal.Number); err != nil {
				return errors.New("literal inventory output unavailable")
			}
		}
		if _, err := fmt.Fprintln(out); err != nil {
			return errors.New("literal inventory output unavailable")
		}
	}
	return nil
}
