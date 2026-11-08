// literalcheck inventories all Go source literals with strings redacted.
// --check enforces the reviewed deployment-literal policy for CI.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"example.com/ata/voip-gateway/internal/literalcheck"
)

func run(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("literalcheck", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", ".", "Go module root")
	policy := flags.String("policy", "docs/runtime-literals-policy.json", "reviewed deployment literal policy")
	list := flags.Bool("list", false, "list all hardcoded Go literals with string values redacted (also the default)")
	check := flags.Bool("check", false, "fail on an unreviewed deployment literal")
	operational := flags.Bool("operational", false, "list only deployment-classified literals")
	draft := flags.Bool("draft-policy", false, "print a policy skeleton that deliberately fails until reviewed")
	if flags.Parse(args) != nil || flags.NArg() != 0 || (*check && (*list || *operational || *draft)) ||
		(*draft && (*operational || *list)) {
		return fmt.Errorf("literalcheck operation refused")
	}
	literals, err := literalcheck.Scan(*root)
	if err != nil {
		return err
	}
	if *check {
		approved, err := literalcheck.ReadPolicy(filepath.Join(*root, *policy))
		if err != nil || literalcheck.Check(literals, approved) != nil {
			return fmt.Errorf("unreviewed or stale deployment literal")
		}
		_, err = fmt.Fprintln(out, "LITERAL_POLICY_PASS")
		return err
	}
	if *draft {
		groups := literalcheck.Groups(literals)
		keys := make([]string, 0, len(groups))
		for file := range groups {
			keys = append(keys, file)
		}
		sort.Strings(keys)
		policy := literalcheck.Policy{Version: 1}
		for _, file := range keys {
			group := groups[file]
			policy.Allow = append(policy.Allow, literalcheck.Rule{File: file, SHA256: group.SHA256,
				Count: group.Count, Classification: "review-required", Reason: "requires manual security review"})
		}
		encoder := json.NewEncoder(out)
		encoder.SetIndent("", "  ")
		return encoder.Encode(policy)
	}
	return literalcheck.Report(out, literals, *operational)
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "LITERAL_CHECK_REFUSED; inspect --operational inventory")
		os.Exit(2)
	}
}
