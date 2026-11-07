package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestDefaultDryRunAndBadArgumentsDoNotEchoCredentials(t *testing.T) {
	var stdout bytes.Buffer
	if err := run(nil, &stdout); err != nil || !strings.Contains(stdout.String(), "DRY RUN") {
		t.Fatal("default vgw command should not read config or open network")
	}
	stdout.Reset()
	for _, args := range [][]string{
		{"--password=synthetic-secret-only"},
		{"--serve", "--check-config"},
		{"--serve", "--serve-byok"},
		{"--check-config", "--serve-byok"},
		{"--serve", "unexpected"},
	} {
		err := run(args, &stdout)
		if err == nil || strings.Contains(err.Error(), "synthetic-secret-only") || stdout.Len() != 0 {
			t.Fatal("untrusted argv accepted or secret echoed")
		}
	}
}

func TestBYOKServiceRefusesWrongIdentityBeforeOpeningAnySocket(t *testing.T) {
	var stdout bytes.Buffer
	if err := run([]string{"--serve-byok"}, &stdout); err == nil || stdout.Len() != 0 {
		t.Fatal("unowned BYOK service started without a vgw user, owned dirs and private config")
	}
}

func TestSourceAddressProbeNeverNeedsProviderConnection(t *testing.T) {
	selected, err := onlySourceAddress(context.Background(), "127.0.0.1", 5061)
	if err != nil || selected != "127.0.0.1" {
		t.Fatal("source address probe failed for synthetic local provider")
	}
	if _, err := onlySourceAddress(context.Background(), "%%invalid", 5061); err == nil {
		t.Fatal("malformed provider name accepted")
	}
}
