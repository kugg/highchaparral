package main

import (
	"strings"
	"testing"
)

func TestGuestARIConfigRejectsDuplicateOrInjectedFields(t *testing.T) {
	base := "GATEWAY_LAB_ARI_USER=ata-ari-lab\nGATEWAY_LAB_ARI_PASSWORD=synthetic-only-password\n"
	user, pass, err := parseARIConfig([]byte(base))
	if err != nil || user != "ata-ari-lab" || pass != "synthetic-only-password" {
		t.Fatal("synthetic ARI fixture rejected")
	}
	for _, bad := range []string{
		base + "GATEWAY_LAB_ARI_PASSWORD=other\n",
		strings.Replace(base, "ata-ari-lab", "user\r\nInjected: data", 1),
		strings.Replace(base, "synthetic-only-password", "x", 1),
		strings.Replace(base, "GATEWAY_LAB_ARI_USER=", "GATEWAY_LAB_SIP=", 1),
		strings.Replace(base, "synthetic-only-password", "synthetic=password", 1),
	} {
		if _, _, err := parseARIConfig([]byte(bad)); err == nil || strings.Contains(err.Error(), "synthetic-only-password") {
			t.Fatal("untrusted ARI config accepted or secret reflected")
		}
	}
}
