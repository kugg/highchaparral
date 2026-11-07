package serviceconfig

import (
	"strings"
	"testing"
)

const syntheticBYOK = "ARI_USER=vgw_local\n" +
	"ARI_PASSWORD=synthetic-ari-password-long-1234\n" +
	"UPSTREAM_HOST=hg.eventphone.de\n" +
	"UPSTREAM_PORT=5061\n" +
	"UPSTREAM_TLS_NAME=hg.eventphone.de\n" +
	"UPSTREAM_CERT_SHA256=ca-only\n" +
	"SITE_ORIGIN_LAN=https://192.0.2.1\n" +
	"SITE_ORIGIN_WG=https://192.0.2.2\n"

func TestBYOKConfigHasNoProviderCredentialAndKeepsExplicitTrust(t *testing.T) {
	c, err := ParseBYOK([]byte(syntheticBYOK))
	if err != nil || c.Host != "hg.eventphone.de" || c.TLSName != c.Host || c.Port != 5061 ||
		c.Origins[0] != "https://192.0.2.1" || strings.Contains(c.String(), "synthetic-ari-password") {
		t.Fatal("owner-only BYOK config or redaction invalid")
	}
	for _, bad := range []string{
		strings.ReplaceAll(syntheticBYOK, "UPSTREAM_CERT_SHA256=ca-only", "UPSTREAM_CERT_SHA256=none"),
		syntheticBYOK + "UPSTREAM_PASSWORD=unreviewed\n",
		strings.ReplaceAll(syntheticBYOK, "https://192.0.2.1", "http://192.0.2.1"),
		strings.ReplaceAll(syntheticBYOK, "SITE_ORIGIN_WG=https://192.0.2.2", "SITE_ORIGIN_WG=https://192.0.2.1"),
		strings.ReplaceAll(syntheticBYOK, "hg.eventphone.de\nUPSTREAM_PORT", "evil.invalid\nUPSTREAM_PORT"),
		strings.ReplaceAll(syntheticBYOK, "synthetic-ari-password-long-1234", "bad\r\nX-Log: injected"),
	} {
		if _, err := ParseBYOK([]byte(bad)); err == nil || strings.Contains(err.Error(), "synthetic") {
			t.Fatal("untrusted BYOK config/credential injection was accepted/reflected")
		}
	}
}
