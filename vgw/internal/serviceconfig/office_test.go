package serviceconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

const syntheticOffice = "Server/Registrar: pbx-epvpn-voip.eventphone.de\n" +
	"AuthUser: synthetic-only\nPassword: OnlyForUnitTests!\nExtension: 1234\n"

func TestOfficeFourFieldIdentityAndFixedVerifiedTLSName(t *testing.T) {
	if OfficePath != "/etc/voip-gateway-office/office-account.config" ||
		OfficeDirectory != "/etc/voip-gateway-office" || OfficeGroupName != "vgw-office" {
		t.Fatal("persistent office secret could enter browser BYOK gateway config or UID")
	}
	account, err := ParseOffice([]byte(syntheticOffice))
	if err != nil || account.Registrar != OfficeRegistrar || account.TLSName != OfficeTLSName ||
		account.AuthUser != "synthetic-only" || account.Extension != "1234" ||
		string(account.Password) != "OnlyForUnitTests!" {
		t.Fatal("operator-owned office account format or fixed TLS identity refused")
	}
	if strings.Contains(account.String(), "synthetic-only") ||
		strings.Contains(account.GoString(), "OnlyForUnitTests!") {
		t.Fatal("office account printed an identity or password")
	}
	if raw, err := json.Marshal(account); err == nil || len(raw) != 0 {
		t.Fatal("office account serialized the persistent SIP credential")
	}
	account.Clear()
	if account.Password != nil {
		t.Fatal("owned password slice survived explicit release")
	}
}

func TestOfficeTemplateOrInjectedFieldsCannotBecomeRegistration(t *testing.T) {
	for _, raw := range []string{
		"Server/Registrar: pbx-epvpn-voip.eventphone.de\nAuthUser: \nPassword: \nExtension: \n",
		strings.Replace(syntheticOffice, "pbx-epvpn-voip.eventphone.de", "attacker.invalid", 1),
		strings.Replace(syntheticOffice, "AuthUser: synthetic-only", "AuthUser: synthetic-only\r\nX-Audit: forged", 1),
		strings.Replace(syntheticOffice, "Password: OnlyForUnitTests!", "Password: test\nPassword: forged", 1),
		strings.Replace(syntheticOffice, "Extension: 1234", "Extension: 1234;Dial(PSTN)", 1),
		strings.Replace(syntheticOffice, "Server/Registrar:", "TLSName:", 1),
		strings.TrimSuffix(syntheticOffice, "\n"),
	} {
		_, err := ParseOffice([]byte(raw))
		if err == nil || strings.Contains(err.Error(), "forged") ||
			strings.Contains(err.Error(), "synthetic-only") || strings.Contains(err.Error(), "attacker.invalid") {
			t.Fatal("untrusted office config was accepted or reflected into an error")
		}
	}
}
