package serviceconfig

import "testing"

// FuzzPrivateConfigParsers uses only synthetic bytes and never reads /etc,
// a credential file, provider socket or owner-private runtime stage.
func FuzzPrivateConfigParsers(f *testing.F) {
	f.Add([]byte(fixture))
	f.Add([]byte(syntheticBYOK))
	f.Add([]byte(syntheticOffice))
	f.Add([]byte("ARI_BASE_URL=https://127.0.0.1:8088\r\nX-Log: forged\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 8192 {
			t.Skip()
		}
		if _, err := Parse(raw); err != nil && err.Error() != "voip-gateway configuration invalid" {
			t.Fatal("service parser returned an unreviewed error category")
		}
		if _, err := ParseBYOK(raw); err != nil && err.Error() != "voip-gateway configuration invalid" {
			t.Fatal("BYOK parser returned an unreviewed error category")
		}
		account, err := ParseOffice(raw)
		if err != nil && err.Error() != "voip-gateway configuration invalid" {
			t.Fatal("office parser returned an unreviewed error category")
		}
		account.Clear()
	})
}
