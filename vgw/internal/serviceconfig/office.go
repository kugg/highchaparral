package serviceconfig

// Persistent OFFICE-ONLY EPVPN identity. Unlike browser BYOK credentials,
// this dedicated office extension must be explicitly filled by the operator
// in a root:vgw file on the APU. No office service or inbound/outbound SIP
// listener is enabled simply because the file exists.

import (
	"bytes"
	"errors"
	"os"
	"regexp"
	"strings"
)

const (
	// A separate owner-only office profile keeps the persistent SIP
	// password OUT of the existing browser BYOK gateway's readable jail.
	OfficeDirectory = "/etc/voip-gateway-office"
	OfficePath      = OfficeDirectory + "/office-account.config"
	OfficeGroupName = "vgw-office"
	// This exact network alias presents a CA-trusted cert for hg, not
	// for the alias. Verified server_name is fixed, NEVER disabled or
	// accepted as a user-input override. No credential is sent until
	// CA+hg hostname verification succeeds over TLS 1.2+.
	OfficeRegistrar = "pbx-epvpn-voip.eventphone.de"
	OfficeTLSName   = "hg.eventphone.de"
)

var officeKeys = [...]string{"Server/Registrar", "AuthUser", "Password", "Extension"}
var officeIdentity = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
var officeExtension = regexp.MustCompile(`^[0-9]{4}$`)

type OfficeAccount struct {
	Registrar string
	AuthUser  string
	Password  []byte
	Extension string
	TLSName   string // fixed derived transport identity, not a fifth editable field
}

func (OfficeAccount) String() string   { return "dedicated office EPVPN account [redacted]" }
func (OfficeAccount) GoString() string { return "serviceconfig.OfficeAccount{redacted}" }
func (OfficeAccount) MarshalJSON() ([]byte, error) {
	return nil, errors.New("office account serialization refused")
}
func (account *OfficeAccount) Clear() {
	if account == nil {
		return
	}
	for i := range account.Password {
		account.Password[i] = 0
	}
	account.Password = nil
}

// ParseOffice accepts EXACTLY these four ordered, printable fields. An
// incomplete blank template must fail closed. Do not reflect any caller or
// secret bytes in an error, CLI status, trace, SIP URL, template or SQL sink.
func ParseOffice(raw []byte) (OfficeAccount, error) {
	var empty OfficeAccount
	if len(raw) < 80 || len(raw) > 1024 || bytes.IndexAny(raw, "\r\x00") >= 0 ||
		!bytes.HasSuffix(raw, []byte("\n")) || bytes.Contains(raw, []byte("\n\n")) {
		return empty, reject()
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) != len(officeKeys) {
		return empty, reject()
	}
	values := make([]string, len(officeKeys))
	for i, row := range lines {
		prefix := officeKeys[i] + ": "
		if !strings.HasPrefix(row, prefix) {
			return empty, reject()
		}
		value := strings.TrimPrefix(row, prefix)
		if len(value) < 1 || len(value) > 256 {
			return empty, reject()
		}
		for _, ch := range []byte(value) {
			if ch < '!' || ch > '~' {
				return empty, reject()
			}
		}
		values[i] = value
	}
	if values[0] != OfficeRegistrar || !officeIdentity.MatchString(values[1]) ||
		!officeExtension.MatchString(values[3]) || len(values[2]) > 256 {
		return empty, reject()
	}
	return OfficeAccount{Registrar: OfficeRegistrar, AuthUser: values[1],
		Password: []byte(values[2]), Extension: values[3], TLSName: OfficeTLSName}, nil
}

// ReadOfficeWithOptions uses a separately provisioned root:selected-GID
// path, not browser/SIP identity. The reviewed registrar/TLS name stay fixed.
func ReadOfficeWithOptions(options RuntimeOptions) (OfficeAccount, error) {
	if !options.Valid() || options.UID != uint32(os.Geteuid()) || options.GID != uint32(os.Getegid()) {
		return OfficeAccount{}, reject()
	}
	raw, err := readProtected(options.ConfigPath, options.UID, options.GID, 1024)
	if err != nil {
		return OfficeAccount{}, err
	}
	return ParseOffice(raw)
}

func ReadOffice() (OfficeAccount, error) {
	return ReadOfficeWithOptions(DefaultOfficeRuntimeOptions())
}
