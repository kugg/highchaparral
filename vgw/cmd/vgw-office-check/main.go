// vgw-office-check is a provider-credential-free TLS and ownership probe.
// It reads the user's office file AS the isolated vgw-office UID, never
// serializes its values, sends no SIP, and never opens a listener.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"example.com/ata/voip-gateway/internal/serviceconfig"
)

func check() string {
	if len(os.Args) != 1 || os.Geteuid() != 34568 || os.Getegid() != 34568 {
		return "OFFICE_GO_IDENTITY_REFUSED"
	}
	account, err := serviceconfig.ReadOffice()
	if err != nil {
		return "OFFICE_GO_ACCOUNT_REFUSED"
	}
	defer account.Clear()
	if account.Registrar != serviceconfig.OfficeRegistrar || account.TLSName != serviceconfig.OfficeTLSName {
		return "OFFICE_GO_TRUST_POLICY_REFUSED"
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil || len(roots.Subjects()) == 0 {
		return "OFFICE_GO_ROOT_CA_REFUSED"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second},
		Config: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots,
			ServerName: serviceconfig.OfficeTLSName}}
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(account.Registrar, strconv.Itoa(5061)))
	if err != nil {
		return "OFFICE_GO_VERIFIED_TLS_REFUSED"
	}
	defer connection.Close()
	verified, ok := connection.(*tls.Conn)
	if !ok || verified.ConnectionState().Version < tls.VersionTLS12 || !verified.ConnectionState().HandshakeComplete {
		return "OFFICE_GO_TLS_VERSION_REFUSED"
	}
	return "OFFICE_GO_FORMAT_OWNER_CA_HOSTNAME_TLS_OK_NO_SIP"
}

func main() {
	fmt.Println(check()) // fixed category only; never fmt.Print(account or err)
}
