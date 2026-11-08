// vgw-office-check is a provider-credential-free TLS and ownership probe.
// It reads the user's office file AS the isolated vgw-office UID, never
// serializes its values, sends no SIP, and never opens a listener.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"example.com/ata/voip-gateway/internal/serviceconfig"
)

func check(args []string) string {
	flags := flag.NewFlagSet("vgw-office-check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	runtimeFlags := serviceconfig.BindRuntimeFlags(flags, serviceconfig.DefaultOfficeRuntimeOptions())
	noNetwork := flags.Bool("no-network", false, "check private account ownership/shape without provider contact")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return "OFFICE_GO_IDENTITY_REFUSED"
	}
	options, err := runtimeFlags.Options()
	if err != nil || uint32(os.Geteuid()) != options.UID || uint32(os.Getegid()) != options.GID {
		return "OFFICE_GO_IDENTITY_REFUSED"
	}
	account, err := serviceconfig.ReadOfficeWithOptions(options)
	if err != nil {
		return "OFFICE_GO_ACCOUNT_REFUSED"
	}
	defer account.Clear()
	if account.Registrar != serviceconfig.OfficeRegistrar || account.TLSName != serviceconfig.OfficeTLSName {
		return "OFFICE_GO_TRUST_POLICY_REFUSED"
	}
	if *noNetwork {
		return "OFFICE_GO_FORMAT_OWNER_POLICY_OK_NO_NETWORK"
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
	connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(account.Registrar, strconv.Itoa(int(options.OfficePort))))
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
	fmt.Println(check(os.Args[1:])) // fixed category only; never fmt.Print(account or err)
}
