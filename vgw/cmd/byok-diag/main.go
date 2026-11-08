// byok-diag is a bounded, read-only jailed-prerequisite probe for a failed
// service start. It never registers, invites, prints config or sends media.
package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"example.com/ata/voip-gateway/internal/serviceconfig"
)

func main() {
	flags := flag.NewFlagSet("byok-diag", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	runtimeFlags := serviceconfig.BindRuntimeFlags(flags, serviceconfig.DefaultBYOKRuntimeOptions())
	if flags.Parse(os.Args[1:]) != nil || flags.NArg() != 0 {
		fmt.Println("DIAG_IDENTITY_REFUSED")
		return
	}
	options, err := runtimeFlags.Options()
	if err != nil || uint32(os.Geteuid()) != options.UID || uint32(os.Getegid()) != options.GID {
		fmt.Println("DIAG_IDENTITY_REFUSED")
		return
	}
	config, err := serviceconfig.ReadBYOKWithOptions(options)
	if err != nil {
		fmt.Println("DIAG_CONFIG_REFUSED")
		return
	}
	fmt.Println("DIAG_CONFIG_PASS")
	if !serviceconfig.OwnedRuntimeDir(options.RuntimeDir, options.UID, options.GID) ||
		!serviceconfig.OwnedRuntimeDir(options.StateDir, options.UID, options.GID) {
		fmt.Println("DIAG_DIRECTORIES_REFUSED")
		return
	}
	fmt.Println("DIAG_DIRECTORIES_PASS")
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil || len(pool.Subjects()) == 0 {
		fmt.Println("DIAG_CA_REFUSED")
		return
	}
	fmt.Println("DIAG_CA_PASS")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, config.Host)
	if err != nil || len(addresses) == 0 || len(addresses) > 16 {
		fmt.Println("DIAG_DNS_REFUSED")
		return
	}
	fmt.Println("DIAG_DNS_PASS")
	for _, addr := range addresses {
		if addr.IP.To4() == nil || addr.IP.IsUnspecified() || addr.IP.IsMulticast() || addr.IP.IsLinkLocalUnicast() {
			continue
		}
		conn, dialErr := net.DialUDP("udp", nil, &net.UDPAddr{IP: addr.IP, Port: int(config.Port)})
		if dialErr == nil {
			_ = conn.Close() // selects source address; emits NO packet
			fmt.Println("DIAG_SOURCE_PASS")
			return
		}
	}
	fmt.Println("DIAG_SOURCE_REFUSED")
}
