// Command vgw is the provider-neutral service entry point. It currently
// implements only bounded SIP/TLS REGISTER. Inbound/ATA/ARI call bridging,
// Contact policy and ambiguous-BYE recovery remain RELEASE BLOCKERS;
// never package this as a full provider-capable APU service yet.
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"example.com/ata/voip-gateway/internal/registration"
	"example.com/ata/voip-gateway/internal/serviceconfig"
)

func onlySourceAddress(ctx context.Context, host string, port uint16) (string, error) {
	lookup, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(lookup, host)
	if err != nil || len(addresses) == 0 || len(addresses) > 16 {
		return "", errors.New("reviewed registrar DNS unavailable")
	}
	for _, candidate := range addresses {
		address := candidate.IP
		// This attended stage uses the existing IPv4 office uplink only.
		// Source selection must not choose or change the fleet IPv6 route.
		if address == nil || address.To4() == nil || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() {
			continue
		}
		remote := &net.UDPAddr{IP: address, Port: int(port)}
		conn, dialErr := net.DialUDP("udp", nil, remote) // source selection only; sends NO packet
		if dialErr != nil {
			continue
		}
		selected := conn.LocalAddr().(*net.UDPAddr).IP
		_ = conn.Close()
		if selected != nil && selected.To4() != nil && !selected.IsUnspecified() && !selected.IsMulticast() {
			return selected.String(), nil
		}
	}
	return "", errors.New("reviewed registrar source address unavailable")
}

func selectedBindIPv4(selected, override string) (string, error) {
	if override == "" {
		return selected, nil
	}
	ip := net.ParseIP(override)
	if ip == nil || ip.To4() == nil || ip.IsUnspecified() || ip.IsMulticast() {
		return "", errors.New("invalid local SIP bind address")
	}
	// Bind and immediately close a packet-free socket to prove the
	// configured IPv4 address belongs to this host before SIP traffic.
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: ip.To4()})
	if err != nil {
		return "", errors.New("unowned local SIP bind address")
	}
	_ = probe.Close()
	return ip.To4().String(), nil
}

func run(args []string, out io.Writer) (runErr error) {
	flags := flag.NewFlagSet("vgw", flag.ContinueOnError)
	flags.SetOutput(io.Discard) // never reflect an argv string containing a credential
	runtimeFlags := serviceconfig.BindRuntimeFlags(flags, serviceconfig.DefaultRuntimeOptions())
	check := flags.Bool("check-config", false, "verify fixed service config without contacting provider")
	serve := flags.Bool("serve", false, "register with reviewed upstream SIP/TLS provider")
	byok := flags.Bool("serve-byok", false, "run one-at-a-time browser BYOK softphone service")
	testCheck := flags.Bool("test-register-check", false, "check owner-only development credential shape offline")
	testOnce := flags.Bool("test-register-once", false, "one bounded development REGISTER and Unregister; no INVITE")
	testStatus := flags.Bool("test-register-status", false, "read fixed-category one-use development result")
	if flags.Parse(args) != nil || flags.NArg() != 0 ||
		(boolInt(*check)+boolInt(*serve)+boolInt(*byok)+boolInt(*testCheck)+boolInt(*testOnce)+boolInt(*testStatus) > 1) {
		return errors.New("unsupported vgw operation; no network used")
	}
	defaultPath := serviceconfig.Path
	if *byok {
		defaultPath = serviceconfig.BYOKPath
	}
	options, err := runtimeFlags.OptionsFor(defaultPath)
	if err != nil {
		return errors.New("invalid trusted vgw runtime options; no network used")
	}
	if *testStatus {
		return reportTestRegisterStatus(out)
	}
	if *testCheck {
		return checkTestRegisterCredentials(out)
	}
	if *testOnce {
		return runTestRegisterOnce(out)
	}
	if !*check && !*serve && !*byok {
		_, _ = fmt.Fprintln(out, "DRY RUN: voip-gateway config/connector; no file, VM or provider network access")
		return nil
	}
	if *byok {
		return runBYOK(out, options)
	}
	c, err := serviceconfig.ReadWithOptions(options) // trusted --config, private owner checks before parsing
	if err != nil {
		return errors.New("owner-private vgw config unavailable")
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		return errors.New("vgw system CA trust unavailable")
	}
	if _, err := serviceconfig.TLSClient(c, roots); err != nil {
		return errors.New("vgw provider identity trust unavailable")
	}
	if *check {
		_, _ = fmt.Fprintln(out, "vgw private config/CA/hostname/TLS policy syntax PASS; no network used")
		return nil
	}
	logFile, err := serviceconfig.OpenErrorLog(c.ErrorLogPath, options.UID, options.GID)
	if err != nil {
		return errors.New("owner-only vgw error log unavailable")
	}
	if logFile != nil {
		defer func() {
			category := "VGW_SERVICE_STOPPED"
			if runErr != nil {
				category = "VGW_SERVICE_REFUSED"
			}
			if serviceconfig.WriteLogCategory(logFile, category) != nil && runErr == nil {
				runErr = errors.New("bounded vgw error log unavailable")
			}
			_ = logFile.Close()
		}()
	}
	closePID, err := serviceconfig.OpenPIDFile(options)
	if err != nil {
		return errors.New("owned vgw PID file unavailable")
	}
	defer func() {
		if closePID() != nil && runErr == nil {
			runErr = errors.New("owned vgw PID file cleanup incomplete")
		}
	}()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	local, err := onlySourceAddress(ctx, c.UpstreamHost, c.UpstreamPort)
	if err != nil {
		return errors.New("vgw local registrar source address unavailable")
	}
	local, err = selectedBindIPv4(local, c.BindIPv4)
	if err != nil {
		return errors.New("reviewed SIP bind address unavailable")
	}
	// Only REGISTER/refresh/unregister is present. No INVITE/voice/provider
	// call can be triggered by this entry point; release gate stays closed.
	if err := registration.RunUpstreamObserved(ctx, c, roots, local, func() error {
		// Fixed signal only after the SIP transaction receives the
		// provider's successful REGISTER response. The deploy stage owns
		// the output file and must check the process is still alive.
		_, err := fmt.Fprintln(out, "VGW_REGISTER_ACCEPTED")
		if err == nil {
			err = serviceconfig.WriteLogCategory(logFile, "VGW_REGISTER_ACCEPTED")
		}
		return err
	}, func() error {
		_, err := fmt.Fprintln(out, "VGW_REGISTER_REFRESHED")
		if err == nil {
			err = serviceconfig.WriteLogCategory(logFile, "VGW_REGISTER_REFRESHED")
		}
		return err
	}); err != nil {
		return errors.New("vgw registration unavailable; no call retry")
	}
	return nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		// Fixed category only. Do not log the provider library error,
		// hostname, SIP headers, credentials, Contact or TLS certificate.
		slog.Error("vgw operation stopped", "category", "registration-or-config")
		os.Exit(2)
	}
}
