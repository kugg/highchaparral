// Provider-free, one-use real browser ARI attachment using the SAME Go
// asterisk.Client as the gateway. No BYOK store, SIP REGISTER/INVITE, target
// number, media sample, credential or remote response is emitted to stdout.
package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"example.com/ata/voip-gateway/internal/asterisk"
	"example.com/ata/voip-gateway/internal/serviceconfig"
)

func category(err error) string {
	if err == nil {
		return "GO_ARI_ATTACH_OK"
	}
	switch err.Error() { // exact source-owned strings only; never return err.Error()
	case "browser ARI admission unavailable":
		return "GO_ARI_ADMISSION_REFUSED"
	case "invalid browser ARI media socket", "owned browser media socket unavailable":
		return "GO_ARI_SOCKET_REFUSED"
	case "browser ARI bridge creation failed":
		return "GO_ARI_BRIDGE_CREATE_REFUSED"
	case "browser ARI external media creation failed":
		return "GO_ARI_EXTERNAL_MEDIA_REFUSED"
	case "browser ARI RTP address unavailable":
		return "GO_ARI_RTP_ADDRESS_REFUSED"
	case "browser ARI RTP port unavailable":
		return "GO_ARI_RTP_PORT_REFUSED"
	case "browser ARI media bridge attachment failed":
		return "GO_ARI_MEDIA_ADD_REFUSED"
	case "browser ARI channel bridge attachment failed":
		return "GO_ARI_BROWSER_ADD_REFUSED"
	case "browser ARI caller not bridge-ready":
		return "GO_ARI_BROWSER_NOT_READY"
	case "browser ARI bridge membership unavailable":
		return "GO_ARI_MEMBERSHIP_REFUSED"
	case "browser ARI failure and owned cleanup incomplete":
		return "GO_ARI_CLEANUP_REFUSED"
	default:
		return "GO_ARI_OTHER_REFUSED"
	}
}

func run(args []string) string {
	flags := flag.NewFlagSet("ari-browser-probe", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	runtimeFlags := serviceconfig.BindRuntimeFlags(flags, serviceconfig.DefaultBYOKRuntimeOptions())
	synthetic := flags.Bool("synthetic-regression", false, "one local synthetic browser call with no provider leg")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return "GO_ARI_IDENTITY_REFUSED"
	}
	var base, user, password, expected string
	var peer *x509.Certificate
	if *synthetic {
		var err error
		user, password, expected, peer, err = regressionInputs()
		if err != nil || os.Geteuid() == 0 {
			return "MOCK_CONFIG_REFUSED"
		}
		base = "https://127.0.0.1:8089"
	} else {
		options, err := runtimeFlags.Options()
		if err != nil || uint32(os.Geteuid()) != options.UID || uint32(os.Getegid()) != options.GID {
			return "GO_ARI_IDENTITY_REFUSED"
		}
		config, err := serviceconfig.ReadBYOKWithOptions(options)
		if err != nil {
			return "GO_ARI_CONFIG_REFUSED"
		}
		peer, err = serviceconfig.ReadARIPeerCertificateWithOptions(options)
		if err != nil {
			return "GO_ARI_PEER_REFUSED"
		}
		base, user, password = config.ARIBaseURL, config.ARIUser, config.ARIPassword
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	limit := 40 * time.Second
	if *synthetic {
		limit = 60 * time.Second
	}
	ctx, timeout := context.WithTimeout(ctx, limit)
	defer timeout()
	client, err := asterisk.New(asterisk.Config{BaseURL: base, PeerCertificate: peer,
		Username: user, Password: password,
		Timeout: 3 * time.Second, Target: asterisk.BrowserIngress})
	if err != nil {
		return "GO_ARI_CLIENT_REFUSED"
	}
	defer client.Close()
	events, gone, err := client.SubscribeBrowser(ctx)
	if err != nil {
		return "GO_ARI_SUBSCRIBE_REFUSED"
	}
	if *synthetic {
		fmt.Println("MOCK_WATCHER_READY")
		return regressionCall(ctx, client, events, gone, expected, user, password, peer)
	}
	fmt.Println("GO_ARI_WATCHER_READY")
	select {
	case <-gone:
		return "GO_ARI_SUBSCRIPTION_GONE"
	case <-ctx.Done():
		return "GO_ARI_EVENT_TIMEOUT"
	case start, ok := <-events:
		if !ok {
			return "GO_ARI_EVENT_REFUSED"
		}
		readCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		dial, err := client.ReadBrowserDial(readCtx, start)
		cancel()
		if err != nil {
			return "GO_ARI_READBACK_REFUSED"
		}
		socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			return "GO_ARI_SOCKET_REFUSED"
		}
		defer socket.Close()
		attached, err := client.AttachBrowser(ctx, asterisk.BrowserStart{ChannelID: dial.ChannelID,
			Nonce: dial.Nonce}, socket)
		if err != nil {
			return category(err)
		}
		select {
		case <-gone:
			if attached.Close() != nil {
				return "GO_ARI_CLEANUP_REFUSED"
			}
			return "GO_ARI_SUBSCRIPTION_GONE_DURING_ATTACH"
		default:
		}
		// No provider leg: answer once to let the disposable browser finish.
		if client.AnswerBrowser(ctx, asterisk.BrowserStart{ChannelID: dial.ChannelID,
			Nonce: dial.Nonce}) != nil {
			if attached.Close() != nil {
				return "GO_ARI_CLEANUP_REFUSED"
			}
			return "GO_ARI_ANSWER_REFUSED"
		}
		if attached.Close() != nil {
			return "GO_ARI_CLEANUP_REFUSED"
		}
		select {
		case <-gone:
			return "GO_ARI_SUBSCRIPTION_GONE_AFTER_CLEANUP"
		default:
		}
		return "GO_ARI_ATTACH_OK"
	}
}

func main() {
	fmt.Println(run(os.Args[1:])) // exact fixed category or ready marker only
}
