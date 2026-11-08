// Package registration owns only a local test registrar connection. It does
// not configure the M0 echo listener or initiate calls.
package registration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"example.com/ata/voip-gateway/internal/safesip"
	"example.com/ata/voip-gateway/internal/serviceconfig"
	"github.com/emiago/diago"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

// Config deliberately permits only a local TLS registrar for the M1 testbench.
// No real provider credentials or endpoints are used by this package's tests.
type Config struct {
	Host       string // empty means strictly local synthetic registrar
	BindHost   string // empty means IPv4 127.0.0.1
	BindPort   int    // 0 means kernel-assigned ephemeral port
	Port       int
	ServerName string
	Roots      *x509.CertPool
	TLS        *tls.Config // nonnil ONLY after serviceconfig.TLSClient verification
	Username   string
	Password   string
	Expiry     time.Duration
	Refresh    time.Duration
	RetryMin   time.Duration
	RetryMax   time.Duration
	Timeout    time.Duration
	// OnFirstRegistered is called only after the SIP transaction receives
	// a successful REGISTER response, never on a 401 challenge. A registrar
	// may accept without issuing a challenge; this reports acceptance,
	// not independent proof of Digest authentication.
	OnFirstRegistered func() error
	// OnFirstRefreshed runs once after a successful REGISTER refresh,
	// never merely because a timer elapsed or a request was sent.
	OnFirstRefreshed func() error
}

func (c Config) valid() bool {
	if c.Host == "" {
		if c.BindHost != "" || c.TLS != nil {
			return false
		}
	} else {
		ip := net.ParseIP(c.BindHost)
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() ||
			c.TLS == nil || c.TLS.InsecureSkipVerify || c.TLS.VerifyConnection == nil ||
			c.TLS.ServerName != c.ServerName || c.TLS.RootCAs != c.Roots ||
			c.TLS.MinVersion < tls.VersionTLS12 {
			return false
		}
	}
	return c.BindPort >= 0 && c.BindPort <= 65535 && c.Port > 0 && c.Port <= 65535 && c.ServerName != "" && c.Roots != nil &&
		len(c.ServerName) <= 253 && validUser(c.Username) &&
		len(c.Password) > 0 && len(c.Password) <= 256 && c.Expiry >= time.Second &&
		c.Refresh >= 50*time.Millisecond && c.Refresh < c.Expiry &&
		c.RetryMin >= 25*time.Millisecond && c.RetryMax >= c.RetryMin &&
		c.RetryMax <= 10*time.Second && c.Timeout > 0 && c.Timeout <= 10*time.Second
}

// The user is interpolated into the SIP URI by sipgo; forbid delimiters,
// controls and other unescaped bytes before constructing that URI.
func validUser(user string) bool {
	if len(user) == 0 || len(user) > 64 {
		return false
	}
	for i := 0; i < len(user); i++ {
		b := user[i]
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' ||
			b >= '0' && b <= '9' || b == '.' || b == '_' || b == '-') {
			return false
		}
	}
	return true
}

const maxConsecutiveFailures = 6

var active atomic.Bool

// Run maintains a registration with Diago's REGISTER transaction API.
// The only destination is 127.0.0.1:Port; TLS verification cannot be disabled.
// Errors are fixed categories, never library errors that may contain headers.
func Run(ctx context.Context, c Config) error {
	if !c.valid() {
		return errors.New("invalid local registration configuration")
	}
	if !active.CompareAndSwap(false, true) {
		return errors.New("local registration already active")
	}
	defer active.Store(false)
	tlsConfig := c.TLS
	bindHost, host := c.BindHost, c.Host
	if c.Host == "" {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.Roots, ServerName: c.ServerName}
		bindHost, host = "127.0.0.1", "127.0.0.1"
	}
	quiet := safesip.Logger
	ua, err := sipgo.NewUA(sipgo.WithUserAgenTLSConfig(tlsConfig),
		sipgo.WithUserAgentTransportLayerOptions(sip.WithTransportLayerLogger(quiet)),
		sipgo.WithUserAgentTransactionLayerOptions(
			sip.WithTransactionLayerLogger(quiet),
			sip.WithTransactionLayerUnhandledResponseHandler(func(*sip.Response) {}),
		))
	if err != nil {
		return errors.New("cannot initialize SIP user agent")
	}
	defer ua.Close()
	// Diago's default handler can log peer-controlled From/To on failures.
	// The M1 registration adapter does not allow that output into local logs.
	dg := diago.NewDiago(ua,
		diago.WithTransport(diago.Transport{Transport: "tls", BindHost: bindHost, BindPort: c.BindPort}),
		diago.WithLogger(quiet),
	)
	uri := sip.Uri{Scheme: "sips", User: c.Username, Host: host, Port: c.Port}
	uri.UriParams = sip.NewParams()
	uri.UriParams.Add("transport", "tls")
	opts := diago.RegisterOptions{Username: c.Username, Password: c.Password, Expiry: c.Expiry}
	var registered *diago.RegisterTransaction
	attempted := false
	registeredEver := false
	observed := false
	observedRefresh := false
	finish := func() error {
		if c.Host != "" && attempted && !registeredEver {
			return errors.New("registration never established; no SIP retry after cancellation")
		}
		return nil
	}
	backoff := c.RetryMin
	failures := 0
	defer func() {
		if registered == nil {
			return
		}
		stop, cancel := context.WithTimeout(context.Background(), c.Timeout)
		defer cancel()
		_ = registered.Unregister(stop) // one bounded best-effort shutdown request
	}()

	for {
		if ctx.Err() != nil {
			return finish()
		}
		attempted = true
		attempt, e := dg.RegisterTransaction(ctx, uri, opts)
		if e == nil {
			request, cancel := context.WithTimeout(ctx, c.Timeout)
			e = attempt.Register(request)
			cancel()
		}
		if e == nil {
			registeredEver = true
			registered = attempt
			if !observed && c.OnFirstRegistered != nil {
				if c.OnFirstRegistered() != nil {
					return errors.New("registration accepted but private status unavailable")
				}
				observed = true
			}
			backoff = c.RetryMin
			failures = 0
			for wait(ctx, c.Refresh) {
				request, cancel := context.WithTimeout(ctx, c.Timeout)
				e = attempt.Qualify(request)
				cancel()
				if e != nil {
					break
				}
				if !observedRefresh && c.OnFirstRefreshed != nil {
					if c.OnFirstRefreshed() != nil {
						return errors.New("registration refresh accepted but private status unavailable")
					}
					observedRefresh = true
				}
			}
		}
		if ctx.Err() != nil {
			return finish()
		}
		if fatal(e) {
			return errors.New("registration rejected or TLS identity invalid")
		}
		failures++
		if failures >= maxConsecutiveFailures {
			return errors.New("registration temporarily unavailable")
		}
		if !wait(ctx, backoff) {
			return finish()
		}
		backoff = min(backoff*2, c.RetryMax)
	}
}

// RunUpstream maintains ONLY SIP/TLS REGISTER/refresh for the reviewed
// private provider config. It does not accept INVITE/BYE or initiate
// calls; that call path is a separate production release gate. The
// caller chooses a local IPv4 bind address but cannot disable normal
// CA/SAN verification; optional DER-leaf pinning is explicit policy.
func RunUpstream(ctx context.Context, service serviceconfig.Config, roots *x509.CertPool, bindIP string) error {
	return RunUpstreamObserved(ctx, service, roots, bindIP, nil, nil)
}

// RunUpstreamObserved reports the first accepted provider REGISTER through
// a caller-controlled private sink; subsequent refreshes cannot replay it.
func RunUpstreamObserved(ctx context.Context, service serviceconfig.Config, roots *x509.CertPool, bindIP string, onFirstRegistered, onFirstRefreshed func() error) error {
	verifyTLS, err := serviceconfig.TLSClient(service, roots)
	if err != nil {
		return errors.New("provider-neutral SIP TLS config refused")
	}
	settings := Config{
		Host: service.UpstreamHost, BindHost: bindIP, BindPort: int(service.BindPort),
		Port: int(service.UpstreamPort), ServerName: service.UpstreamTLSName,
		Roots: roots, TLS: verifyTLS,
		Username: service.UpstreamUsername, Password: service.UpstreamPassword,
		Expiry: 90 * time.Second, Refresh: 45 * time.Second,
		RetryMin: 2 * time.Second, RetryMax: 10 * time.Second, Timeout: 5 * time.Second,
		OnFirstRegistered: onFirstRegistered,
		OnFirstRefreshed:  onFirstRefreshed,
	}
	if !settings.valid() {
		return errors.New("provider-neutral SIP registration config refused")
	}
	return Run(ctx, settings)
}

func wait(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func fatal(err error) bool {
	if err == nil {
		return false
	}
	var response *diago.RegisterResponseError
	if errors.As(err, &response) {
		return response.StatusCode() == 401 || response.StatusCode() == 403 || response.StatusCode() == 407
	}
	var hostname *x509.HostnameError
	var authority x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var verify *tls.CertificateVerificationError
	var alert tls.AlertError
	return errors.As(err, &hostname) || errors.As(err, &authority) ||
		errors.As(err, &invalid) || errors.As(err, &verify) || errors.As(err, &alert)
}

// Check is an offline preflight for the local-only M1 registration settings.
func Check(c Config) error {
	if !c.valid() {
		return fmt.Errorf("invalid local registration configuration")
	}
	return nil
}
