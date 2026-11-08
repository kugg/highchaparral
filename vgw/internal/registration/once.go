package registration

// RegisterOnce is a one-use development proof of the same TLS/Diago
// registration path used by vgw. It sends no INVITE and never retries a
// REGISTER at application level. A protocol 401/Digest challenge remains
// part of the single SIP registration transaction.

import (
	"context"
	"errors"
	"time"

	"example.com/ata/voip-gateway/internal/safesip"
	"github.com/emiago/diago"
	"github.com/emiago/sipgo"
	"github.com/emiago/sipgo/sip"
)

type OneShotResult struct {
	Registered   bool
	Unregistered bool
}

func RegisterOnce(ctx context.Context, c Config) (OneShotResult, error) {
	var result OneShotResult
	if ctx == nil || c.Host == "" || !c.valid() {
		return result, errors.New("one-use provider registration configuration refused")
	}
	if !active.CompareAndSwap(false, true) {
		return result, errors.New("provider registration already active in process")
	}
	defer active.Store(false)
	quiet := safesip.Logger
	ua, err := sipgo.NewUA(sipgo.WithUserAgenTLSConfig(c.TLS),
		sipgo.WithUserAgentTransportLayerOptions(sip.WithTransportLayerLogger(quiet)),
		sipgo.WithUserAgentTransactionLayerOptions(
			sip.WithTransactionLayerLogger(quiet),
			sip.WithTransactionLayerUnhandledResponseHandler(func(*sip.Response) {})))
	if err != nil {
		return result, errors.New("one-use SIP user agent unavailable")
	}
	defer ua.Close()
	dg := diago.NewDiago(ua,
		diago.WithTransport(diago.Transport{Transport: "tls", BindHost: c.BindHost, BindPort: c.BindPort}),
		diago.WithLogger(quiet),
		diago.WithServerRequestMiddleware(func(_ sipgo.RequestHandler) sipgo.RequestHandler {
			return func(req *sip.Request, tx sip.ServerTransaction) {
				if req != nil && tx != nil {
					_ = tx.Respond(sip.NewResponseFromRequest(req, sip.StatusServiceUnavailable,
						"No call service", nil))
				}
			}
		}))
	uri := sip.Uri{Scheme: "sips", User: c.Username, Host: c.Host, Port: c.Port}
	uri.UriParams = sip.NewParams()
	uri.UriParams.Add("transport", "tls")
	transaction, err := dg.RegisterTransaction(ctx, uri, diago.RegisterOptions{
		Username: c.Username, Password: c.Password, Expiry: c.Expiry,
	})
	if err != nil {
		return result, errors.New("one-use REGISTER setup unavailable")
	}
	registerCtx, stopRegister := context.WithTimeout(ctx, c.Timeout)
	err = transaction.Register(registerCtx)
	stopRegister()
	if err != nil {
		return result, errors.New("one-use REGISTER rejected or unconfirmed")
	}
	result.Registered = true
	// A confirmed registration is always followed by ONE bounded
	// unregister, even if the parent test deadline just expired.
	stopCtx, stopUnregister := context.WithTimeout(context.Background(), min(c.Timeout, 5*time.Second))
	defer stopUnregister()
	if transaction.Unregister(stopCtx) != nil {
		return result, errors.New("one-use Unregister unconfirmed")
	}
	result.Unregistered = true
	return result, nil
}
