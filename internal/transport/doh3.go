package transport

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// DoH3 is a DNS-over-HTTP/3 client (RFC 8484 over HTTP/3).
type DoH3 struct {
	cfg   Config
	url   string
	rt    *http3.Transport
	httpc *http.Client

	redials
}

// NewDoH3 returns a DoH3 client for cfg.
func NewDoH3(cfg Config) *DoH3 {
	u := &DoH3{
		cfg: cfg,
		url: "https://" + cfg.ServerName + "/dns-query",
	}

	u.rt = &http3.Transport{
		TLSClientConfig: cfg.tlsConfig(http3.NextProtoH3),
		QUICConfig:      cfg.quicConfig(),
		// Pin every dial to the target address so no separate resolution or
		// connection to any other host can happen.
		Dial: func(
			ctx context.Context,
			_ string,
			tlsCfg *tls.Config,
			qCfg *quic.Config,
		) (*quic.Conn, error) {
			u.mark()

			return quic.DialAddrEarly(ctx, cfg.Addr.String(), tlsCfg, qCfg)
		},
	}
	u.httpc = &http.Client{Transport: u.rt, Timeout: cfg.Timeout}

	return u
}

// Address reports the human-readable upstream address.
func (u *DoH3) Address() string {
	return u.url
}

// Close releases the HTTP/3 transport.
func (u *DoH3) Close() error {
	return u.rt.Close()
}

// Exchange sends req as a GET with the wire-format query in the dns parameter
// (RFC 8484, section 4.1).
func (u *DoH3) Exchange(req *dns.Msg) (*dns.Msg, error) {
	packed, err := zeroID(req).Pack()
	if err != nil {
		return nil, fmt.Errorf("packing query: %w", err)
	}

	q := base64.RawURLEncoding.EncodeToString(packed)

	httpReq, err := http.NewRequest(http.MethodGet, u.url+"?dns="+q, nil)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	httpReq.Header.Set("Accept", "application/dns-message")

	resp, err := u.httpc.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("requesting %s: %w", u.url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	out := &dns.Msg{}
	if err = out.Unpack(body); err != nil {
		return nil, fmt.Errorf("unpacking response: %w", err)
	}

	return out, nil
}
