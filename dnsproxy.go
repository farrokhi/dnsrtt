package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
)

// dnsproxyUpstream wraps a dnsproxy upstream so it can report re-dials, which
// dnsproxy only exposes through its debug log.
type dnsproxyUpstream struct {
	upstream.Upstream
	log *bytes.Buffer
}

// redialMarkers are the dnsproxy debug log lines that mark a new connection
// after the first one.
var redialMarkers = []string{
	"recreating the quic connection", // see dnsproxy upstream/doq.go
	"recreating the http client",     // see dnsproxy upstream/doh.go
}

// Redials tallies re-dial markers captured in the debug log.
func (d *dnsproxyUpstream) Redials() (n int) {
	log := d.log.String()
	for _, m := range redialMarkers {
		n += strings.Count(log, m)
	}

	return n
}

// openDNSProxy builds a dnsproxy upstream pinned to ip via a static bootstrap.
func openDNSProxy(
	addr string,
	ip netip.Addr,
	timeout time.Duration,
	httpVersions []upstream.HTTPVersion,
) (upstream.Upstream, error) {
	log := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(log, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	u, err := upstream.AddressToUpstream(addr, &upstream.Options{
		Logger:       logger,
		Timeout:      timeout,
		Bootstrap:    upstream.StaticResolver{ip},
		HTTPVersions: httpVersions,
	})
	if err != nil {
		return nil, fmt.Errorf("creating upstream: %w", err)
	}

	return &dnsproxyUpstream{Upstream: u, log: log}, nil
}
