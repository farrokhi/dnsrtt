// Package transport implements DNS-over-QUIC and DNS-over-HTTP/3 clients
// directly on quic-go.  dnsproxy does not expose quic.Config, so its clients
// cannot adapt their initial packet size to the path MTU or their handshake
// timeout to the round-trip time, which makes them fail outright on tunnels
// and very slow links.
package transport

import (
	"crypto/tls"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// keepAlive matches dnsproxy's QUICKeepAlivePeriod so connection reuse, and
// therefore the re-dial behaviour being measured, stays comparable.
const keepAlive = 20 * time.Second

// Config describes one native QUIC-based upstream.
type Config struct {
	// Addr is the pinned server address; no name resolution happens here.
	Addr netip.AddrPort

	// ServerName is the TLS SNI and certificate name.
	ServerName string

	// Timeout bounds a single exchange.
	Timeout time.Duration

	// PacketSize is the QUIC initial packet size; the RFC floor by default,
	// grown by quic-go's path MTU discovery after the handshake.
	PacketSize int
}

// quicConfig builds the tuned config shared by both transports.
func (c Config) quicConfig() *quic.Config {
	return &quic.Config{
		InitialPacketSize: uint16(c.PacketSize),
		// The handshake needs several round trips, so it must be allowed more
		// time than a single query; quic-go's 5s default is what kills slow
		// links regardless of any deadline the caller sets.
		HandshakeIdleTimeout: c.Timeout,
		MaxIdleTimeout:       c.Timeout + keepAlive,
		KeepAlivePeriod:      keepAlive,
		TokenStore:           quic.NewLRUTokenStore(10, 10),
	}
}

// tlsConfig builds the TLS config for the given ALPN protocols.
func (c Config) tlsConfig(nextProtos ...string) *tls.Config {
	return &tls.Config{
		ServerName:         c.ServerName,
		NextProtos:         nextProtos,
		ClientSessionCache: tls.NewLRUClientSessionCache(64),
		MinVersion:         tls.VersionTLS13,
	}
}

// redials counts connection establishments after the first one.
type redials struct {
	n     atomic.Int64
	first sync.Once
}

// mark records a connection establishment, ignoring the initial one.
func (r *redials) mark() {
	counted := false
	r.first.Do(func() { counted = true })

	if !counted {
		r.n.Add(1)
	}
}

// Redials reports how many times the connection was re-established.
func (r *redials) Redials() int {
	return int(r.n.Load())
}

// zeroID copies req with the ID zeroed, as both DoQ (RFC 9250, section 4.2.1)
// and DoH (RFC 8484, section 4.1) require.
func zeroID(req *dns.Msg) *dns.Msg {
	out := req.Copy()
	out.Id = 0

	return out
}
