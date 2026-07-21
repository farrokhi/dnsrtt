// Package probe measures a baseline round-trip time to a resolver so callers
// can size timeouts to the path.  A fixed timeout cannot tell a consistently
// slow link apart from a dead one.
package probe

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/miekg/dns"
)

// stepCap bounds each attempt so a filtered path does not stall startup.
const stepCap = 3 * time.Second

// samples per method; the minimum is kept so one delayed packet does not
// inflate every timeout for the whole run.
const samples = 2

// Path describes what was learned about the route to a resolver.
type Path struct {
	// RTT is the lowest round-trip time observed.  Only meaningful when RTTOK.
	RTT time.Duration

	// Method names the probe that succeeded, e.g. "tcp/443".
	Method string

	// RTTOK reports whether any probe in the chain succeeded.
	RTTOK bool
}

// Measure characterizes the path to ip, currently its round-trip time.
func Measure(ip netip.Addr) (p Path) {
	if rtt, method, ok := baseline(ip); ok {
		p.RTT, p.Method, p.RTTOK = rtt, method, true
	}

	return p
}

// method is one step of the fallback chain.
type method struct {
	name string
	run  func(netip.Addr) (time.Duration, error)
}

// chain is ordered by how likely each probe is to survive a filtered path.
var chain = []method{
	{"tcp/443", func(ip netip.Addr) (time.Duration, error) { return tcpRTT(ip, 443) }},
	{"tcp/853", func(ip netip.Addr) (time.Duration, error) { return tcpRTT(ip, 853) }},
	{"udp/53", udpDNSRTT},
}

// baseline measures the round-trip time to ip, trying each probe in turn and
// returning the first that succeeds.
func baseline(ip netip.Addr) (rtt time.Duration, method string, ok bool) {
	for _, m := range chain {
		best, found := bestOf(ip, m.run)
		if found {
			return best, m.name, true
		}
	}

	return 0, "", false
}

// bestOf runs f up to samples times and keeps the lowest successful result.
func bestOf(ip netip.Addr, f func(netip.Addr) (time.Duration, error)) (best time.Duration, ok bool) {
	for range samples {
		d, err := f(ip)
		if err != nil {
			continue
		}

		if !ok || d < best {
			best, ok = d, true
		}
	}

	return best, ok
}

// tcpRTT times a TCP handshake, which costs exactly one round trip.
func tcpRTT(ip netip.Addr, port uint16) (time.Duration, error) {
	addr := net.JoinHostPort(ip.String(), fmt.Sprint(port))

	start := time.Now()
	conn, err := net.DialTimeout("tcp", addr, stepCap)
	elapsed := time.Since(start)

	if err != nil {
		return 0, err
	}
	_ = conn.Close()

	return elapsed, nil
}

// udpDNSRTT times a plain DNS query, the fallback when TCP is unavailable.
func udpDNSRTT(ip netip.Addr) (time.Duration, error) {
	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn("."), dns.TypeNS)

	c := &dns.Client{Net: "udp", Timeout: stepCap}

	_, rtt, err := c.Exchange(req, net.JoinHostPort(ip.String(), "53"))
	if err != nil {
		return 0, err
	}

	return rtt, nil
}
