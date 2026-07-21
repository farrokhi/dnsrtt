// Package bench measures and compares per-query latency of different DNS
// transports against one resolver.  It is transport-agnostic: each target
// supplies an [upstream.Upstream], so the same loop times a dnsproxy client and
// a native quic-go client identically.
package bench

import (
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
)

// Target is a single transport endpoint to measure.
type Target struct {
	// Name is the short label shown in the report, e.g. "DoQ".
	Name string

	// Open builds the upstream to measure.  A target owns its own transport,
	// timeout and connection, so the loop only has to time [upstream.Exchange].
	Open func() (upstream.Upstream, error)
}

// RedialCounter is implemented by upstreams that can report how many times they
// re-established their connection during a run.
type RedialCounter interface {
	Redials() int
}

// Config holds the parameters shared by every target in a run.
type Config struct {
	// Count is the number of timed queries sent per target.
	Count int

	// Gap is the idle sleep inserted between consecutive queries.  A non-zero
	// gap is used to observe whether a transport re-dials its connection after
	// sitting idle.
	Gap time.Duration

	// Warmup, when true, sends one untimed query first so the initial handshake
	// is not counted in the samples.
	Warmup bool

	// Names is the rotating set of query names.  Popular, cacheable names keep
	// server-side recursion out of the measurement and leave mostly transport
	// round-trip time.
	Names []string
}

// Result holds the raw measurements for a single target.
type Result struct {
	// Name mirrors the originating [Target.Name].
	Name string

	// Durations are the per-query latencies of the successful queries.
	Durations []time.Duration

	// Errors is the number of failed queries.
	Errors int

	// Redials is the number of connection re-establishments after the first.
	Redials int

	// SetupErr is set when the target could not be constructed at all.
	SetupErr error

	// ProbeErr is set when the first query to the target failed, e.g. a TLS
	// handshake the server rejects or a transport it does not support.  When it
	// is set the timed loop is skipped so a dead transport returns after one
	// timeout instead of count*timeout.
	ProbeErr error
}

// Run measures every target in order using the shared config and returns one
// [Result] per target.
func Run(cfg Config, targets []Target) (results []Result) {
	results = make([]Result, 0, len(targets))
	for _, t := range targets {
		results = append(results, runTarget(cfg, t))
	}

	return results
}

// runTarget opens the upstream for t and sends cfg.Count timed queries.
func runTarget(cfg Config, t Target) (res Result) {
	res.Name = t.Name

	u, err := t.Open()
	if err != nil {
		res.SetupErr = err

		return res
	}
	defer func() { _ = u.Close() }()

	if cfg.Warmup {
		// The warm-up doubles as a reachability probe: if the first exchange
		// fails (e.g. a TLS name mismatch or an unsupported transport), give up
		// on this target instead of timing out on every query.
		if _, err = u.Exchange(newReq(cfg.Names[0])); err != nil {
			res.ProbeErr = err

			return res
		}
	}

	res.Durations = make([]time.Duration, 0, cfg.Count)
	for i := range cfg.Count {
		if cfg.Gap > 0 && i > 0 {
			time.Sleep(cfg.Gap)
		}

		req := newReq(cfg.Names[i%len(cfg.Names)])

		start := time.Now()
		_, err = u.Exchange(req)
		elapsed := time.Since(start)

		if err != nil {
			// Without a warm-up probe, the first failing query stands in for it
			// so an unreachable transport still aborts early.
			if i == 0 && !cfg.Warmup {
				res.ProbeErr = err

				return res
			}

			res.Errors++

			continue
		}

		res.Durations = append(res.Durations, elapsed)
	}

	if rc, ok := u.(RedialCounter); ok {
		res.Redials = rc.Redials()
	}

	return res
}

// newReq builds a recursive A query for name.
func newReq(name string) (req *dns.Msg) {
	req = &dns.Msg{}
	req.SetQuestion(dns.Fqdn(name), dns.TypeA)
	req.RecursionDesired = true

	return req
}
