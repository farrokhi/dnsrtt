package main

import (
	"testing"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/farrokhi/dnsrtt/internal/probe"
	"github.com/miekg/dns"
)

// capabilities is the known transport support of each provider.  Quad9 offers
// every transport; Google and Cloudflare do not run DoQ.  The suite asserts the
// tool reaches exactly these, which also exercises the path-adaptive QUIC
// sizing end to end (the encrypted transports would black-hole on a small-MTU
// path without it).
var capabilities = map[string]map[string]bool{
	"quad9": {
		"do53": true, "dot": true, "doh2": true, "doq": true, "doh3": true,
	},
	"google": {
		"do53": true, "dot": true, "doh2": true, "doq": false, "doh3": true,
	},
	"cloudflare": {
		"do53": true, "dot": true, "doh2": true, "doq": false, "doh3": true,
	},
}

// providerOrder fixes the iteration order for stable test output.
var providerOrder = []string{"quad9", "google", "cloudflare"}

// transportOrder fixes the transport iteration order.
var transportOrder = []string{"do53", "dot", "doh2", "doq", "doh3"}

func TestProviderCapabilities(t *testing.T) {
	if testing.Short() {
		t.Skip("network capability test; skipped under -short")
	}

	for _, provider := range providerOrder {
		t.Run(provider, func(t *testing.T) {
			tgt := measuredTarget(t, provider)

			// If plain DNS cannot reach the provider, the network is down or the
			// path is blocked; skip rather than report false regressions.
			if !reaches(transports["do53"], tgt, false) {
				t.Skipf("%s unreachable over Do53; network likely down", provider)
			}

			for _, key := range transportOrder {
				want := capabilities[provider][key]
				t.Run(key, func(t *testing.T) {
					s := transports[key]
					if got := reaches(s, tgt, want); got != want {
						t.Errorf("%s over %s: reachable=%v, want %v", key, provider, got, want)
					}
				})
			}
		})
	}
}

// measuredTarget resolves a preset and sizes the target to the live path, the
// same way the command does.
func measuredTarget(t *testing.T, provider string) target {
	t.Helper()

	host, ip, _, err := resolveTarget(provider, "", probe.DefaultBudget)
	if err != nil {
		t.Fatalf("resolving %s: %v", provider, err)
	}

	path := probe.Measure(ip)
	timeout := probe.DefaultBudget
	if path.RTTOK {
		timeout = probe.Budget(path.RTT)
	}

	return target{host: host, ip: ip, timeout: timeout, packetSize: probe.MinDatagram}
}

// reaches reports whether one query over s succeeds.  Cases expected to succeed
// are retried, so a single dropped packet does not fail the suite; cases
// expected to fail are tried once.
func reaches(s spec, tgt target, expectSuccess bool) bool {
	u, err := s.open(tgt)
	if err != nil {
		return false
	}
	defer func() { _ = u.Close() }()

	attempts := 1
	if expectSuccess {
		attempts = 3
	}

	for range attempts {
		if exchangeOK(u) {
			return true
		}
	}

	return false
}

// exchangeOK sends one A query and reports whether a response came back.
func exchangeOK(u upstream.Upstream) bool {
	req := &dns.Msg{}
	req.SetQuestion(dns.Fqdn("google.com"), dns.TypeA)
	req.RecursionDesired = true

	resp, err := u.Exchange(req)

	return err == nil && resp != nil
}
