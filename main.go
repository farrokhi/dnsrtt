// Command dnsrtt compares the per-query latency of different DNS transports
// (Do53, DoT, DoQ, DoH2, DoH3) against the same resolver, so the only variable
// is the transport on the wire.  The QUIC transports use native quic-go clients
// tuned to the path (packet size, handshake timeout); the rest use dnsproxy.
package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime/debug"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/farrokhi/dnsrtt/internal/bench"
	"github.com/farrokhi/dnsrtt/internal/probe"
	"github.com/farrokhi/dnsrtt/internal/transport"
	"github.com/spf13/cobra"
)

// version is set at release time via -ldflags "-X main.version=...".
var version = ""

// versionString prefers the release-injected version, then the module version
// Go stamps into binaries built with `go install module@vX.Y.Z`, then "dev".
func versionString() string {
	if version != "" {
		return version
	}

	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}

	return "dev"
}

// lookupTimeout bounds the hostname lookup, which happens before the path can
// be measured and so cannot use the probed budget.
const lookupTimeout = 15 * time.Second

// defaultNames is a small rotating set of popular, cacheable domains.  Keeping
// them cached server-side strips recursion variance and leaves mostly transport
// round-trip time.
var defaultNames = []string{
	"google.com", "cloudflare.com", "amazon.com", "microsoft.com",
	"apple.com", "wikipedia.org", "github.com", "netflix.com",
	"youtube.com", "facebook.com",
}

// preset is a known public resolver: a TLS hostname paired with a canonical
// anycast IP that serves a certificate for it.  Pinning both keeps presets
// self-contained, so selecting one does not depend on system DNS.
type preset struct {
	name string
	host string
	ip   string
}

// presets are the built-in providers, quad9 first.
var presets = []preset{
	{"quad9", "dns.quad9.net", "9.9.9.9"},
	{"cloudflare", "cloudflare-dns.com", "1.1.1.1"},
	{"google", "dns.google", "8.8.8.8"},
	{"adguard", "dns.adguard-dns.com", "94.140.14.14"},
}

// presetNames lists the preset keys in order for help and error messages.
func presetNames() string {
	names := make([]string, len(presets))
	for i, p := range presets {
		names[i] = p.name
	}

	return strings.Join(names, ", ")
}

// target carries everything a transport needs to build its upstream.
type target struct {
	host       string
	ip         netip.Addr
	timeout    time.Duration
	packetSize int
}

// spec describes one transport: how it is built and what it requires.
type spec struct {
	label     string
	encrypted bool // needs a TLS hostname, so cannot run against a bare IP
	quic      bool // rides QUIC, so needs a viable path MTU
	open      func(target) (upstream.Upstream, error)
}

// transports maps a CLI key to its spec.  The QUIC transports use native
// quic-go clients so their packet size and handshake timeout follow the path;
// the rest use dnsproxy, where TCP handles MTU on its own.
var transports = map[string]spec{
	"do53": {label: "Do53", open: func(t target) (upstream.Upstream, error) {
		return openDNSProxy(t.host+":53", t.ip, t.timeout, nil)
	}},
	"dot": {label: "DoT", encrypted: true, open: func(t target) (upstream.Upstream, error) {
		return openDNSProxy("tls://"+t.host+":853", t.ip, t.timeout, nil)
	}},
	"doh2": {label: "DoH2", encrypted: true, open: func(t target) (upstream.Upstream, error) {
		return openDNSProxy("https://"+t.host+":443/dns-query", t.ip, t.timeout,
			[]upstream.HTTPVersion{upstream.HTTPVersion2})
	}},
	"doq": {label: "DoQ", encrypted: true, quic: true, open: func(t target) (upstream.Upstream, error) {
		return transport.NewDoQ(quicConfig(t, 853)), nil
	}},
	"doh3": {label: "DoH3", encrypted: true, quic: true, open: func(t target) (upstream.Upstream, error) {
		return transport.NewDoH3(quicConfig(t, 443)), nil
	}},
}

// quicConfig builds the native transport config for a QUIC target on port.
func quicConfig(t target, port uint16) transport.Config {
	return transport.Config{
		Addr:       netip.AddrPortFrom(t.ip, port),
		ServerName: t.host,
		Timeout:    t.timeout,
		PacketSize: t.packetSize,
	}
}

// skip records a transport that was not run and why.
type skip struct {
	name   string
	reason string
}

func main() {
	var (
		ipOverride string
		count      int
		gap        time.Duration
		timeout    time.Duration
		mtu        int
		transList  []string
		noWarmup   bool
	)

	root := &cobra.Command{
		Use:     "dnsrtt TARGET",
		Version: versionString(),
		Short:   "Compare per-query latency of DNS transports against one resolver",
		Long: "dnsrtt sends a fixed number of queries over each selected DNS\n" +
			"transport (Do53, DoT, DoQ, DoH2, DoH3) to the same resolver and\n" +
			"reports the latency distribution and connection re-dials.  Every\n" +
			"transport is pinned to the same server IP, so the only variable is\n" +
			"the transport itself.\n\n" +
			"TARGET is a provider preset (" + presetNames() + "), a resolver\n" +
			"hostname (its IP is resolved once and pinned), or a bare IP (only\n" +
			"Do53 runs; the encrypted transports need a hostname).",
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			host, ip, encrypted, err := resolveTarget(args[0], ipOverride, timeout)
			if err != nil {
				return err
			}

			path := probe.Measure(ip)

			// Sizing the budget to the path keeps a consistently slow link from
			// looking like a dead transport.  An explicit -t wins.
			if !cmd.Flags().Changed("timeout") && path.RTTOK {
				timeout = probe.Budget(path.RTT)
			}

			// The initial QUIC packet must fit the path MTU or the handshake is
			// a black hole.  The interface MTU is only a first-hop upper bound,
			// not the path MTU, so default to the RFC floor (every QUIC path
			// must carry it) and let quic-go grow it via PMTUD.  --mtu pins a
			// larger size for a path known to allow it.
			packetSize, quicOK := probe.MinDatagram, true
			if cmd.Flags().Changed("mtu") {
				packetSize, quicOK = probe.PacketSize(mtu, ip)
			}

			t := target{host: host, ip: ip, timeout: timeout, packetSize: packetSize}
			targets, skips := buildTargets(transList, t, encrypted, quicOK, mtu)
			if len(targets) == 0 {
				return fmt.Errorf("no transports to run")
			}

			cfg := bench.Config{
				Count:  count,
				Gap:    gap,
				Warmup: !noWarmup,
				Names:  defaultNames,
			}

			printHeader(cfg, host, ip, timeout, path, packetSize, cmd.Flags().Changed("timeout"), skips)
			printReport(bench.Run(cfg, targets))

			return nil
		},
	}

	f := root.Flags()
	f.StringVar(&ipOverride, "ip", "", "pin the server IP for a hostname/preset target (e.g. a specific PoP)")
	f.IntVarP(&count, "count", "n", 50, "timed queries per transport")
	f.DurationVarP(&gap, "gap", "g", 0, "idle sleep between queries (e.g. 25s) to observe re-dials")
	f.DurationVarP(&timeout, "timeout", "t", probe.DefaultBudget,
		"per-query timeout (default: measured from path RTT)")
	f.IntVar(&mtu, "mtu", 0, "pin the path MTU for QUIC packet sizing (default: RFC 1200-byte floor, grown by PMTUD)")
	f.StringSliceVarP(&transList, "transports", "T", []string{"do53", "doq", "doh3"},
		"transports to test: do53,dot,doq,doh2,doh3")
	f.BoolVar(&noWarmup, "no-warmup", false, "do not send an untimed warm-up query first")

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// resolveTarget turns the TARGET argument into a (host, pinned IP) pair.  A
// preset name yields both; a bare IP yields the IP as host with encrypted
// false (only Do53 can run); a hostname is resolved to an IP unless ipOverride
// pins one.
func resolveTarget(target, ipOverride string, timeout time.Duration) (host string, ip netip.Addr, encrypted bool, err error) {
	if p, ok := lookupPreset(target); ok {
		host = p.host
		ip = netip.MustParseAddr(p.ip)
	} else if addr, perr := netip.ParseAddr(target); perr == nil {
		// Bare IP: no TLS name to present, so only Do53 can run.  Do53 targets
		// the IP literal directly; encrypted transports are dropped downstream.
		if err = overrideErr(ipOverride); err != nil {
			return "", netip.Addr{}, false, err
		}

		return addr.String(), addr, false, nil
	} else {
		host = target
	}

	if ipOverride != "" {
		ip, err = netip.ParseAddr(ipOverride)
		if err != nil {
			return "", netip.Addr{}, false, fmt.Errorf("invalid --ip %q: %w", ipOverride, err)
		}
	} else if !ip.IsValid() {
		ip, err = resolveHost(host, timeout)
		if err != nil {
			return "", netip.Addr{}, false, err
		}
	}

	return host, ip, true, nil
}

// overrideErr rejects --ip on a bare-IP target, where it would be meaningless.
func overrideErr(ipOverride string) error {
	if ipOverride != "" {
		return fmt.Errorf("--ip cannot be combined with a bare IP target")
	}

	return nil
}

// lookupPreset returns the preset named by key, matched case-insensitively.
func lookupPreset(key string) (preset, bool) {
	key = strings.ToLower(strings.TrimSpace(key))
	for _, p := range presets {
		if p.name == key {
			return p, true
		}
	}

	return preset{}, false
}

// resolveHost looks up host once and returns one address, preferring IPv4 so
// the pinned address matches the common path.
func resolveHost(host string, timeout time.Duration) (netip.Addr, error) {
	deadline := lookupTimeout
	if timeout > deadline {
		deadline = timeout
	}

	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("resolving %q: %w", host, err)
	}

	for _, a := range addrs {
		if a.Is4() {
			return a, nil
		}
	}

	return addrs[0].Unmap(), nil
}

// buildTargets resolves the requested transport keys into targets, skipping the
// encrypted ones on a bare IP and the QUIC ones when the path MTU cannot carry
// QUIC.  Requested order is preserved.
func buildTargets(keys []string, t target, encrypted, quicOK bool, mtu int) (targets []bench.Target, skips []skip) {
	for _, k := range keys {
		key := strings.ToLower(strings.TrimSpace(k))
		s, ok := transports[key]
		if !ok {
			skips = append(skips, skip{key, "unknown transport"})

			continue
		}

		switch {
		case s.encrypted && !encrypted:
			skips = append(skips, skip{s.label, "needs a hostname, not a bare IP"})
		case s.quic && !quicOK:
			skips = append(skips, skip{s.label, quicSkipReason(mtu, t.ip)})
		default:
			s := s
			targets = append(targets, bench.Target{
				Name: s.label,
				Open: func() (upstream.Upstream, error) { return s.open(t) },
			})
		}
	}

	return targets, skips
}

// quicSkipReason explains why a QUIC transport cannot run on this path.
func quicSkipReason(mtu int, ip netip.Addr) string {
	return fmt.Sprintf("path MTU %d carries %dB < %dB QUIC minimum",
		mtu, mtu-probe.Overhead(ip), probe.MinDatagram)
}

// printHeader describes the run parameters.
func printHeader(
	cfg bench.Config,
	host string,
	ip netip.Addr,
	timeout time.Duration,
	path probe.Path,
	packetSize int,
	timeoutSet bool,
	skips []skip,
) {
	rtt, source := "unknown", "user"
	if !timeoutSet && path.RTTOK {
		rtt, source = ms(path.RTT), "auto via "+path.Method
	} else if path.RTTOK {
		rtt = ms(path.RTT)
	}

	quicpkt := "n/a"
	if packetSize > 0 {
		quicpkt = fmt.Sprintf("%dB", packetSize)
	}

	fmt.Printf(
		"resolver=%s host=%s rtt=%s quicpkt=%s count=%d gap=%s timeout=%s (%s) warmup=%t\n",
		ip, host, rtt, quicpkt, cfg.Count, cfg.Gap, timeout, source, cfg.Warmup,
	)

	for _, s := range skips {
		fmt.Printf("skipping %s: %s\n", s.name, s.reason)
	}

	fmt.Println()
}

// printReport prints a one-line summary per target.
func printReport(results []bench.Result) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "transport\tn\tavg\tmedian\tp95\tmin\tmax\tredials\toutliers")

	for _, r := range results {
		s := r.Summarize()
		switch {
		case s.SetupErr != nil:
			fmt.Fprintf(w, "%s\tsetup error: %v\n", s.Name, s.SetupErr)

			continue
		case s.ProbeErr != nil:
			fmt.Fprintf(w, "%s\tunavailable: %s\n", s.Name, explain(s.Name, s.ProbeErr))

			continue
		}

		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%s\t%s\t%s\t%d\t%d\n",
			s.Name, s.N, ms(s.Avg), ms(s.Median), ms(s.P95),
			ms(s.Min), ms(s.Max), s.Redials, s.Outliers,
		)
	}

	_ = w.Flush()
}

// ms formats a duration as milliseconds with one decimal.
func ms(d time.Duration) string {
	return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000)
}
