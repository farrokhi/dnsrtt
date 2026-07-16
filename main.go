// Command dnsrtt compares the per-query latency of different DNS transports
// (Do53, DoT, DoQ, DoH2, DoH3) against the same resolver, so the only variable
// is the transport on the wire.
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

// presets are the built-in providers, quad9 first.  buildTargets and the help
// text iterate this slice so the order is stable.
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

// transportBuilder turns a TLS hostname into a target.  The resolver IP is
// pinned separately via the bootstrap, so every transport hits the same server.
type transportBuilder func(host string) bench.Target

// transports maps a CLI key to the target it builds.
var transports = map[string]transportBuilder{
	"do53": func(host string) bench.Target {
		return bench.Target{Name: "Do53", Addr: host + ":53"}
	},
	"dot": func(host string) bench.Target {
		return bench.Target{Name: "DoT", Addr: "tls://" + host + ":853"}
	},
	"doq": func(host string) bench.Target {
		return bench.Target{Name: "DoQ", Addr: "quic://" + host + ":853"}
	},
	"doh2": func(host string) bench.Target {
		return bench.Target{
			Name:         "DoH2",
			Addr:         "https://" + host + ":443/dns-query",
			HTTPVersions: []upstream.HTTPVersion{upstream.HTTPVersion2},
		}
	},
	"doh3": func(host string) bench.Target {
		return bench.Target{
			Name:         "DoH3",
			Addr:         "https://" + host + ":443/dns-query",
			HTTPVersions: []upstream.HTTPVersion{upstream.HTTPVersion3},
		}
	},
}

// encryptedKeys are the transport keys that need a TLS hostname and so cannot
// run against a bare IP target.
var encryptedKeys = map[string]bool{"dot": true, "doq": true, "doh2": true, "doh3": true}

func main() {
	var (
		ipOverride string
		count      int
		gap        time.Duration
		timeout    time.Duration
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
		RunE: func(_ *cobra.Command, args []string) error {
			host, ip, encrypted, err := resolveTarget(args[0], ipOverride)
			if err != nil {
				return err
			}

			targets, skipped, err := buildTargets(transList, host, encrypted)
			if err != nil {
				return err
			}

			cfg := bench.Config{
				ResolverIP: ip,
				Count:      count,
				Gap:        gap,
				Timeout:    timeout,
				Warmup:     !noWarmup,
				Names:      defaultNames,
			}

			printHeader(cfg, host, skipped)
			results := bench.Run(cfg, targets)
			printReport(results)

			return nil
		},
	}

	f := root.Flags()
	f.StringVar(&ipOverride, "ip", "", "pin the server IP for a hostname/preset target (e.g. a specific PoP)")
	f.IntVarP(&count, "count", "n", 50, "timed queries per transport")
	f.DurationVarP(&gap, "gap", "g", 0, "idle sleep between queries (e.g. 25s) to observe re-dials")
	f.DurationVarP(&timeout, "timeout", "t", 5*time.Second, "per-query timeout")
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
func resolveTarget(target, ipOverride string) (host string, ip netip.Addr, encrypted bool, err error) {
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
		ip, err = resolveHost(host)
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
func resolveHost(host string) (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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

// buildTargets resolves the requested transport keys into targets.  When the
// target is a bare IP (encrypted is false), encrypted transports are dropped
// and returned in skipped so the caller can note them.
func buildTargets(keys []string, host string, encrypted bool) (targets []bench.Target, skipped []string, err error) {
	targets = make([]bench.Target, 0, len(keys))
	for _, k := range keys {
		key := strings.ToLower(strings.TrimSpace(k))
		b, ok := transports[key]
		if !ok {
			return nil, nil, fmt.Errorf("unknown transport %q (have: do53,dot,doq,doh2,doh3)", k)
		}

		if !encrypted && encryptedKeys[key] {
			skipped = append(skipped, b(host).Name)

			continue
		}

		targets = append(targets, b(host))
	}

	if len(targets) == 0 {
		return nil, nil, fmt.Errorf("no transports to run: a bare IP target supports only do53")
	}

	return targets, skipped, nil
}

// printHeader describes the run parameters.
func printHeader(cfg bench.Config, host string, skipped []string) {
	fmt.Printf(
		"resolver=%s host=%s count=%d gap=%s timeout=%s warmup=%t\n",
		cfg.ResolverIP, host, cfg.Count, cfg.Gap, cfg.Timeout, cfg.Warmup,
	)

	if len(skipped) > 0 {
		fmt.Printf("skipping %s: encrypted transports need a hostname, not a bare IP\n",
			strings.Join(skipped, ", "))
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
			fmt.Fprintf(w, "%s\tskipped: %v\n", s.Name, s.ProbeErr)

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
