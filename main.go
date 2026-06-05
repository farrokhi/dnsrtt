// Command dnsrtt compares the per-query latency of different DNS transports
// (Do53, DoT, DoQ, DoH2, DoH3) against the same resolver, so the only variable
// is the transport on the wire.
package main

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/farrokhi/dnsrtt/internal/bench"
	"github.com/spf13/cobra"
)

// version is the released version of dnsrtt.
const version = "1.0.0"

// defaultNames is a small rotating set of popular, cacheable domains.  Keeping
// them cached server-side strips recursion variance and leaves mostly transport
// round-trip time.
var defaultNames = []string{
	"google.com", "cloudflare.com", "amazon.com", "microsoft.com",
	"apple.com", "wikipedia.org", "github.com", "netflix.com",
	"youtube.com", "facebook.com",
}

// transportBuilder turns a pinned resolver IP and TLS hostname into a target.
type transportBuilder func(host string) bench.Target

// transports maps a CLI key to the target it builds.  The resolver IP is pinned
// separately via the bootstrap, so every transport hits the same server.
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

func main() {
	var (
		resolver  string
		hostname  string
		count     int
		gap       time.Duration
		timeout   time.Duration
		transList []string
		noWarmup  bool
	)

	root := &cobra.Command{
		Use:     "dnsrtt",
		Version: version,
		Short:   "Compare per-query latency of DNS transports against one resolver",
		Long: "dnsrtt sends a fixed number of queries over each selected DNS\n" +
			"transport (Do53, DoT, DoQ, DoH2, DoH3) to the same resolver and\n" +
			"reports the latency distribution and connection re-dials.  Every\n" +
			"transport is pinned to the same server IP, so the only variable is\n" +
			"the transport itself.",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, _ []string) error {
			ip, err := netip.ParseAddr(resolver)
			if err != nil {
				return fmt.Errorf("invalid --resolver %q: %w", resolver, err)
			}

			targets, err := buildTargets(transList, hostname)
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

			printHeader(cfg, hostname)
			results := bench.Run(cfg, targets)
			printReport(results)

			return nil
		},
	}

	f := root.Flags()
	f.StringVarP(&resolver, "resolver", "r", "9.9.9.10", "resolver IP every transport is pinned to")
	f.StringVarP(&hostname, "hostname", "H", "dns10.quad9.net", "TLS server name for encrypted transports")
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

// buildTargets resolves the requested transport keys into targets.
func buildTargets(keys []string, host string) (targets []bench.Target, err error) {
	targets = make([]bench.Target, 0, len(keys))
	for _, k := range keys {
		b, ok := transports[strings.ToLower(strings.TrimSpace(k))]
		if !ok {
			return nil, fmt.Errorf("unknown transport %q (have: do53,dot,doq,doh2,doh3)", k)
		}

		targets = append(targets, b(host))
	}

	return targets, nil
}

// printHeader describes the run parameters.
func printHeader(cfg bench.Config, host string) {
	fmt.Printf(
		"resolver=%s host=%s count=%d gap=%s timeout=%s warmup=%t\n\n",
		cfg.ResolverIP, host, cfg.Count, cfg.Gap, cfg.Timeout, cfg.Warmup,
	)
}

// printReport prints a one-line summary per target.
func printReport(results []bench.Result) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "transport\tn\tavg\tmedian\tp95\tmin\tmax\tredials\toutliers")

	for _, r := range results {
		s := r.Summarize()
		if s.SetupErr != nil {
			fmt.Fprintf(w, "%s\tsetup error: %v\n", s.Name, s.SetupErr)

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
