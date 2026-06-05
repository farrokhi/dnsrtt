# dnsrtt

`dnsrtt` is a small benchmark that compares the per-query latency of different
DNS transports against the same resolver. It sends a fixed number of queries
over each selected transport (Do53, DoT, DoQ, DoH2, DoH3) and reports the
latency distribution along with how many times the underlying connection had to
be re-established.

Every transport is pinned to the same server IP through a static
bootstrap, therefore the only thing that changes between rows is the
transport on the wire. This tool uses
[AdGuardTeam/dnsproxy](https://github.com/AdguardTeam/dnsproxy)
, which means there is no resolver selection or load balancing
 between the measurement and the network.

## Why this tool exists

This started as an investigation into why an AdGuard Home dashboard reported a
DNS-over-QUIC upstream averaging around > 60 ms while a DNS-over-HTTPS/3 upstream
to the same Quad9 host averaged around < 20 ms. The suspicion was that the DoQ
client opened a new QUIC connection, with a full TLS handshake, on every query.

## Does the latency really matter?

When the connection is warm, the transports are more or less equal
(unless you are a nitpicker). The additional latency in the dashboard
average comes from connection re-establishment, which is encrypted
protocol is very expensive.
DoQ reconnect tends to be extra expensive compared to DoH3 which sends
its query as QUIC 0-RTT early data and so the startup cost is lower than
other encrypted transport protocols. 

## Install

```
go install github.com/farrokhi/dnsrtt@latest
```

Or build from a checkout:

```
go build -o dnsrtt .
```

## Usage

```
dnsrtt [flags]
```

Flags:

```
-r, --resolver string      resolver IP every transport is pinned to (default "9.9.9.10")
-H, --hostname string      TLS server name for encrypted transports (default "dns10.quad9.net")
-n, --count int            timed queries per transport (default 50)
-g, --gap duration         idle sleep between queries (e.g. 25s) to observe re-dials
-t, --timeout duration     per-query timeout (default 5s)
-T, --transports strings   transports to test: do53,dot,doq,doh2,doh3 (default do53,doq,doh3)
    --no-warmup            do not send an untimed warm-up query first
```

The resolver IP is pinned separately from the hostname so that every encrypted
transport reaches the same physical server while still presenting a valid TLS
name. For Quad9 the defaults pair `9.9.9.10` with `dns10.quad9.net`; point both
at another provider to test it instead.

## Examples

Warm, back-to-back run against the default Quad9 resolver:

```
$ dnsrtt
resolver=9.9.9.10 host=dns10.quad9.net count=50 gap=0s timeout=5s warmup=true

transport  n   avg     median  p95     min     max     redials  outliers
Do53       50  14.3ms  13.6ms  23.1ms  11.1ms  25.6ms  0        1
DoQ        50  13.0ms  12.0ms  18.2ms  9.9ms   18.9ms  0        0
DoH3       50  12.6ms  12.4ms  17.1ms  10.2ms  18.8ms  0        0
```

With an idle gap larger than the client keep-alive (20s), the server drops the
connection and the next query reconnects. DoQ pays a visible spike, DoH3 mostly
does not:

```
$ dnsrtt --transports do53,doq,doh3 --count 6 --gap 25s
...
transport  n  avg     median  p95     min     max     redials  outliers
Do53       6  13.7ms  13.9ms  15.1ms  12.2ms  15.1ms  0        0
DoQ        6  24.6ms  12.4ms  83.6ms  11.1ms  83.6ms  1        1
DoH3       5  13.8ms  12.7ms  19.6ms  11.5ms  19.6ms  1        0
```

Numbers depend on your network path and on how aggressively the server recycles
connections, so expect variation between runs.

## Columns

`avg`, `median`, `p95`, `min`, `max` summarize the successful query latencies.
`redials` counts connection re-establishments seen in the dnsproxy debug log
after the first connection. `outliers` counts samples above 1.8x the median, a
transport-agnostic proxy for reconnect cost.

## License

BSD-2-Clause. See [LICENSE](LICENSE).
