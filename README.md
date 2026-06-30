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
dnsrtt TARGET [flags]
```

`TARGET` is required and decides which resolver you measure. It can be one of
three things:

- a provider preset (`quad9`, `cloudflare`, `google`, `adguard`), which carries
  a known hostname and a pinned anycast IP;
- a resolver hostname (e.g. `dns.quad9.net`), whose IP is resolved once and then
  pinned for every transport;
- a bare IP (e.g. `9.9.9.9`), which runs Do53 only. The encrypted transports
  need a hostname to present as the TLS server name, so they are skipped with a
  note.

The IP and the TLS name always come from the same target, so they cannot
disagree. That matters because an encrypted upstream validates the server's
certificate against the hostname: a mismatched pair fails the handshake. If you
need to test a specific point of presence, pass `--ip` to pin the address a
hostname or preset resolves to.

Flags:

```
    --ip string            pin the server IP for a hostname/preset target (e.g. a specific PoP)
-n, --count int            timed queries per transport (default 50)
-g, --gap duration         idle sleep between queries (e.g. 25s) to observe re-dials
-t, --timeout duration     per-query timeout (default 5s)
-T, --transports strings   transports to test: do53,dot,doq,doh2,doh3 (default do53,doq,doh3)
    --no-warmup            do not send an untimed warm-up query first
-v, --version              print version and exit
```

Not every provider offers every transport (Cloudflare and Google do not run
DoQ, for example). A transport the server will not accept is skipped after its
first query fails, so the run finishes in about one timeout instead of stalling
on every query.

## Examples

Warm, back-to-back run against the Quad9 preset:

```
$ dnsrtt quad9
resolver=9.9.9.9 host=dns.quad9.net count=50 gap=0s timeout=5s warmup=true

transport  n   avg     median  p95     min     max     redials  outliers
Do53       50  13.9ms  13.8ms  15.8ms  11.8ms  16.3ms  0        0
DoQ        50  11.8ms  11.7ms  12.9ms  10.6ms  16.6ms  0        0
DoH3       50  13.3ms  13.0ms  17.1ms  11.1ms  19.3ms  0        0
```

A bare IP measures only Do53 and says so:

```
$ dnsrtt 9.9.9.9 -n 8
resolver=9.9.9.9 host=9.9.9.9 count=8 gap=0s timeout=5s warmup=true
skipping DoQ, DoH3: encrypted transports need a hostname, not a bare IP

transport  n  avg     median  p95     min     max     redials  outliers
Do53       8  15.2ms  14.9ms  17.9ms  13.9ms  17.9ms  0        0
```

The `--gap` flag inserts an idle sleep between queries so you can watch for
reconnects. Note that the QUIC clients run a 20s keep-alive that pings the
connection, so a moderate gap usually keeps it alive and you see no redial:

```
$ dnsrtt quad9 -T do53,doq,doh3 -n 4 -g 25s
resolver=9.9.9.9 host=dns.quad9.net count=4 gap=25s timeout=5s warmup=true

transport  n  avg     median  p95     min     max     redials  outliers
Do53       4  15.8ms  16.0ms  17.7ms  14.0ms  17.7ms  0        0
DoQ        4  13.6ms  13.4ms  16.4ms  12.3ms  16.4ms  0        0
DoH3       4  16.5ms  16.3ms  18.7ms  14.8ms  18.7ms  0        0
```

A redial shows up when the server itself drops the connection (a long idle
period, or a server that recycles connections under load). When that happens
the `redials` column ticks up and the reconnecting query lands as an outlier,
and DoQ's reconnect tends to cost more than DoH3's. Numbers depend on your
network path and on how aggressively the server recycles connections, so expect
variation between runs.

## Columns

`avg`, `median`, `p95`, `min`, `max` summarize the successful query latencies.
`redials` counts connection re-establishments seen in the dnsproxy debug log
after the first connection. `outliers` counts samples above 1.8x the median, a
transport-agnostic proxy for reconnect cost.

## License

BSD-2-Clause. See [LICENSE](LICENSE).
