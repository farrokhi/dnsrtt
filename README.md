# dnsrtt

[![CI](https://github.com/farrokhi/dnsrtt/actions/workflows/ci.yml/badge.svg)](https://github.com/farrokhi/dnsrtt/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/farrokhi/dnsrtt)](https://github.com/farrokhi/dnsrtt/releases)
[![Go version](https://img.shields.io/github/go-mod/go-version/farrokhi/dnsrtt)](go.mod)
[![License](https://img.shields.io/github/license/farrokhi/dnsrtt)](LICENSE)

## TL;DR

```
go install github.com/farrokhi/dnsrtt@latest
dnsrtt quad9
```

That sends 50 queries each over plain DNS, DNS-over-QUIC and DNS-over-HTTPS/3
to the same Quad9 server and prints a latency table per transport. The point is
to see what an encrypted transport costs you compared to plain DNS. Prebuilt
binaries are on the
[releases page](https://github.com/farrokhi/dnsrtt/releases) if you would
rather not build anything.

## What it does

`dnsrtt` is a small benchmark that compares the per-query latency of different
DNS transports against the same resolver. It sends a fixed number of queries
over each selected transport (Do53, DoT, DoQ, DoH2, DoH3) and reports the
latency distribution along with how many times the underlying connection had to
be re-established.

Every transport is pinned to the same server IP through a static bootstrap, so
the only thing that changes between rows is the transport on the wire. Do53,
DoT and DoH2 use [AdGuardTeam/dnsproxy](https://github.com/AdguardTeam/dnsproxy)
directly. DoQ and DoH3 use native [quic-go](https://github.com/quic-go/quic-go)
clients so the QUIC packet size and handshake timeout can be tuned to the path
(see [Timeouts and MTU](#timeouts-and-mtu)); dnsproxy does not expose those. In
all cases there is no resolver selection or load balancing between the
measurement and the network.

## Why this tool exists

This started as an investigation into why an AdGuard Home dashboard reported a
DNS-over-QUIC upstream averaging around > 60 ms while a DNS-over-HTTPS/3 upstream
to the same Quad9 host averaged around < 20 ms. The suspicion was that the DoQ
client opened a new QUIC connection, with a full TLS handshake, on every query.

## Does the latency really matter?

When the connection is warm, the transports are more or less equal
(unless you are a nitpicker). The additional latency in the dashboard
average comes from connection re-establishment, which is expensive for
encrypted protocols. DoQ reconnects tend to be extra costly compared to
DoH3, which sends its query as QUIC 0-RTT early data, so its startup
cost is lower than the other encrypted transports.

## Install

Prebuilt binaries for Linux, macOS, FreeBSD and Windows (amd64 and arm64) are
on the [releases page](https://github.com/farrokhi/dnsrtt/releases). Or install
with the Go toolchain:

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
-t, --timeout duration     per-query timeout (default: measured from path RTT)
    --mtu int              pin the path MTU for QUIC packet sizing (default: RFC 1200-byte floor, grown by PMTUD)
-T, --transports strings   transports to test: do53,dot,doq,doh2,doh3 (default do53,doq,doh3)
    --no-warmup            do not send an untimed warm-up query first
-v, --version              print version and exit
```

Not every provider offers every transport (Cloudflare and Google do not run
DoQ, for example). A transport the server will not accept is skipped after its
first query fails, so the run finishes in about one timeout instead of stalling
on every query.

## Timeouts and MTU

The QUIC transports fail in two ways a fixed configuration cannot handle, so
dnsrtt measures the path first and tunes to it. The header prints the RTT and
the QUIC initial packet size it used.

Latency: an encrypted handshake costs two to three round trips before the
query, and DoH3 must fit all of it in one deadline, so a timeout that suits a
fast link fails on a slow one and looks like a dead transport. dnsrtt sizes the
per-query budget at six times the measured RTT (floor 5s, ceiling 60s); `-t`
overrides it.

Packet size: quic-go's default 1280-byte initial packets become 1308-byte IP
packets that do not fit a tunnel or VPN whose path MTU is smaller, and the drop
is often invisible because the ICMP is filtered. This is why DoQ and DoH3
silently time out on many VPNs while plain DNS still works. dnsrtt sends its
initial packets at QUIC's mandatory 1200-byte floor, which every QUIC-capable
path must carry, and lets quic-go's path MTU discovery grow them afterward.
`--mtu` pins a larger size for a path known to allow it, and QUIC is skipped
when `--mtu` is below the 1200-byte floor.

## Examples

Warm, back-to-back run against the Quad9 preset:

```
$ dnsrtt quad9
resolver=9.9.9.9 host=dns.quad9.net rtt=171.9ms quicpkt=1200B count=50 gap=0s timeout=5s (auto via tcp/443) warmup=true

transport  n   avg      median   p95      min      max      redials  outliers
Do53       50  176.3ms  176.0ms  180.1ms  172.1ms  186.3ms  0        0
DoQ        50  174.7ms  174.7ms  176.9ms  172.8ms  178.3ms  0        0
DoH3       50  175.5ms  175.2ms  178.1ms  173.2ms  180.9ms  0        0
```

A bare IP measures only Do53 and says so:

```
$ dnsrtt 9.9.9.9 -n 8
resolver=9.9.9.9 host=9.9.9.9 rtt=173.4ms quicpkt=1200B count=8 gap=0s timeout=5s (auto via tcp/443) warmup=true
skipping DoQ: needs a hostname, not a bare IP
skipping DoH3: needs a hostname, not a bare IP

transport  n  avg      median   p95      min      max      redials  outliers
Do53       8  176.2ms  175.4ms  179.0ms  174.3ms  179.0ms  0        0
```

A transport the server does not answer is marked unavailable. A bare timeout
cannot tell "not offered" from "port blocked on your path", so the note says so
rather than guessing (Cloudflare does not run DoQ):

```
$ dnsrtt cloudflare -n 5
resolver=1.1.1.1 host=cloudflare-dns.com rtt=170.7ms quicpkt=1200B count=5 gap=0s timeout=5s (auto via tcp/443) warmup=true

transport  n  avg      median   p95      min      max      redials  outliers
Do53       5  178.4ms  178.1ms  184.4ms  173.3ms  184.4ms  0        0
DoQ        unavailable: no response on udp/853 (server may not offer DoQ, or the port is blocked)
DoH3       5  173.8ms  174.0ms  175.4ms  172.6ms  175.4ms  0        0
```

The `--gap` flag inserts an idle sleep between queries so you can watch for
reconnects. Note that the QUIC clients run a 20s keep-alive that pings the
connection, so a moderate gap usually keeps it alive and you see no redial:

```
$ dnsrtt quad9 -T do53,doq,doh3 -n 4 -g 25s
resolver=9.9.9.9 host=dns.quad9.net rtt=167.1ms quicpkt=1200B count=4 gap=25s timeout=5s (auto via tcp/443) warmup=true

transport  n  avg      median   p95      min      max      redials  outliers
Do53       4  173.5ms  172.9ms  176.6ms  172.0ms  176.6ms  0        0
DoQ        4  168.8ms  169.5ms  169.7ms  167.7ms  169.7ms  0        0
DoH3       4  172.7ms  173.9ms  179.4ms  167.3ms  179.4ms  0        0
```

A redial shows up when the server itself drops the connection (a long idle
period, or a server that recycles connections under load). When that happens
the `redials` column ticks up and the reconnecting query lands as an outlier,
and DoQ's reconnect tends to cost more than DoH3's. Numbers depend on your
network path and on how aggressively the server recycles connections, so expect
variation between runs.

## Columns

`avg`, `median`, `p95`, `min`, `max` summarize the successful query latencies.
`redials` counts connection re-establishments after the first connection.
`outliers` counts samples above 1.8x the median, a transport-agnostic proxy for
reconnect cost.

## License

BSD-2-Clause. See [LICENSE](LICENSE). Release archives also carry a
`THIRD-PARTY-NOTICES` file with the licenses of the Go modules linked into the
binary (all permissive: Apache-2.0, BSD, MIT, and Unlicense).
