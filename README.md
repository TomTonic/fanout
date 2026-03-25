# fanout

[![Go Report Card](https://goreportcard.com/badge/github.com/TomTonic/fanout)](https://goreportcard.com/report/github.com/TomTonic/fanout)
![CI](https://github.com/TomTonic/fanout/workflows/ci/badge.svg)
[![Vulnerabilities](https://img.shields.io/endpoint?url=https://gist.githubusercontent.com/TomTonic/b4af9f82c5cc14dd9ef02f3e86f26d32/raw/grype_me-plugin_release.json)](https://gist.github.com/TomTonic/b4af9f82c5cc14dd9ef02f3e86f26d32#file-grype_me-plugin_release-md)

## About This Fork

This is a hardened fork of [networkservicemesh/fanout](https://github.com/networkservicemesh/fanout).

**Why this fork exists:**

1. **Supply-chain security** — The original project at `github.com/networkservicemesh/fanout` pulls in transitive dependencies from the `github.com/networkservicemesh/*` ecosystem. This fork eliminates those dependencies, reducing the attack surface to the minimum required set: CoreDNS, `miekg/dns`, and `quic-go`.
2. **Robustness** — Additional hardening such as connection pooling with liveness checks, retry-on-stream-failure, strict TLS version enforcement, and comprehensive race-detector-enabled tests.
3. **Modern encrypted DNS protocols** — Full support for six DNS transport protocols, including DoH (HTTP/2), DoH3 (HTTP/3 over QUIC), and DoQ (DNS-over-QUIC, RFC 9250), in addition to the plain UDP, TCP, and DoT transports from the original.

## Name

*fanout* — parallel proxying DNS messages to upstream resolvers.

## Description

Each incoming DNS query that hits the CoreDNS fanout plugin will be replicated in parallel to each listed upstream. The first non-negative response from any of the queried DNS servers will be forwarded as a response to the application's DNS request.

## Supported Protocols

| Protocol | RFC | Prefix / Directive | Default Port | Transport |
|----------|-----|--------------------|--------------|-----------|
| DNS/UDP | — | *(plain address)* | 53 | UDP |
| DNS/TCP | — | *(plain address)* + `network TCP` | 53 | TCP |
| DoT (DNS-over-TLS) | [RFC 7858](https://datatracker.ietf.org/doc/html/rfc7858) | `tls://` or `tls` directive | 853/TCP | TLS over TCP |
| DoH (DNS-over-HTTPS) | [RFC 8484](https://datatracker.ietf.org/doc/html/rfc8484) | `https://` | 443/TCP | HTTP/2 over TLS |
| DoH3 (DNS-over-HTTPS/3) | [RFC 8484](https://datatracker.ietf.org/doc/html/rfc8484) + [RFC 9114](https://datatracker.ietf.org/doc/html/rfc9114) | `h3://` | 443/UDP | HTTP/3 over QUIC |
| DoQ (DNS-over-QUIC) | [RFC 9250](https://datatracker.ietf.org/doc/html/rfc9250) | `quic://` | 853/UDP | QUIC (TLS 1.3, ALPN `doq`) |

Upstream addresses are distinguished by their URL prefix:

```
fanout . <plain-host>[:port]        # UDP/TCP  (default)
fanout . tls://<host>[:port]        # DoT
fanout . https://<host>/<path>      # DoH  (HTTP/2)
fanout . h3://<host>/<path>         # DoH3 (HTTP/3 over QUIC)
fanout . quic://<host>[:port]       # DoQ  (RFC 9250, default port 853)
```

You can mix protocols freely in a single `fanout` block. The first successful response wins, regardless of which transport delivered it.

## Syntax

```
fanout FROM TO... {
    tls CERT KEY CA
    tls_servername NAME
    network PROTOCOL
    worker-count COUNT
    policy POLICY
    weighted-random-server-count COUNT
    weighted-random-load-factor FACTOR...
    except DOMAIN...
    except-file FILE
    attempt-count COUNT
    timeout DURATION
    bootstrap IP...
    ecs [CIDR]
    debug
    race
    race-continue-on-error
}
```

* `tls` **CERT** **KEY** **CA** — define the TLS properties for TLS connections. From 0 to 3 arguments can be
  provided with the meaning as described below:
  * `tls` — no client authentication is used, and the system CAs are used to verify the server certificate
  * `tls` **CA** — no client authentication is used, and the file CA is used to verify the server certificate
  * `tls` **CERT** **KEY** — client authentication is used with the specified cert/key pair.
    The server certificate is verified with the system CAs
  * `tls` **CERT** **KEY** **CA** — client authentication is used with the specified cert/key pair.
    The server certificate is verified using the specified CA file
* `tls_servername` **NAME** — allows you to set a server name in the TLS configuration; for instance `9.9.9.9`
  needs this to be set to `dns.quad9.net`. Multiple upstreams are still allowed in this scenario,
  but they have to use the same `tls_servername`. E.g. mixing `9.9.9.9` (Quad9) with `1.1.1.1`
  (Cloudflare) will not work.
* `worker-count` — the number of parallel queries per request. By default equals the count of the upstream list. Use this only to reduce parallel queries per request.
* `policy` — specifies the policy for DNS server selection. The default is `sequential`.
  * `sequential` — select DNS servers one-by-one based on their order
  * `weighted-random` — select DNS servers randomly based on `weighted-random-server-count` and `weighted-random-load-factor`
* `weighted-random-server-count` — the number of DNS servers to be queried. Equals the number of specified upstreams by default. Used only with the `weighted-random` policy.
* `weighted-random-load-factor` — the probability of selecting a server (1–100). Specified in the order of the upstream list. Default is 100 for all servers. Used only with the `weighted-random` policy.
* `network` — specific network protocol for plain upstreams: `tcp`, `udp` (default), or `tcp-tls`.
* `except` — a space-separated list of domains to exclude from proxying.
* `except-file` — path to a file with line-separated domains to exclude from proxying.
* `attempt-count` — the number of failed attempts before considering an upstream to be down. If `0`, the upstream will never be marked as down and the request will run until `timeout`. Default is `3`.
* `timeout` — the maximum time for the entire request. Default is `30s`.
* `bootstrap` **IP...** — one or more IP addresses (with optional `:port`, default port 53) of plain-DNS
  servers used to resolve hostnames in upstream URLs. This is required when DoH, DoH3, or DoQ upstreams
  use hostname-based endpoints (e.g. `dns.nextdns.io`) and the system's default DNS resolver
  might point back at this very CoreDNS instance, creating a circular dependency. The bootstrap
  resolver sends plain-UDP DNS queries to the specified IPs, bypassing the system resolver entirely.
  Only the _hostname resolution_ of upstream endpoints uses the bootstrap servers; regular client
  queries still go through the configured upstreams.
* `ecs` [**CIDR**] — enable EDNS0 Client Subnet ([RFC 7871](https://datatracker.ietf.org/doc/html/rfc7871))
  on bootstrap DNS queries. Requires a prior `bootstrap` directive.
  * Without argument (`ecs`): the local outgoing IP is auto-detected and sent as a /24 (IPv4) or
    /48 (IPv6) prefix. This is the recommended default — it works on laptops, hotel Wi-Fi,
    and dynamically assigned addresses without manual configuration.
  * With argument (`ecs 203.0.113.0/24`): the given CIDR is used verbatim.
  * **When to use:** When the bootstrap resolvers are not on your local network. Without ECS,
    a distant bootstrap resolver (e.g. `9.9.9.11` in Frankfurt) asks the authoritative server
    for `dns.nextdns.io` and receives the IP closest to _Frankfurt_, not to you. With ECS
    enabled, your subnet is forwarded so the authoritative server returns the endpoint closest
    to _you_.
  * **Privacy note:** ECS reveals a prefix of your IP to the bootstrap resolver and, transitively,
    to authoritative name servers. If this is undesirable, simply omit `ecs` — the bootstrap query
    will then be a plain DNS lookup without subnet information.
  * **Which bootstrap IPs support ECS?** Not all resolvers forward ECS to authoritative servers.
    You must use an ECS-enabled resolver for this feature to have any effect:

    | Provider   | Standard (no ECS)          | ECS-enabled                  |
    |------------|----------------------------|------------------------------|
    | Quad9      | `9.9.9.9`, `149.112.112.112` | **`9.9.9.11`**, `149.112.112.11` |
    | Google     | —                          | `8.8.8.8`, `8.8.4.4`        |
    | Cloudflare | `1.1.1.1`, `1.0.0.1`      | _(ECS generally not forwarded)_ |

  * **Why not for forwarded queries?** ECS on bootstrap queries only resolves the _upstream hostname_
    (e.g. `dns.nextdns.io` → optimal anycast IP). For the actual forwarded DNS queries, the upstream sees
    the IP of the fanout instance, not the original downstream client. Propagating per-client ECS through
    this plugin would therefore require explicit client-subnet handling in the request path and — in
    combination with the CoreDNS `cache` plugin — would still be potentially harmful: the cache keys on
    `(qname, qtype, qclass)` without considering ECS subnets, so different clients could receive cached
    answers optimized for someone else's location.
* `debug` — emit per-upstream intermediate request failures through the `fanout` logger so defective upstream attempts remain visible even when another upstream still answers successfully. Expected local cancellations caused by fanout shutting down losing attempts are excluded from these warning lines.
* `race` — gives priority to the first result, whether it is negative or not, as long as it is a valid DNS response.
* `race-continue-on-error` — When enabled together with `race`, fanout does not early-return on erroneous DNS responses such as `SERVFAIL`, but still treats `NOERROR` and `NXDOMAIN` as terminal answers that can end the race immediately. The default is `false`.

## Metrics

If monitoring is enabled (via the *prometheus* plugin) then the following metrics are exported:

* `coredns_fanout_request_count_total{to}` — request attempt count per upstream, including attempts that fail before a DNS response is received.
* `coredns_fanout_request_error_count_total{to, error}` — request attempt count per upstream and bounded upstream error class.
* `coredns_fanout_request_cancel_count_total{to}` — request attempt count per upstream that fanout canceled locally before a final upstream outcome was received.
* `coredns_fanout_request_success_count_total{to}` — request attempt count per upstream that completed with a valid DNS response (transport-level success). This includes responses with any RCODE, e.g. `SERVFAIL` or `NXDOMAIN`, because the upstream did respond with a well-formed DNS packet.
* `coredns_fanout_response_win_count_total{to}` — number of times an upstream's response was the one fanout selected and returned downstream. Because fanout queries multiple upstreams in parallel, several may succeed, but only one response is written to the client per incoming query. A win is counted for any selected response, including non-success RCODEs when no better response was available.
* `coredns_fanout_response_rcode_count_total{to, rcode}` — count of returned RCODEs per upstream.
* `coredns_fanout_request_duration_seconds{to}` — duration of request attempts that completed with a valid DNS response.

Where `to` is one of the upstream servers (**TO** from the config), `rcode` is the returned RCODE
from the upstream, and `error` is one of the bounded classes used by fanout
(for example `connect_failed`, `request_send_failed`, `response_read_failed`, or `response_decode_failed`).

The counters are designed to follow a simple accounting model per upstream:

* `request_count_total = request_error_count_total (summed over error labels) + request_cancel_count_total + request_success_count_total`
* `request_success_count_total = response_rcode_count_total` summed over all `rcode` labels
* `response_win_count_total <= request_success_count_total` (because multiple upstreams may succeed per query but only one is selected)

### Practical interpretation

Use these metrics to identify the best upstream in your environment:

* An upstream with a high `connect_failed` error rate and zero successes is likely blocked by a firewall or misconfigured.
* An upstream with high success but low win rate works fine but is slower than competing upstreams.
* An upstream with high `SERVFAIL` rcode count responds, but cannot resolve queries — check the server itself.
* Compare win rates across upstreams to find the fastest and most reliable one.

### Debug logging

When `debug` logging is enabled, fanout logs only defective upstream attempts and includes the normalized `error_class` field so warning lines can be correlated directly with `request_error_count_total`. Expected local cancellations (i.e. losing race participants) are suppressed to avoid noise. When a request times out (`context deadline exceeded`), the log line includes a `context_error` field to distinguish timeouts from genuine network errors. Without `debug` enabled, final request failures are still logged at ERROR level by the CoreDNS errors plugin, including the upstream endpoint in the error message.

## Examples

### Plain DNS (UDP)

Proxy all requests within `example.org.` to four nameservers. The first positive response wins.

~~~ corefile
example.org {
    fanout . 127.0.0.1:9005 127.0.0.1:9006 127.0.0.1:9007 127.0.0.1:9008
}
~~~

### Plain DNS (TCP)

Send parallel requests to three resolvers via TCP.

~~~ corefile
. {
    fanout . 10.0.0.10:53 10.0.0.11:1053 [2003::1]:53 {
        network TCP
    }
}
~~~

### DNS-over-TLS (DoT)

Proxy all requests to Quad9 using DNS-over-TLS (RFC 7858).
The `tls_servername` is mandatory because `9.9.9.9` can't be used in TLS negotiation.

~~~ corefile
. {
    fanout . tls://9.9.9.9 {
        tls_servername dns.quad9.net
    }
}
~~~

### DNS-over-HTTPS (DoH)

Proxy all requests to Cloudflare via DNS-over-HTTPS (RFC 8484, HTTP/2).

~~~ corefile
. {
    fanout . https://cloudflare-dns.com/dns-query
}
~~~

### DNS-over-HTTPS/3 (DoH3)

Proxy all requests to Cloudflare via DNS-over-HTTPS over HTTP/3 (QUIC).
Use the `h3://` prefix — it is internally converted to an HTTPS URL.

~~~ corefile
. {
    fanout . h3://cloudflare-dns.com/dns-query
}
~~~

### DNS-over-QUIC (DoQ)

Proxy all requests to AdGuard DNS via DNS-over-QUIC (RFC 9250).
The default port is 853/UDP. TLS 1.3 with ALPN token `doq` is enforced automatically.

~~~ corefile
. {
    fanout . quic://dns.adguard-dns.com
}
~~~

### Mixed Protocols

Fan out to multiple upstreams across different transports simultaneously.
The first successful response from any transport wins.

~~~ corefile
. {
    fanout . 1.1.1.1 https://cloudflare-dns.com/dns-query h3://cloudflare-dns.com/dns-query quic://dns.adguard-dns.com:853
}
~~~

### Bootstrap Resolver

When running inside a container whose system DNS points back at CoreDNS itself,
hostname-based upstreams like `dns.nextdns.io` cannot be resolved. The `bootstrap`
directive breaks this circular dependency by resolving upstream hostnames through
the specified plain-DNS servers.

~~~ corefile
. {
    fanout . https://dns.nextdns.io/abc123 h3://dns.nextdns.io/abc123 quic://DoQ-abc123.dns.nextdns.io:853 {
        bootstrap 9.9.9.11 149.112.112.11
    }
}
~~~

### Bootstrap with ECS (Auto-Detect)

When the bootstrap resolvers are in a different geographic region, EDNS0 Client
Subnet ensures the authoritative server returns the upstream's anycast endpoint
closest to you — not to the bootstrap resolver. With `ecs` (no argument), the
local IP is auto-detected.

~~~ corefile
. {
    fanout . https://dns.nextdns.io/abc123 h3://dns.nextdns.io/abc123 quic://DoQ-abc123.dns.nextdns.io:853 {
        bootstrap 9.9.9.11 149.112.112.11
        ecs
        race
        race-continue-on-error
    }
}
~~~

### Bootstrap with Explicit ECS Subnet

If you need precise control over which subnet is announced (e.g. in a data centre
with fixed IP ranges), pass a CIDR explicitly.

~~~ corefile
. {
    fanout . https://dns.nextdns.io/abc123 {
        bootstrap 8.8.8.8
        ecs 203.0.113.0/24
    }
}
~~~

### Excluding Domains

Proxy everything except requests to `example.org`.

~~~ corefile
. {
    fanout . 10.0.0.10:1234 {
        except example.org
    }
}
~~~

### Limiting Workers

Send parallel requests to five resolvers but limit to two concurrent workers.

~~~ corefile
. {
    fanout . 10.0.0.10:53 10.0.0.11:53 10.0.0.12:53 10.0.0.13:1053 10.0.0.14:1053 {
        worker-count 2
    }
}
~~~

### Race Mode

Multiple upstreams are configured but one of them is down. With `race` enabled, the first result is returned immediately instead of waiting for timeouts.

~~~ corefile
. {
    fanout . 10.0.0.10:53 10.0.0.11:53 10.0.0.12:53 {
        race
    }
}
~~~

By default `race` will return the first DNS response that arrives as long as it is a
valid DNS result — this may be a non-success RCODE such as `SERVFAIL` or `NXDOMAIN`.

If you prefer to keep the latency benefits of `race` but avoid early-returning on upstream error responses,
enable `race-continue-on-error`. When both `race` and `race-continue-on-error` are set, fanout will
still end the race immediately for `NOERROR` and `NXDOMAIN`, but it will keep waiting when a fast
upstream returns an error such as `SERVFAIL`.

Example: A fast upstream returns `SERVFAIL` and a slow upstream returns `NOERROR`. With
`race` alone the user receives `SERVFAIL`; with `race` and `race-continue-on-error` set the
user receives a successful domain name resolution (if it arrives before the request timeout).

~~~ corefile
. {
    fanout . 10.0.0.10:53 10.0.0.11:53 10.0.0.12:53 {
        race
        race-continue-on-error
    }
}
~~~

### Weighted Random Selection

Send parallel requests to two randomly selected resolvers. `127.0.0.1:9007` is selected most frequently due to its highest load factor.

~~~ corefile
example.org {
    fanout . 127.0.0.1:9005 127.0.0.1:9006 127.0.0.1:9007 {
        policy weighted-random
        weighted-random-server-count 2
        weighted-random-load-factor 50 70 100
    }
}
~~~

## Building CoreDNS with fanout

See [coredns/README.md](coredns/README.md) for instructions on building a CoreDNS binary or Docker image with this plugin.
