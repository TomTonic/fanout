# fanout

![ci](https://github.com/TomTonic/fanout/workflows/ci/badge.svg)

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
    race
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
* `race` — gives priority to the first result, whether it is negative or not, as long as it is a standard DNS result.

## Metrics

If monitoring is enabled (via the *prometheus* plugin) then the following metrics are exported:

* `coredns_fanout_request_duration_seconds{to}` — duration per upstream interaction.
* `coredns_fanout_request_count_total{to}` — query count per upstream.
* `coredns_fanout_response_rcode_count_total{to, rcode}` — count of RCODEs per upstream.

Where `to` is one of the upstream servers (**TO** from the config), `rcode` is the returned RCODE
from the upstream.

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

Multiple upstreams are configured but one of them is down. With `race` enabled, the first result (even negative/NXDOMAIN) is returned immediately instead of waiting for timeouts.

~~~ corefile
. {
    fanout . 10.0.0.10:53 10.0.0.11:53 10.0.0.12:53 {
        race
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
