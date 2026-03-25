// Copyright (c) 2026 Tom Gelhausen; contributors: various coding‑agents.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fanout

import (
	"context"
	"math/rand/v2"
	"net"

	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

// bootstrapConfig holds the configuration for bootstrap DNS resolution.
// It uses miekg/dns directly (instead of net.Resolver) to support EDNS0
// Client Subnet (ECS, RFC 7871). When a bootstrap resolver is behind a
// non-local anycast or unicast address, ECS lets the authoritative server
// return the anycast endpoint closest to the *client*, not the resolver.
//
// Corefile usage:
//
//	fanout . https://dns.nextdns.io/abc123 {
//	    bootstrap 9.9.9.11 149.112.112.11
//	    ecs                          # auto-detect local subnet
//	    # OR: ecs 203.0.113.0/24    # explicit subnet
//	}
//
// Privacy note: ECS reveals part of the client's IP to the bootstrap
// resolver and — transitively — to authoritative name servers. If that is
// undesirable, omit the ecs directive; the bootstrap query will then be a
// plain DNS lookup without subnet information.
//
// Which bootstrap IPs support ECS?
//
//	Provider   | Standard (no ECS)        | ECS-enabled
//	-----------+--------------------------+--------------------------
//	Quad9      | 9.9.9.9, 149.112.112.112 | 9.9.9.11, 149.112.112.11
//	Google     | —                        | 8.8.8.8, 8.8.4.4
//	Cloudflare | 1.1.1.1, 1.0.0.1        | (ECS generally not forwarded)
type bootstrapConfig struct {
	addrs []string          // bootstrap DNS server addresses (ip:port)
	ecs   *dns.EDNS0_SUBNET // optional ECS option for geo-aware responses (nil = disabled)
}

// newBootstrapConfig creates a bootstrap configuration that sends queries
// to the given DNS server addresses over plain UDP.
func newBootstrapConfig(addrs []string) *bootstrapConfig {
	return &bootstrapConfig{addrs: addrs}
}

// setECS enables EDNS0 Client Subnet (RFC 7871) on bootstrap queries.
// The subnet defines which prefix of the client's IP is sent to the
// bootstrap resolver so that authoritative servers can return
// geographically optimal answers.
func (b *bootstrapConfig) setECS(subnet *net.IPNet) {
	ones, _ := subnet.Mask.Size()
	family := uint16(1) // IPv4
	if subnet.IP.To4() == nil {
		family = 2 // IPv6
	}
	b.ecs = &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        family,
		SourceNetmask: uint8(ones), //nolint:gosec // prefix length ≤128
		SourceScope:   0,
		Address:       subnet.IP.Mask(subnet.Mask),
	}
}

// lookup resolves a hostname to IP addresses using the configured bootstrap
// DNS servers. If ECS is configured, an EDNS0 Client Subnet option is
// included so that authoritative servers return geographically optimal results.
func (b *bootstrapConfig) lookup(ctx context.Context, host string) ([]string, error) {
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		ips, err := b.queryBootstrap(ctx, host, qtype)
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
	}
	return nil, errors.Errorf("bootstrap: no addresses found for %s", host)
}

// queryBootstrap sends a single DNS query to a randomly chosen bootstrap
// server and extracts IP addresses from the answer section.
func (b *bootstrapConfig) queryBootstrap(ctx context.Context, host string, qtype uint16) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), qtype)
	msg.RecursionDesired = true

	if b.ecs != nil {
		msg.SetEdns0(dns.DefaultMsgSize, false)
		if opt := msg.IsEdns0(); opt != nil {
			opt.Option = append(opt.Option, b.ecs)
		}
	}

	addr := b.addrs[rand.IntN(len(b.addrs))] //nolint:gosec // not security-sensitive
	client := &dns.Client{
		Net:     "udp",
		Timeout: dialTimeout,
	}

	resp, _, err := client.ExchangeContext(ctx, msg, addr)
	if err != nil {
		return nil, err
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, errors.Errorf("bootstrap query for %s (type %d) returned rcode %d", host, qtype, resp.Rcode)
	}

	var ips []string
	for _, rr := range resp.Answer {
		switch v := rr.(type) {
		case *dns.A:
			ips = append(ips, v.A.String())
		case *dns.AAAA:
			ips = append(ips, v.AAAA.String())
		}
	}
	return ips, nil
}

// resolveHost resolves the hostname portion of a host:port string.
// If the host is already an IP address the input is returned unchanged.
// On success the first resolved IP is returned joined with the original port,
// and the bare hostname is returned separately so the caller can set the TLS
// ServerName for certificate verification.
func (b *bootstrapConfig) resolveHost(ctx context.Context, hostport string) (resolved, hostname string, err error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport, "", nil
	}
	if net.ParseIP(host) != nil {
		return hostport, "", nil
	}
	ips, err := b.lookup(ctx, host)
	if err != nil {
		return "", host, errors.Wrapf(err, "bootstrap resolution of %s failed", host)
	}
	return net.JoinHostPort(ips[0], port), host, nil
}

// dialContext returns a function compatible with http.Transport.DialContext
// that resolves hostnames through this bootstrap configuration before dialing.
// This ensures DoH clients use bootstrap resolution (including ECS) instead
// of the system resolver.
func (b *bootstrapConfig) dialContext() func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		resolved, _, err := b.resolveHost(ctx, address)
		if err != nil {
			return nil, err
		}
		d := net.Dialer{Timeout: dialTimeout}
		return d.DialContext(ctx, network, resolved)
	}
}

// detectLocalSubnet determines the machine's outgoing IP address by making
// a connectionless UDP "dial" to targetAddr. The returned *net.IPNet uses a
// /24 prefix for IPv4 and /48 for IPv6, which is the recommended granularity
// for EDNS0 Client Subnet (see RFC 7871 §11.1).
func detectLocalSubnet(targetAddr string) (*net.IPNet, error) {
	conn, err := net.DialTimeout("udp", targetAddr, dialTimeout)
	if err != nil {
		return nil, errors.Wrap(err, "detecting local subnet")
	}
	defer func() { _ = conn.Close() }()

	host, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return nil, errors.Wrap(err, "parsing local address")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, errors.Errorf("invalid local IP %q", host)
	}

	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}, nil
	}
	return &net.IPNet{IP: ip.Mask(net.CIDRMask(48, 128)), Mask: net.CIDRMask(48, 128)}, nil
}
