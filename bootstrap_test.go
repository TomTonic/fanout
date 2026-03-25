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
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/coredns/caddy"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// startTestDNSServer starts a UDP DNS server on localhost that calls handler
// for each incoming query. Returns the server address and registers cleanup.
func startTestDNSServer(t *testing.T, handler dns.Handler) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	server := &dns.Server{
		PacketConn: pc,
		Handler:    handler,
	}
	go server.ActivateAndServe() //nolint:errcheck // test server
	t.Cleanup(func() { _ = server.Shutdown() })
	return pc.LocalAddr().String()
}

// TestBootstrapLookupWithoutECS verifies that bootstrapConfig.lookup resolves
// a hostname via a local bootstrap DNS server when no ECS is configured.
// It also asserts that no EDNS0 Client Subnet option is included in the
// outgoing query, confirming the privacy-safe default.
func TestBootstrapLookupWithoutECS(t *testing.T) {
	var receivedECS atomic.Bool

	addr := startTestDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if opt := r.IsEdns0(); opt != nil {
			for _, o := range opt.Option {
				if _, ok := o.(*dns.EDNS0_SUBNET); ok {
					receivedECS.Store(true)
				}
			}
		}
		resp := new(dns.Msg)
		resp.SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("93.184.216.34"),
			})
		}
		_ = w.WriteMsg(resp)
	}))

	b := newBootstrapConfig([]string{addr})
	ips, err := b.lookup(context.Background(), "example.com")
	require.NoError(t, err)
	require.Equal(t, []string{"93.184.216.34"}, ips)
	require.False(t, receivedECS.Load(), "ECS should not be sent when not configured")
}

// TestBootstrapLookupWithECS verifies that when ECS is configured, the
// bootstrap query includes an EDNS0 Client Subnet option with the correct
// family, prefix length, and masked address. This allows distant bootstrap
// resolvers (e.g. 9.9.9.11) to forward geographically relevant answers from
// authoritative servers back to the client, instead of answers optimized for
// the resolver's own location.
func TestBootstrapLookupWithECS(t *testing.T) {
	var receivedSubnet atomic.Pointer[dns.EDNS0_SUBNET]

	addr := startTestDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if opt := r.IsEdns0(); opt != nil {
			for _, o := range opt.Option {
				if s, ok := o.(*dns.EDNS0_SUBNET); ok {
					cp := *s
					receivedSubnet.Store(&cp)
				}
			}
		}
		resp := new(dns.Msg)
		resp.SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("198.51.100.1"),
			})
		}
		_ = w.WriteMsg(resp)
	}))

	_, subnet, err := net.ParseCIDR("203.0.113.0/24")
	require.NoError(t, err)
	b := newBootstrapConfig([]string{addr})
	b.setECS(subnet)

	ips, err := b.lookup(context.Background(), "example.com")
	require.NoError(t, err)
	require.Equal(t, []string{"198.51.100.1"}, ips)

	s := receivedSubnet.Load()
	require.NotNil(t, s, "ECS option should have been received by bootstrap server")
	require.Equal(t, uint16(1), s.Family, "should be IPv4 family")
	require.Equal(t, uint8(24), s.SourceNetmask, "prefix length")
	require.Equal(t, "203.0.113.0", s.Address.String(), "masked address")
}

// TestBootstrapECSIPv6 verifies that setECS correctly handles IPv6 subnets,
// setting the EDNS0 family to 2 and encoding the prefix length. This covers
// dual-stack environments where the client's IPv6 subnet should be sent to
// the bootstrap resolver for geo-aware responses.
func TestBootstrapECSIPv6(t *testing.T) {
	var receivedSubnet atomic.Pointer[dns.EDNS0_SUBNET]

	addr := startTestDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		if opt := r.IsEdns0(); opt != nil {
			for _, o := range opt.Option {
				if s, ok := o.(*dns.EDNS0_SUBNET); ok {
					cp := *s
					receivedSubnet.Store(&cp)
				}
			}
		}
		resp := new(dns.Msg)
		resp.SetReply(r)
		if r.Question[0].Qtype == dns.TypeA {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("10.0.0.2"),
			})
		}
		_ = w.WriteMsg(resp)
	}))

	_, subnet, err := net.ParseCIDR("2001:db8:abcd::/48")
	require.NoError(t, err)
	b := newBootstrapConfig([]string{addr})
	b.setECS(subnet)

	_, err = b.lookup(context.Background(), "example.com")
	require.NoError(t, err)

	s := receivedSubnet.Load()
	require.NotNil(t, s)
	require.Equal(t, uint16(2), s.Family, "should be IPv6 family")
	require.Equal(t, uint8(48), s.SourceNetmask, "prefix length")
}

// TestBootstrapResolveHostPassthroughIP verifies that resolveHost returns an
// address unchanged when it already contains an IP literal. This is the fast
// path for upstream addresses specified by IP (e.g. tls://1.2.3.4:853) and
// exercises the net.ParseIP short-circuit in resolveHost.
func TestBootstrapResolveHostPassthroughIP(t *testing.T) {
	b := newBootstrapConfig([]string{"127.0.0.1:53"})
	resolved, hostname, err := b.resolveHost(context.Background(), "1.2.3.4:853")
	require.NoError(t, err)
	require.Equal(t, "1.2.3.4:853", resolved)
	require.Empty(t, hostname)
}

// newTestDNSRecordHandler creates a DNS handler that responds to the given
// query type with the given IP address. Used by multiple tests.
func newTestDNSRecordHandler(qtype uint16, ip string) dns.Handler {
	return dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		if r.Question[0].Qtype == qtype {
			switch qtype {
			case dns.TypeA:
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP(ip),
				})
			case dns.TypeAAAA:
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
					AAAA: net.ParseIP(ip),
				})
			}
		}
		_ = w.WriteMsg(resp)
	})
}

// TestBootstrapResolveHostResolution verifies that resolveHost correctly
// resolves hostname-based addresses through the bootstrap DNS server for
// both A and AAAA record types. The A-record case covers the common path
// (hostname-based DoH/DoH3/DoQ upstreams like dns.nextdns.io:443).
// The AAAA-fallback case covers IPv6-only environments where no A record
// is available and ensures the resolved address is correctly formatted
// with square brackets for net.JoinHostPort.
func TestBootstrapResolveHostResolution(t *testing.T) {
	tests := []struct {
		name     string
		qtype    uint16
		ip       string
		hostport string
		expected string
	}{
		{"A record", dns.TypeA, "10.0.0.1", "dns.example.com:853", "10.0.0.1:853"},
		{"AAAA fallback", dns.TypeAAAA, "2001:db8::1", "dns.example.com:443", "[2001:db8::1]:443"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := startTestDNSServer(t, newTestDNSRecordHandler(tt.qtype, tt.ip))
			b := newBootstrapConfig([]string{addr})
			resolved, hostname, err := b.resolveHost(context.Background(), tt.hostport)
			require.NoError(t, err)
			require.Equal(t, tt.expected, resolved)
			require.Equal(t, "dns.example.com", hostname)
		})
	}
}

// TestBootstrapDialContext verifies that bootstrapConfig.dialContext() returns
// a DialContext function that resolves hostnames through the bootstrap server
// before establishing TCP connections. This is the mechanism used by the DoH
// (HTTP/2) client to break circular DNS dependencies with ECS support.
func TestBootstrapDialContext(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = tcpListener.Close() }()

	_, tcpPort, _ := net.SplitHostPort(tcpListener.Addr().String())

	dnsAddr := startTestDNSServer(t, newTestDNSRecordHandler(dns.TypeA, "127.0.0.1"))

	b := newBootstrapConfig([]string{dnsAddr})
	dial := b.dialContext()

	go func() {
		conn, _ := tcpListener.Accept()
		if conn != nil {
			_ = conn.Close()
		}
	}()

	conn, err := dial(context.Background(), "tcp", "fake.hostname.test:"+tcpPort)
	require.NoError(t, err)
	_ = conn.Close()
}

// TestBootstrapLookupFailure verifies that lookup returns a descriptive error
// when the bootstrap server cannot resolve the hostname, rather than silently
// returning an empty result. This tests both the A and AAAA fallback paths.
func TestBootstrapLookupFailure(t *testing.T) {
	addr := startTestDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		resp.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(resp)
	}))

	b := newBootstrapConfig([]string{addr})
	_, err := b.lookup(context.Background(), "nonexistent.test")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no addresses found")
}

// TestParseBootstrap verifies that the Corefile "bootstrap" directive creates
// a bootstrapConfig with the correct server addresses, appending default port
// 53 when no port is specified. Also exercises the bare-IP and IP:port formats.
func TestParseBootstrap(t *testing.T) {
	input := `fanout . 127.0.0.1:53 {
		bootstrap 9.9.9.11 149.112.112.11:5353
	}`
	c := caddy.NewTestController("dns", input)
	f, err := parseFanout(c)
	require.NoError(t, err)
	require.NotNil(t, f.bootstrap)
	require.Equal(t, []string{"9.9.9.11:53", "149.112.112.11:5353"}, f.bootstrap.addrs)
	require.Nil(t, f.bootstrap.ecs, "ECS should not be set without ecs directive")
}

// TestParseECSExplicitCIDR verifies that the "ecs" directive with an explicit
// CIDR argument enables EDNS0 Client Subnet on the bootstrapConfig.
// Checks family, prefix length, and address encoding for both IPv4 and IPv6.
func TestParseECSExplicitCIDR(t *testing.T) {
	tests := []struct {
		name           string
		cidr           string
		expectFamily   uint16
		expectPrefixL  uint8
		expectAddrPart string
	}{
		{"IPv4/24", "203.0.113.0/24", 1, 24, "203.0.113.0"},
		{"IPv4/16", "10.20.0.0/16", 1, 16, "10.20.0.0"},
		{"IPv6/48", "2001:db8:abcd::/48", 2, 48, "2001:db8:abcd::"},
		{"IPv6/32", "2a0d:2406::/32", 2, 32, "2a0d:2406::"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := `fanout . 127.0.0.1:53 {
				bootstrap 9.9.9.11
				ecs ` + tt.cidr + `
			}`
			c := caddy.NewTestController("dns", input)
			f, err := parseFanout(c)
			require.NoError(t, err)
			require.NotNil(t, f.bootstrap)
			require.NotNil(t, f.bootstrap.ecs)
			require.Equal(t, tt.expectFamily, f.bootstrap.ecs.Family)
			require.Equal(t, tt.expectPrefixL, f.bootstrap.ecs.SourceNetmask)
			require.Contains(t, f.bootstrap.ecs.Address.String(), tt.expectAddrPart)
		})
	}
}

// TestParseECSWithoutBootstrap verifies that specifying ecs without a prior
// bootstrap directive results in a parse error, since ECS without a bootstrap
// resolver to send it to is meaningless.
func TestParseECSWithoutBootstrap(t *testing.T) {
	input := `fanout . 127.0.0.1:53 {
		ecs 203.0.113.0/24
	}`
	c := caddy.NewTestController("dns", input)
	_, err := parseFanout(c)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "bootstrap"),
		"error should mention bootstrap dependency, got: %s", err.Error())
}

// TestParseECSInvalidCIDR verifies that an invalid CIDR notation in the ecs
// directive results in a clear parse error.
func TestParseECSInvalidCIDR(t *testing.T) {
	input := `fanout . 127.0.0.1:53 {
		bootstrap 9.9.9.11
		ecs not-a-cidr
	}`
	c := caddy.NewTestController("dns", input)
	_, err := parseFanout(c)
	require.Error(t, err)
	require.True(t, strings.Contains(err.Error(), "CIDR"),
		"error should mention CIDR, got: %s", err.Error())
}

// TestParseECSAutoDetect verifies that "ecs" without arguments auto-detects
// the local subnet by dialing UDP to a bootstrap server. On any machine with
// a network stack, this should produce a valid /24 (IPv4) or /48 (IPv6)
// subnet without error.
func TestParseECSAutoDetect(t *testing.T) {
	input := `fanout . 127.0.0.1:53 {
		bootstrap 127.0.0.1
		ecs
	}`
	c := caddy.NewTestController("dns", input)
	f, err := parseFanout(c)
	require.NoError(t, err)
	require.NotNil(t, f.bootstrap)
	require.NotNil(t, f.bootstrap.ecs, "auto-detected ECS should be set")
	// On localhost, the detected IP is 127.0.0.1 → /24 → family 1.
	require.Equal(t, uint16(1), f.bootstrap.ecs.Family)
	require.Equal(t, uint8(24), f.bootstrap.ecs.SourceNetmask)
}

// TestDetectLocalSubnet verifies that detectLocalSubnet returns a valid /24
// IPv4 subnet when dialing to localhost. This exercises the UDP-dial approach
// for determining the outgoing IP without sending any packets.
func TestDetectLocalSubnet(t *testing.T) {
	subnet, err := detectLocalSubnet("127.0.0.1:53")
	require.NoError(t, err)
	require.NotNil(t, subnet)
	ones, bits := subnet.Mask.Size()
	if bits == 32 {
		require.Equal(t, 24, ones)
	} else {
		require.Equal(t, 48, ones)
	}
}
