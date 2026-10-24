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
	"crypto/tls"
	"net"
	"net/netip"
	"strings"

	"github.com/quic-go/quic-go"
)

// Upstream hostnames are names of servers, not names to be completed by the host's
// resolver configuration. Without a bootstrap resolver the Go resolver would try the
// search domains from /etc/resolv.conf as well: first for names with fewer dots than
// ndots, and for every other name as soon as the absolute lookup fails. That sends the
// upstream's name to unrelated zones (a leak) and can turn a wildcard search domain
// into a wrong server address. A trailing dot makes the resolver skip the search list,
// which is what CoreDNS's forward plugin does for its upstreams as well (v1.15.0).
// The helpers below apply that to every dial that does not go through bootstrap.

// quicDialFunc is the signature shared by quic.DialAddr, quic.DialAddrEarly and
// http3.Transport.Dial, so one wrapper serves DoQ and DoH3.
type quicDialFunc func(ctx context.Context, addr string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error)

// dnsNameOf returns the host of hostport without a trailing dot if that host is a
// DNS name, and "" if it is an IP literal (with or without zone), empty, or hostport
// has no port. Names are the only hosts the resolver has to look up.
func dnsNameOf(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil || host == "" {
		return ""
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return ""
	}
	return strings.TrimSuffix(host, ".")
}

// absoluteHostPort returns hostport with its host rewritten into an absolute DNS name
// (trailing dot). IP literals and values it cannot split are returned unchanged.
func absoluteHostPort(hostport string) string {
	name := dnsNameOf(hostport)
	if name == "" {
		return hostport
	}
	_, port, _ := net.SplitHostPort(hostport)
	return net.JoinHostPort(name+".", port)
}

// absoluteDialContext wraps dial so that DNS names are dialed as absolute names.
// The wrapped function is meant for http.Transport.DialContext; the TLS server name
// and Host header still come from the request URL, so they are unaffected.
func absoluteDialContext(dial func(ctx context.Context, network, addr string) (net.Conn, error)) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dial(ctx, network, absoluteHostPort(addr))
	}
}

// absoluteQUICDial wraps dial so that DNS names are dialed as absolute names.
//
// quic-go derives the TLS server name from the address it is given, which would turn
// "host.:853" into the server name "host."; the original name is therefore pinned as
// ServerName first, unless the caller configured one. The caller's tls.Config is
// never modified.
func absoluteQUICDial(dial quicDialFunc) quicDialFunc {
	return func(ctx context.Context, addr string, tlsConf *tls.Config, conf *quic.Config) (*quic.Conn, error) {
		if name := dnsNameOf(addr); name != "" && tlsConf.ServerName == "" {
			tlsConf = tlsConf.Clone()
			tlsConf.ServerName = name
		}
		return dial(ctx, absoluteHostPort(addr), tlsConf, conf)
	}
}
