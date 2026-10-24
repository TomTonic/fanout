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
	"errors"
	"net"
	"net/http"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

// Upstream spellings shared by the tests below.
const (
	upstreamName        = "dns.example"
	upstreamPlain853    = "dns.example:853"
	upstreamOtherName   = "other.example"
	upstreamAbsolute853 = "dns.example.:853"
	upstreamIPv4        = "192.0.2.1:853"
	upstreamIPv6        = "[2001:db8::1]:853"
	upstreamIPv6Zone    = "[fe80::1%eth0]:853"
	upstreamNoHost      = ":853"
)

var errRecordedDial = errors.New("recorded dial, no connection made")

// dialRecord is what a recording dial function saw.
type dialRecord struct {
	addr       string
	serverName string
	tlsConf    *tls.Config
}

// recordingQUICDial returns a quicDialFunc that records its arguments and fails, so no
// network traffic or name resolution happens.
func recordingQUICDial(rec *dialRecord) quicDialFunc {
	return func(_ context.Context, addr string, tlsConf *tls.Config, _ *quic.Config) (*quic.Conn, error) {
		rec.addr = addr
		rec.tlsConf = tlsConf
		rec.serverName = tlsConf.ServerName
		return nil, errRecordedDial
	}
}

// TestAbsoluteHostPort verifies that an upstream's host name is handed to the
// resolver as an absolute name, so the search domains of the machine running CoreDNS
// can never complete or redirect it.
//
// This covers the shared helper behind all DoH, DoH3 and DoQ dials that do not use a
// bootstrap resolver.
//
// It asserts that DNS names get a trailing dot exactly once, and that IP literals,
// including IPv6 with a zone, and values without a port are left alone.
func TestAbsoluteHostPort(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"appends a dot to a dns name", upstreamPlain853, upstreamAbsolute853},
		{"appends a dot to a single-label name", "dnsbox:443", "dnsbox.:443"},
		{"keeps an already absolute name", upstreamAbsolute853, upstreamAbsolute853},
		{"keeps the case of the name", "DNS.Example:853", "DNS.Example.:853"},
		{"leaves an IPv4 literal alone", upstreamIPv4, upstreamIPv4},
		{"leaves an IPv6 literal alone", upstreamIPv6, upstreamIPv6},
		{"leaves an IPv6 literal with zone alone", upstreamIPv6Zone, upstreamIPv6Zone},
		{"leaves a value without port alone", upstreamName, upstreamName},
		{"leaves an empty host alone", upstreamNoHost, upstreamNoHost},
		{"leaves the empty string alone", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, absoluteHostPort(tc.in))
		})
	}
}

// TestDNSNameOf verifies that only real DNS names are reported as names.
//
// This covers the helper that decides both whether to add the trailing dot and
// whether the TLS server name has to be pinned.
//
// It asserts the name comes back without trailing dot, and that IPs yield "".
func TestDNSNameOf(t *testing.T) {
	require.Equal(t, upstreamName, dnsNameOf(upstreamPlain853))
	require.Equal(t, upstreamName, dnsNameOf(upstreamAbsolute853))
	require.Empty(t, dnsNameOf(upstreamIPv4))
	require.Empty(t, dnsNameOf(upstreamIPv6))
	require.Empty(t, dnsNameOf(upstreamIPv6Zone))
	require.Empty(t, dnsNameOf(upstreamName))
	require.Empty(t, dnsNameOf(".:853"))
}

// TestAbsoluteDialContext verifies that DoH connections ask the system resolver for
// the upstream's absolute name.
//
// This covers the dial function installed on the DoH HTTP transport.
//
// It asserts the wrapped dialer sees the absolute address with the network unchanged,
// that IP literals pass through untouched, and that dial errors are returned as is.
func TestAbsoluteDialContext(t *testing.T) {
	var gotNetwork, gotAddr string
	dial := absoluteDialContext(func(_ context.Context, network, addr string) (net.Conn, error) {
		gotNetwork, gotAddr = network, addr
		return nil, errRecordedDial
	})

	_, err := dial(context.Background(), "tcp", "dns.example:443")
	require.ErrorIs(t, err, errRecordedDial)
	require.Equal(t, "tcp", gotNetwork)
	require.Equal(t, "dns.example.:443", gotAddr)

	_, err = dial(context.Background(), "tcp", "192.0.2.1:443")
	require.ErrorIs(t, err, errRecordedDial)
	require.Equal(t, "192.0.2.1:443", gotAddr)
}

// TestAbsoluteQUICDial verifies that QUIC connections (DoQ, DoH3) ask the system
// resolver for the absolute name while the certificate is still checked against the
// name the user configured.
//
// This covers the wrapper around quic.DialAddr and quic.DialAddrEarly. quic-go would
// otherwise take "dns.example." from the address as the TLS server name.
//
// It asserts the address is absolute, ServerName is the name without dot, an explicit
// ServerName (the tls_servername directive) wins, IP upstreams get no server name,
// and the caller's tls.Config is never modified.
func TestAbsoluteQUICDial(t *testing.T) {
	cases := []struct {
		name           string
		addr           string
		configured     string
		wantAddr       string
		wantServerName string
	}{
		{"pins the configured name as server name", upstreamPlain853, "", upstreamAbsolute853, upstreamName},
		{"pins the name without trailing dot", upstreamAbsolute853, "", upstreamAbsolute853, upstreamName},
		{"keeps an explicit server name", upstreamPlain853, upstreamOtherName, upstreamAbsolute853, upstreamOtherName},
		{"leaves IP upstreams alone", upstreamIPv4, "", upstreamIPv4, ""},
		{"keeps an explicit server name for IP upstreams", upstreamIPv4, upstreamName, upstreamIPv4, upstreamName},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var rec dialRecord
			orig := &tls.Config{ServerName: tc.configured, MinVersion: tls.VersionTLS13}

			_, err := absoluteQUICDial(recordingQUICDial(&rec))(context.Background(), tc.addr, orig, nil)

			require.ErrorIs(t, err, errRecordedDial)
			require.Equal(t, tc.wantAddr, rec.addr)
			require.Equal(t, tc.wantServerName, rec.serverName)
			require.Equal(t, tc.configured, orig.ServerName, "the caller's tls.Config must not be modified")
		})
	}
}

// TestDoQClient_DialsAbsoluteNameWithoutBootstrap verifies that a DoQ upstream given
// as a host name is looked up as an absolute name when no bootstrap resolver is set.
//
// This covers the DoQ client's connection setup, the path used by upstreams like
// quic://dns.example in a Corefile without a bootstrap directive.
//
// It asserts the dial function receives upstreamAbsolute853 and the server name
// upstreamName.
func TestDoQClient_DialsAbsoluteNameWithoutBootstrap(t *testing.T) {
	var rec dialRecord
	c := newDoQClientWithDial(upstreamPlain853, nil, nil, recordingQUICDial(&rec)).(*doqClient)

	_, err := c.getOrDialConn(context.Background())

	require.ErrorIs(t, err, errRecordedDial)
	require.Equal(t, upstreamAbsolute853, rec.addr)
	require.Equal(t, upstreamName, rec.serverName)
	require.Equal(t, []string{doqALPN}, rec.tlsConf.NextProtos)
}

// TestDoQClient_BootstrapStillBypassesSystemDial verifies that configuring a
// bootstrap resolver keeps taking precedence over the system dial.
//
// This covers the DoQ client's choice between bootstrap and system resolution.
//
// It asserts that with an unreachable bootstrap resolver the base dial is never used.
func TestDoQClient_BootstrapStillBypassesSystemDial(t *testing.T) {
	var rec dialRecord
	b := newBootstrapConfig([]string{"127.0.0.1:1"})
	c := newDoQClientWithDial(upstreamPlain853, nil, b, recordingQUICDial(&rec)).(*doqClient)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.getOrDialConn(ctx)

	require.Error(t, err)
	require.NotErrorIs(t, err, errRecordedDial)
	require.Empty(t, rec.addr)
}

// TestDoH3Client_DialsAbsoluteNameWithoutBootstrap verifies that a DoH3 upstream given
// as a host name is looked up as an absolute name when no bootstrap resolver is set,
// also after the TLS configuration was replaced.
//
// This covers the HTTP/3 transport of the DoH3 client, including the replacement
// transport that SetTLSConfig builds (as the tls_servername directive triggers).
//
// It asserts the transport's Dial hook receives "dns.example:443" as the absolute
// "dns.example.:443" before and after SetTLSConfig.
func TestDoH3Client_DialsAbsoluteNameWithoutBootstrap(t *testing.T) {
	var rec dialRecord
	c := newDoH3ClientWithDial("https://dns.example/dns-query", nil, nil, recordingQUICDial(&rec)).(*doh3Client)
	shutdownClientAfterTest(t, c)

	dial := func() error {
		c.mu.Lock()
		tr := c.transport
		c.mu.Unlock()
		require.NotNil(t, tr.Dial)
		// http3 hands the dial hook a clone of the transport's own TLS config.
		_, err := tr.Dial(context.Background(), "dns.example:443", tr.TLSClientConfig.Clone(), nil)
		return err
	}

	require.ErrorIs(t, dial(), errRecordedDial)
	require.Equal(t, "dns.example.:443", rec.addr)
	require.Equal(t, upstreamName, rec.serverName)

	rec = dialRecord{}
	c.SetTLSConfig(&tls.Config{ServerName: "tls.example", MinVersion: tls.VersionTLS13})
	require.ErrorIs(t, dial(), errRecordedDial)
	require.Equal(t, "dns.example.:443", rec.addr)
	require.Equal(t, "tls.example", rec.serverName)
}

// TestDoHClient_DialsAbsoluteNameWithoutBootstrap verifies that a DoH upstream given
// as a host name is looked up as an absolute name when no bootstrap resolver is set.
//
// This covers the HTTP/2 transport of the DoH client.
//
// It asserts the transport's DialContext hands the dialer "dns.example.:443".
func TestDoHClient_DialsAbsoluteNameWithoutBootstrap(t *testing.T) {
	var gotAddr string
	hc := newHTTP2ClientWithDialer(nil, nil, func(_ context.Context, _, addr string) (net.Conn, error) {
		gotAddr = addr
		return nil, errRecordedDial
	})
	tr, ok := hc.Transport.(*http.Transport)
	require.True(t, ok)
	t.Cleanup(tr.CloseIdleConnections)

	_, err := tr.DialContext(context.Background(), "tcp", "dns.example:443")

	require.ErrorIs(t, err, errRecordedDial)
	require.Equal(t, "dns.example.:443", gotAddr)
}

// shutdownClientAfterTest closes c when the test ends, releasing the transports a
// DoH3 client keeps (and the timers for retired ones).
func shutdownClientAfterTest(t *testing.T, c Client) {
	t.Helper()
	t.Cleanup(func() {
		if cl, ok := c.(interface{ Close() error }); ok {
			logErrIfNotNil(cl.Close())
		}
	})
}
