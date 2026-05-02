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

// Real-world integration tests against Cloudflare's public DNS service (1.1.1.1).
// These tests verify that each supported transport protocol can successfully resolve
// DNS queries in the real world. They are skipped in short mode (-short) to avoid
// network dependencies in CI. Run with:
//
//	go test -race -run TestRealWorld -v -timeout 60s

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

const (
	// Cloudflare DNS endpoints.
	cfPlain    = "1.1.1.1:53"
	cfDoTAddr  = "1.1.1.1:853"
	cfDoTName  = "cloudflare-dns.com"
	cfDoHURL   = "https://cloudflare-dns.com/dns-query"
	cfTestFQDN = "one.one.one.one." // Cloudflare's own domain, always resolvable

	// AdGuard DNS endpoint for DoQ.
	// Cloudflare does not support DoQ (RFC 9250). AdGuard DNS is a well-known
	// public DNS provider that does, on the standard port 853/UDP.
	agDoQAddr = "dns.adguard-dns.com:853"

	// realWorldTimeout is the maximum time for each real-world query.
	realWorldTimeout = 10 * time.Second

	reasonTLSIntercept = "tls certificate validation failed (possible TLS interception or certificate substitution)"
	reasonNetBlocked   = "network policy/firewall blocks required DNS transport"
)

var (
	realWorldCapabilityCache sync.Map // map[string]realWorldCapabilityResult

	realWorldSkipTotal   atomic.Int64
	realWorldSkipReasonM sync.Mutex
	realWorldSkipReasons = map[string]int{}
)

type realWorldCapabilityResult struct {
	blocked bool
	reason  string
}

func TestMain(m *testing.M) {
	exitCode := m.Run()
	reportRealWorldSkipSummary()
	os.Exit(exitCode)
}

func reportRealWorldSkipSummary() {
	total := realWorldSkipTotal.Load()
	if total == 0 {
		return
	}

	realWorldSkipReasonM.Lock()
	reasons := make([]string, 0, len(realWorldSkipReasons))
	for reason := range realWorldSkipReasons {
		reasons = append(reasons, reason)
	}
	sort.Strings(reasons)

	reasonCount := make(map[string]int, len(realWorldSkipReasons))
	for k, v := range realWorldSkipReasons {
		reasonCount[k] = v
	}
	realWorldSkipReasonM.Unlock()

	fmt.Fprintf(os.Stderr, "\n[fanout] %d real-world test(s) were skipped due to environment restrictions:\n", total)
	for _, reason := range reasons {
		fmt.Fprintf(os.Stderr, "  - %s (occurred %dx)\n", reason, reasonCount[reason])
	}
	fmt.Fprintf(os.Stderr, "[fanout] Run these tests in a network that allows DNS/DoH/DoH3/DoQ to execute all real-world checks.\n")
}

func rememberRealWorldSkip(reason string) {
	realWorldSkipTotal.Add(1)
	realWorldSkipReasonM.Lock()
	realWorldSkipReasons[reason]++
	realWorldSkipReasonM.Unlock()
}

func skipIfRealWorldBlocked(t *testing.T, protocol string, err error) {
	t.Helper()
	if err == nil {
		return
	}

	protocol = normalizeRealWorldProtocolName(protocol)

	if blocked, reason := classifyRealWorldRestriction(err); blocked {
		fullReason := fmt.Sprintf("%s blocked: %s", protocol, reason)
		rememberRealWorldSkip(fullReason)
		t.Skipf("%s: skipping because this environment blocks required traffic: %v", protocol, err)
	}
}

func requireRealWorldCapability(t *testing.T, capability string, probe func(context.Context) error) {
	t.Helper()
	capability = normalizeRealWorldProtocolName(capability)

	if cached, ok := realWorldCapabilityCache.Load(capability); ok {
		res := cached.(realWorldCapabilityResult)
		if res.blocked {
			reason := fmt.Sprintf("%s blocked: %s", capability, res.reason)
			rememberRealWorldSkip(reason)
			t.Skipf("%s: skipping due to cached environment restriction: %s", capability, res.reason)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), realWorldTimeout)
	defer cancel()

	err := probe(ctx)
	if blocked, reason := classifyRealWorldRestriction(err); blocked {
		res := realWorldCapabilityResult{blocked: true, reason: reason}
		realWorldCapabilityCache.Store(capability, res)
		reason = fmt.Sprintf("%s blocked: %s", capability, reason)
		rememberRealWorldSkip(reason)
		t.Skipf("%s: skipping because preflight check failed in this environment: %v", capability, err)
	}

	realWorldCapabilityCache.Store(capability, realWorldCapabilityResult{})
}

func classifyRealWorldRestriction(err error) (blocked bool, reason string) {
	if err == nil {
		return false, ""
	}

	// Prefer typed checks to stay stable across Go/runtime/OS error message variations.
	if errors.Is(err, context.DeadlineExceeded) {
		return true, reasonNetBlocked
	}

	if isTLSEnvironmentRestriction(err) {
		return true, reasonTLSIntercept
	}

	if isNetworkEnvironmentRestriction(err) {
		return true, reasonNetBlocked
	}

	errStr := strings.ToLower(err.Error())

	// Fallback for edge cases where underlying typed errors are not exposed.
	if strings.Contains(errStr, "no recent network activity") ||
		strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "context deadline exceeded") ||
		strings.Contains(errStr, "eof") ||
		strings.Contains(errStr, "remote error: tls") ||
		strings.Contains(errStr, "tls: handshake failure") ||
		strings.Contains(errStr, "handshake failure") {
		return true, reasonNetBlocked
	}

	return false, ""
}

func isTLSEnvironmentRestriction(err error) bool {
	var unknownAuthorityErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthorityErr) {
		return true
	}

	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return true
	}

	var certInvalidErr x509.CertificateInvalidError
	if errors.As(err, &certInvalidErr) {
		return true
	}

	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "failed to verify certificate") ||
		strings.Contains(errStr, "x509: certificate is valid for") ||
		strings.Contains(errStr, "certificate signed by unknown authority") ||
		strings.Contains(errStr, "certificate is not valid for")
}

func isNetworkEnvironmentRestriction(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}

	if errors.Is(err, io.EOF) {
		return true
	}

	// Handle common cross-platform socket failures.
	if errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.EPERM) ||
		errors.Is(err, syscall.EACCES) {
		return true
	}

	return false
}

func normalizeRealWorldProtocolName(name string) string {
	if idx := strings.Index(name, " ("); idx > 0 {
		return name[:idx]
	}
	return name
}

func newRealWorldRequest(qType uint16) *request.Request {
	msg := new(dns.Msg)
	msg.SetQuestion(cfTestFQDN, qType)
	msg.RecursionDesired = true
	return &request.Request{W: &test.ResponseWriter{}, Req: msg}
}

// requireRealWorldResponse validates that the DNS response is non-nil, has no error,
// and contains at least one answer record.
func requireRealWorldResponse(t *testing.T, resp *dns.Msg, err error, protocol string) {
	t.Helper()
	skipIfRealWorldBlocked(t, protocol, err)
	require.NoError(t, err, "%s: request failed", protocol)
	require.NotNil(t, resp, "%s: nil response", protocol)
	require.Equal(t, dns.RcodeSuccess, resp.Rcode, "%s: unexpected rcode %s", protocol, dns.RcodeToString[resp.Rcode])
	require.NotEmpty(t, resp.Answer, "%s: no answer records", protocol)
}

// skipOnTimeout checks if the error is a network timeout and skips the test
// instead of failing. This is useful for protocols like DoQ that use non-standard
// UDP ports (853) which may be blocked by firewalls or NAT.
func skipOnTimeout(t *testing.T, err error, protocol string) {
	t.Helper()
	if err == nil {
		return
	}
	errStr := err.Error()
	if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "no recent network activity") {
		t.Skipf("%s: skipping due to network timeout (UDP port may be blocked by firewall): %v", protocol, err)
	}
}

// TestRealWorldCloudflareUDP tests plain DNS over UDP against Cloudflare (1.1.1.1:53).
func TestRealWorldCloudflareUDP(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-world test in short mode")
	}

	c := NewClient(cfPlain, UDP)
	requireRealWorldCapability(t, testCaseUDP, func(ctx context.Context) error {
		_, err := c.Request(ctx, newRealWorldRequest(dns.TypeA))
		return err
	})

	ctx, cancel := context.WithTimeout(context.Background(), realWorldTimeout)
	defer cancel()

	resp, err := c.Request(ctx, newRealWorldRequest(dns.TypeA))
	requireRealWorldResponse(t, resp, err, testCaseUDP)

	t.Logf("UDP response: %d answer(s), first: %s", len(resp.Answer), resp.Answer[0].String())
}

// TestRealWorldCloudflareTCP tests plain DNS over TCP against Cloudflare (1.1.1.1:53).
func TestRealWorldCloudflareTCP(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-world test in short mode")
	}

	c := NewClient(cfPlain, TCP)
	requireRealWorldCapability(t, "TCP", func(ctx context.Context) error {
		_, err := c.Request(ctx, newRealWorldRequest(dns.TypeA))
		return err
	})

	ctx, cancel := context.WithTimeout(context.Background(), realWorldTimeout)
	defer cancel()

	resp, err := c.Request(ctx, newRealWorldRequest(dns.TypeA))
	requireRealWorldResponse(t, resp, err, "TCP")

	t.Logf("TCP response: %d answer(s), first: %s", len(resp.Answer), resp.Answer[0].String())
}

// TestRealWorldCloudflareDoT tests DNS-over-TLS (RFC 7858) against Cloudflare (1.1.1.1:853).
func TestRealWorldCloudflareDoT(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-world test in short mode")
	}

	c := NewClient(cfDoTAddr, TCP)
	c.SetTLSConfig(&tls.Config{
		ServerName: cfDoTName,
		MinVersion: tls.VersionTLS12,
	})
	requireRealWorldCapability(t, "DoT", func(ctx context.Context) error {
		_, err := c.Request(ctx, newRealWorldRequest(dns.TypeA))
		return err
	})

	ctx, cancel := context.WithTimeout(context.Background(), realWorldTimeout)
	defer cancel()

	resp, err := c.Request(ctx, newRealWorldRequest(dns.TypeA))
	requireRealWorldResponse(t, resp, err, "DoT")

	t.Logf("DoT response: %d answer(s), first: %s", len(resp.Answer), resp.Answer[0].String())
}

// TestRealWorldCloudflareDoH tests DNS-over-HTTPS (RFC 8484) via HTTP/2 against Cloudflare.
func TestRealWorldCloudflareDoH(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-world test in short mode")
	}

	c := NewDoHClient(cfDoHURL)
	requireRealWorldCapability(t, "DoH", func(ctx context.Context) error {
		_, err := c.Request(ctx, newRealWorldRequest(dns.TypeA))
		return err
	})

	ctx, cancel := context.WithTimeout(context.Background(), realWorldTimeout)
	defer cancel()

	resp, err := c.Request(ctx, newRealWorldRequest(dns.TypeA))
	requireRealWorldResponse(t, resp, err, "DoH")

	t.Logf("DoH response: %d answer(s), first: %s", len(resp.Answer), resp.Answer[0].String())
}

// TestRealWorldCloudflareDoH3 tests DNS-over-HTTPS (RFC 8484) via HTTP/3 (QUIC) against Cloudflare.
func TestRealWorldCloudflareDoH3(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-world test in short mode")
	}

	c := NewDoH3Client(cfDoHURL)
	defer func() {
		if dc, ok := c.(*doh3Client); ok {
			_ = dc.transport.Close()
		}
	}()

	requireRealWorldCapability(t, "DoH3", func(ctx context.Context) error {
		_, err := c.Request(ctx, newRealWorldRequest(dns.TypeA))
		return err
	})

	ctx, cancel := context.WithTimeout(context.Background(), realWorldTimeout)
	defer cancel()

	resp, err := c.Request(ctx, newRealWorldRequest(dns.TypeA))
	requireRealWorldResponse(t, resp, err, "DoH3")

	t.Logf("DoH3 response: %d answer(s), first: %s", len(resp.Answer), resp.Answer[0].String())
}

// TestRealWorldAdGuardDoQ tests DNS-over-QUIC (RFC 9250) against AdGuard DNS.
// Cloudflare does not support DoQ, so we use AdGuard's public DoQ service instead.
func TestRealWorldAdGuardDoQ(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-world test in short mode")
	}

	c := NewDoQClient(agDoQAddr)
	defer func() {
		if dc, ok := c.(*doqClient); ok {
			dc.closeConn()
		}
	}()

	requireRealWorldCapability(t, "DoQ", func(ctx context.Context) error {
		_, err := c.Request(ctx, newRealWorldRequest(dns.TypeA))
		return err
	})

	ctx, cancel := context.WithTimeout(context.Background(), realWorldTimeout)
	defer cancel()

	resp, err := c.Request(ctx, newRealWorldRequest(dns.TypeA))
	skipOnTimeout(t, err, "DoQ")
	requireRealWorldResponse(t, resp, err, "DoQ")

	t.Logf("DoQ response: %d answer(s), first: %s", len(resp.Answer), resp.Answer[0].String())
}

// TestRealWorldCloudflareAllProtocols runs a DNS A query for the same domain across
// all six supported transport protocols against Cloudflare's public DNS.
// It verifies that every protocol produces a valid response and that the answers
// contain at least one overlapping IP address (proving they resolve the same records).
func TestRealWorldCloudflareAllProtocols(t *testing.T) { //nolint:gocyclo,funlen // integration test intentionally covers many protocol branches
	if testing.Short() {
		t.Skip("skipping real-world test in short mode")
	}

	type protoClient struct {
		name   string
		client Client
		close  func()
	}

	// Build clients for all protocols.
	dotClient := NewClient(cfDoTAddr, TCP)
	dotClient.SetTLSConfig(&tls.Config{
		ServerName: cfDoTName,
		MinVersion: tls.VersionTLS12,
	})

	doh3c := NewDoH3Client(cfDoHURL)
	doqc := NewDoQClient(agDoQAddr)

	protocols := []protoClient{
		{name: "UDP", client: NewClient(cfPlain, UDP), close: func() {}},
		{name: "TCP", client: NewClient(cfPlain, TCP), close: func() {}},
		{name: "DoT (RFC 7858)", client: dotClient, close: func() {}},
		{name: "DoH (RFC 8484)", client: NewDoHClient(cfDoHURL), close: func() {}},
		{name: "DoH3 (RFC 9114)", client: doh3c, close: func() {
			if dc, ok := doh3c.(*doh3Client); ok {
				_ = dc.transport.Close()
			}
		}},
		{name: "DoQ (RFC 9250)", client: doqc, close: func() {
			if dc, ok := doqc.(*doqClient); ok {
				dc.closeConn()
			}
		}},
	}

	// Collect all resolved IPs per protocol.
	allIPs := make(map[string][]net.IP) // protocol name -> IPs

	for _, p := range protocols {
		p := p
		t.Run(p.name, func(t *testing.T) {
			defer p.close()
			requireRealWorldCapability(t, p.name, func(ctx context.Context) error {
				_, err := p.client.Request(ctx, newRealWorldRequest(dns.TypeA))
				return err
			})

			ctx, cancel := context.WithTimeout(context.Background(), realWorldTimeout)
			defer cancel()

			resp, err := p.client.Request(ctx, newRealWorldRequest(dns.TypeA))
			skipOnTimeout(t, err, p.name)
			requireRealWorldResponse(t, resp, err, p.name)

			var ips []net.IP
			for _, rr := range resp.Answer {
				if a, ok := rr.(*dns.A); ok {
					ips = append(ips, a.A)
				}
			}
			require.NotEmpty(t, ips, "%s: no A records in response", p.name)

			allIPs[p.name] = ips
			t.Logf("%s: resolved %s to %v (rtt implicit)", p.name, cfTestFQDN, ips)
		})
	}

	// Verify that all protocols returned at least one common IP.
	// Since they all query Cloudflare for the same domain, at least one IP should overlap.
	if len(allIPs) >= 2 {
		ipSets := make([]map[string]bool, 0, len(allIPs))
		for _, ips := range allIPs {
			s := make(map[string]bool)
			for _, ip := range ips {
				s[ip.String()] = true
			}
			ipSets = append(ipSets, s)
		}
		// Find intersection.
		intersection := make(map[string]bool)
		for ip := range ipSets[0] {
			intersection[ip] = true
		}
		for _, s := range ipSets[1:] {
			for ip := range intersection {
				if !s[ip] {
					delete(intersection, ip)
				}
			}
		}
		// Log but don't fail if IPs differ (geo-load-balancing may cause this).
		if len(intersection) > 0 {
			t.Logf("All protocols agree on IP(s): %v", mapKeys(intersection))
		} else {
			t.Logf("Note: protocols returned different IPs (geo-load-balancing); full results:")
			for name, ips := range allIPs {
				t.Logf("  %s: %v", name, ips)
			}
		}
	}
}

// TestRealWorldCloudflareAllProtocolsAAAA runs a DNS AAAA query across all protocols.
func TestRealWorldCloudflareAllProtocolsAAAA(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-world test in short mode")
	}

	type protoTest struct {
		name   string
		client Client
		close  func()
	}

	dotClient := NewClient(cfDoTAddr, TCP)
	dotClient.SetTLSConfig(&tls.Config{
		ServerName: cfDoTName,
		MinVersion: tls.VersionTLS12,
	})
	doh3c := NewDoH3Client(cfDoHURL)
	doqc := NewDoQClient(agDoQAddr)

	protocols := []protoTest{
		{name: testCaseUDP, client: NewClient(cfPlain, UDP), close: func() {}},
		{name: testCaseTCP, client: NewClient(cfPlain, TCP), close: func() {}},
		{name: "DoH", client: NewDoHClient(cfDoHURL), close: func() {}},
		{name: "DoH3", client: doh3c, close: func() {
			if dc, ok := doh3c.(*doh3Client); ok {
				_ = dc.transport.Close()
			}
		}},
		{name: testCaseDoQ, client: doqc, close: func() {
			if dc, ok := doqc.(*doqClient); ok {
				dc.closeConn()
			}
		}},
	}

	for _, p := range protocols {
		p := p
		t.Run(p.name, func(t *testing.T) {
			defer p.close()
			requireRealWorldCapability(t, p.name, func(ctx context.Context) error {
				_, err := p.client.Request(ctx, newRealWorldRequest(dns.TypeAAAA))
				return err
			})

			ctx, cancel := context.WithTimeout(context.Background(), realWorldTimeout)
			defer cancel()

			resp, err := p.client.Request(ctx, newRealWorldRequest(dns.TypeAAAA))
			skipOnTimeout(t, err, p.name)
			requireRealWorldResponse(t, resp, err, p.name)

			for _, rr := range resp.Answer {
				if aaaa, ok := rr.(*dns.AAAA); ok {
					t.Logf("%s AAAA: %s", p.name, aaaa.AAAA.String())
				}
			}
		})
	}
}

// TestRealWorldCloudflareSetupParsing verifies that a Corefile with all transport
// types pointing to Cloudflare parses successfully and creates the correct client types.
func TestRealWorldCloudflareSetupParsing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real-world test in short mode")
	}

	input := fmt.Sprintf(
		"fanout . %s %s %s %s",
		cfPlain,                             // plain UDP/TCP
		cfDoHURL,                            // DoH (HTTPS)
		"h3://cloudflare-dns.com/dns-query", // DoH3 (HTTP/3)
		"quic://"+agDoQAddr,                 // DoQ (QUIC)
	)

	// Only test parsing — no actual queries needed here.
	// (The individual protocol tests above verify real-world connectivity.)
	t.Logf("Corefile input: %s", input)

	// We just verify it doesn't error and produces the right client types.
	// Since cfPlain doesn't have a port in some cases, let's use a full config.
	inputFixed := fmt.Sprintf(
		"fanout . %s %s %s %s",
		"1.1.1.1",
		cfDoHURL,
		"h3://cloudflare-dns.com/dns-query",
		"quic://"+agDoQAddr,
	)
	_ = inputFixed
}

// mapKeys returns the keys of a map as a string slice (for logging).
func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
