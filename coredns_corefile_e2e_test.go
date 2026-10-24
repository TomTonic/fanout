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
	"fmt"
	"net"
	"slices"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	// Registers the bind and cache directives next to the fanout one this package
	// registers itself, so a Corefile can use them like in a real CoreDNS build.
	_ "github.com/coredns/coredns/plugin/bind"
	_ "github.com/coredns/coredns/plugin/cache"
)

// e2eAnswerTTL is the TTL of every answer the e2e upstream hands out. It is also the
// cache's maximum and minimum TTL in the Corefiles below, so an entry goes stale after
// exactly this many seconds.
const e2eAnswerTTL = 2

// e2eUpstream is a UDP DNS server whose behaviour tests flip while the CoreDNS server
// under test is running: it either answers A queries with 192.0.2.<octet> or stays
// silent, which fanout sees as an unreachable upstream.
type e2eUpstream struct {
	srv   *server
	hits  atomic.Int32
	octet atomic.Int32
	down  atomic.Bool
}

func newE2EUpstream(t *testing.T) *e2eUpstream {
	t.Helper()
	u := &e2eUpstream{}
	u.octet.Store(7)
	u.srv = newServer(t, UDP, func(w dns.ResponseWriter, r *dns.Msg) {
		u.hits.Add(1)
		if u.down.Load() {
			return
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.RecursionAvailable = true
		m.Answer = []dns.RR{makeRecordA(fmt.Sprintf("%s %d IN A 192.0.2.%d", r.Question[0].Name, e2eAnswerTTL, u.octet.Load()))}
		_ = w.WriteMsg(m)
	})
	return u
}

// freeUDPAndTCPPort picks a port that is currently free on both protocols, since
// CoreDNS listens on both for a plain server block.
func freeUDPAndTCPPort(t *testing.T) int {
	t.Helper()
	for range 20 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		port := l.Addr().(*net.TCPAddr).Port
		pc, err := net.ListenPacket("udp", "127.0.0.1:"+strconv.Itoa(port))
		logErrIfNotNil(l.Close())
		if err == nil {
			logErrIfNotNil(pc.Close())
			return port
		}
	}
	t.Fatal("no port free on both udp and tcp")
	return 0
}

// startCorefile boots a complete CoreDNS server (listener, plugin chain, server-level
// dispatch) from a Corefile with the directive order bind, cache, fanout, and returns
// the address it listens on. The server is stopped, including the plugins' shutdown
// callbacks, when the test ends.
func startCorefile(t *testing.T, body func(port int) string) string {
	t.Helper()
	orig := slices.Clone(dnsserver.Directives)
	require.NoError(t, dnsserver.SetDirectives([]string{"bind", "cache", "fanout"}))
	prevQuiet := caddy.Quiet
	caddy.Quiet = true

	port := freeUDPAndTCPPort(t)
	inst, err := caddy.Start(caddy.CaddyfileInput{
		Filepath:       "Corefile",
		Contents:       []byte(body(port)),
		ServerTypeName: "dns",
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		for _, e := range inst.ShutdownCallbacks() {
			logErrIfNotNil(e)
		}
		logErrIfNotNil(inst.Stop())
		caddy.Quiet = prevQuiet
		_ = dnsserver.SetDirectives(orig)
	})
	return "127.0.0.1:" + strconv.Itoa(port)
}

// e2eQuery asks addr for the A record of name over UDP and fails the test if no
// reply arrives, since every scenario here expects some answer, even if it is SERVFAIL.
func e2eQuery(t *testing.T, addr, name string) *dns.Msg {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	c := &dns.Client{Net: UDP, Timeout: 3 * time.Second}
	r, _, err := c.Exchange(m, addr)
	require.NoError(t, err)
	return r
}

// answerOctet returns the last octet of the single A record in r, or -1 if r carries none.
func answerOctet(r *dns.Msg) int {
	for _, rr := range r.Answer {
		if a, ok := rr.(*dns.A); ok {
			return int(a.A.To4()[3])
		}
	}
	return -1
}

// fanoutCorefile renders a server block that puts cache (configured by cacheBody) in
// front of a fanout to up, with timeouts short enough for a silent upstream not to
// stall the test.
func fanoutCorefile(port int, cacheBody string, up *e2eUpstream) string {
	return fmt.Sprintf(`.:%d {
    bind 127.0.0.1
    cache {
        %s
    }
    fanout . %s {
        timeout 300ms
        attempt-count 1
    }
}
`, port, cacheBody, up.srv.addr)
}

// TestCorefile_TotalOutageIsAnsweredFromServfailCache verifies that when every
// upstream is unreachable, a household's repeated retries get a quick SERVFAIL instead
// of each one hammering the dead upstreams again.
//
// This covers a full CoreDNS server (cache plugin in front of fanout, started from a
// Corefile) under CoreDNS v1.15.0, where cache stores a SERVFAIL for a next plugin that
// fails without a response, and the server itself turns fanout's (SERVFAIL, error)
// into the reply the client sees.
//
// It asserts the first query yields SERVFAIL after contacting the upstream once, and
// an immediate repeat yields SERVFAIL without contacting it again (counted at the
// upstream rather than timed, so a slow CI runner cannot make it flaky).
func TestCorefile_TotalOutageIsAnsweredFromServfailCache(t *testing.T) {
	up := newE2EUpstream(t)
	up.down.Store(true)
	addr := startCorefile(t, func(port int) string {
		return fanoutCorefile(port, "servfail 30s", up)
	})

	r := e2eQuery(t, addr, "outage.example.")
	require.Equal(t, dns.RcodeServerFailure, r.Rcode)
	require.EqualValues(t, 1, up.hits.Load())

	r = e2eQuery(t, addr, "outage.example.")
	require.Equal(t, dns.RcodeServerFailure, r.Rcode)
	require.EqualValues(t, 1, up.hits.Load(), "the repeat must be served from the cache")
}

// TestCorefile_ServeStaleCoversUpstreamOutageAndRecovers verifies that a household
// keeps resolving names it looked up before the upstreams went down, and gets fresh
// answers again once they are back.
//
// This covers cache's serve_stale (the mode used in the project's local Corefile)
// driving fanout for its background refresh, where fanout is called with a response
// writer that has no client connection behind it.
//
// It warms the cache, takes the upstream down past the TTL, and asserts the stale
// answer is still served and the refresh really went through fanout. It then restores
// the upstream with a different address and asserts the new answer shows up.
func TestCorefile_ServeStaleCoversUpstreamOutageAndRecovers(t *testing.T) {
	up := newE2EUpstream(t)
	addr := startCorefile(t, func(port int) string {
		return fanoutCorefile(port, fmt.Sprintf("success 100 %d %d\n        serve_stale 1h immediate", e2eAnswerTTL, e2eAnswerTTL), up)
	})

	require.Equal(t, 7, answerOctet(e2eQuery(t, addr, "stale.example.")))
	require.EqualValues(t, 1, up.hits.Load())

	up.down.Store(true)
	time.Sleep((e2eAnswerTTL*1000 + 300) * time.Millisecond)

	r := e2eQuery(t, addr, "stale.example.")
	require.Equal(t, dns.RcodeSuccess, r.Rcode)
	require.Equal(t, 7, answerOctet(r), "the expired answer must be served stale, not turned into SERVFAIL")
	require.Eventually(t, func() bool { return up.hits.Load() >= 2 }, 3*time.Second, 20*time.Millisecond,
		"serve_stale immediate must refresh in the background through fanout")

	up.octet.Store(8)
	up.down.Store(false)
	require.Eventually(t, func() bool {
		return answerOctet(e2eQuery(t, addr, "stale.example.")) == 8
	}, 5*time.Second, 100*time.Millisecond, "after recovery the refreshed answer must replace the stale one")
}

// TestCorefile_PrefetchRefreshesThroughFanout verifies that popular names are renewed
// in the background before they expire, so that users never wait on an upstream for
// them.
//
// This covers cache's prefetch driving fanout with a detached response writer, the code
// path CoreDNS v1.15.0 hardened against nil dereferences.
//
// It asserts that a second query is answered from the cache with the old address
// immediately, and that this query alone makes the cache contact the upstream again.
func TestCorefile_PrefetchRefreshesThroughFanout(t *testing.T) {
	up := newE2EUpstream(t)
	addr := startCorefile(t, func(port int) string {
		return fanoutCorefile(port, fmt.Sprintf("success 100 %d %d\n        prefetch 1 10s 90%%", e2eAnswerTTL, e2eAnswerTTL), up)
	})

	require.Equal(t, 7, answerOctet(e2eQuery(t, addr, "prefetch.example.")))
	require.EqualValues(t, 1, up.hits.Load())

	up.octet.Store(8)
	require.Equal(t, 7, answerOctet(e2eQuery(t, addr, "prefetch.example.")), "served from the cache")
	require.Eventually(t, func() bool { return up.hits.Load() == 2 }, 3*time.Second, 20*time.Millisecond,
		"the cache hit must trigger exactly one background refresh through fanout")
	require.Equal(t, 8, answerOctet(e2eQuery(t, addr, "prefetch.example.")), "the prefetched answer replaces the old one")
}
