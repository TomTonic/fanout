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
	"sync/atomic"
	"testing"

	"github.com/coredns/coredns/plugin/cache"
	"github.com/coredns/coredns/plugin/dnstap"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"
	tap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// chainUpstream is a Client double for the tests that put real CoreDNS plugins in
// front of fanout. It counts how often fanout actually contacted the upstream, which
// is the observable that tells a cache hit from a cache miss.
type chainUpstream struct {
	calls atomic.Int32
	// reply builds the upstream answer; a nil result together with a non-nil err
	// simulates an unreachable upstream.
	reply func(req *dns.Msg) (*dns.Msg, error)
}

func (c *chainUpstream) Request(_ context.Context, r *request.Request) (*dns.Msg, error) {
	c.calls.Add(1)
	return c.reply(r.Req)
}
func (c *chainUpstream) Endpoint() string           { return "192.0.2.1:53" }
func (c *chainUpstream) Net() string                { return UDP }
func (c *chainUpstream) SetTLSConfig(_ *tls.Config) {}

var errChainUpstreamDown = errors.New("upstream unreachable")

// downUpstream returns a chainUpstream whose every attempt fails.
func downUpstream() *chainUpstream {
	return &chainUpstream{reply: func(*dns.Msg) (*dns.Msg, error) { return nil, errChainUpstreamDown }}
}

// answeringUpstream returns a chainUpstream that answers every A query with a
// non-authoritative NOERROR response, like a recursive resolver would.
func answeringUpstream() *chainUpstream {
	return &chainUpstream{reply: func(req *dns.Msg) (*dns.Msg, error) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.RecursionAvailable = true
		m.Answer = []dns.RR{test.A("example1. 300 IN A 192.0.2.7")}
		return m, nil
	}}
}

// newChainFanout wires a single-attempt fanout around up so failures surface quickly.
func newChainFanout(t *testing.T, up Client) *Fanout {
	t.Helper()
	f := New()
	shutdownAfterTest(t, f)
	f.From = "."
	f.Attempts = 1
	f.AddClient(up)
	return f
}

func chainQuery() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(testQuery, dns.TypeA)
	return m
}

// TestChain_CacheRemembersTotalUpstreamFailure verifies that clients retrying a name
// whose upstreams are all down are answered with SERVFAIL by the cache instead of
// each retry fanning out to every upstream again.
//
// This covers the interplay of the CoreDNS cache plugin (v1.15.0 "Cache SERVFAIL when
// the resolver fails without a response") with fanout, which reports a total upstream
// failure as (SERVFAIL, error) without writing a message.
//
// It sends the same query twice through cache -> fanout and asserts that the second
// query is a SERVFAIL served from the cache, i.e. the upstream was contacted only once.
func TestChain_CacheRemembersTotalUpstreamFailure(t *testing.T) {
	verifyNoLeaks(t)
	up := downUpstream()
	c := cache.New()
	c.Next = newChainFanout(t, up)

	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	rcode, err := c.ServeDNS(context.Background(), rec, chainQuery())
	require.Equal(t, dns.RcodeServerFailure, rcode)
	require.ErrorIs(t, err, errChainUpstreamDown)
	require.Nil(t, rec.Msg, "fanout must leave the SERVFAIL to the server; nothing is written")
	require.EqualValues(t, 1, up.calls.Load())

	rec = dnstest.NewRecorder(&test.ResponseWriter{})
	rcode, err = c.ServeDNS(context.Background(), rec, chainQuery())
	require.NoError(t, err)
	require.Equal(t, dns.RcodeSuccess, rcode, "a cache hit writes its own answer")
	require.NotNil(t, rec.Msg)
	require.Equal(t, dns.RcodeServerFailure, rec.Msg.Rcode)
	require.EqualValues(t, 1, up.calls.Load(), "the retry must be served from the cache, not from the upstream")
}

// TestChain_CacheDoesNotRememberCanceledQueries verifies that a query the client
// gave up on is not turned into a cached SERVFAIL for everybody else.
//
// This covers the same cache/fanout seam as above; CoreDNS only stores the failure
// while the request context is still alive.
//
// It sends a query with an already canceled context, then a healthy one, and asserts
// that the second query reaches the upstream and is answered normally.
func TestChain_CacheDoesNotRememberCanceledQueries(t *testing.T) {
	verifyNoLeaks(t)
	up := answeringUpstream()
	c := cache.New()
	c.Next = newChainFanout(t, up)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	rcode, err := c.ServeDNS(canceled, rec, chainQuery())
	require.Equal(t, dns.RcodeServerFailure, rcode)
	require.Error(t, err)

	rec = dnstest.NewRecorder(&test.ResponseWriter{})
	rcode, err = c.ServeDNS(context.Background(), rec, chainQuery())
	require.NoError(t, err)
	require.Equal(t, dns.RcodeSuccess, rcode)
	require.NotNil(t, rec.Msg)
	require.Equal(t, dns.RcodeSuccess, rec.Msg.Rcode)
	require.NotEmpty(t, rec.Msg.Answer)
}

// TestChain_CachedAnswerKeepsUpstreamAuthoritativeBit verifies that an answer
// served from the cache carries the same AA flag as the answer fanout delivered on
// the cache miss.
//
// This covers CoreDNS v1.15.0 "Stop setting AA on answers served from cache": until
// 1.14 a hit always claimed AA=1 even though fanout relays recursive, non-authoritative
// answers, so clients saw the flag flip between the first and later queries.
//
// It queries twice through cache -> fanout and asserts AA is false both times and that
// only the first query reached the upstream.
func TestChain_CachedAnswerKeepsUpstreamAuthoritativeBit(t *testing.T) {
	verifyNoLeaks(t)
	up := answeringUpstream()
	c := cache.New()
	c.Next = newChainFanout(t, up)

	for i, label := range []string{"miss", "hit"} {
		rec := dnstest.NewRecorder(&test.ResponseWriter{})
		rcode, err := c.ServeDNS(context.Background(), rec, chainQuery())
		require.NoError(t, err, label)
		require.Equal(t, dns.RcodeSuccess, rcode, label)
		require.NotNil(t, rec.Msg, label)
		require.False(t, rec.Msg.Authoritative, "AA must not be synthesized on a cache %s (query %d)", label, i+1)
		require.NotEmpty(t, rec.Msg.Answer, label)
	}
	require.EqualValues(t, 1, up.calls.Load())
}

// tapTypes returns the dnstap message types in emission order.
func tapTypes(s *dnstapIOStub) []tap.Message_Type {
	types := make([]tap.Message_Type, 0, len(s.msgs))
	for _, m := range s.msgs {
		types = append(types, m.GetMessage().GetType())
	}
	return types
}

// newTappedFanout puts the real dnstap handler in front of fanout, wired the way
// setup.go does it at startup (fanout.TapPlugin points at the handler).
func newTappedFanout(t *testing.T, up Client) (*dnstap.Dnstap, *dnstapIOStub) {
	t.Helper()
	f := newChainFanout(t, up)
	d := &dnstap.Dnstap{Next: f}
	stub := &dnstapIOStub{}
	injectDnstapIO(t, d, stub)
	f.TapPlugin = d
	return d, stub
}

// TestChain_DnstapRecordsClientResponseWhenAllUpstreamsFail verifies that operators
// reading a dnstap stream see a CLIENT_RESPONSE for a query fanout could not answer.
//
// This covers CoreDNS v1.15.0 "Tap deferred error responses": fanout returns
// (SERVFAIL, error) without writing, and the dnstap handler now synthesizes the
// response the server will send afterwards.
//
// It asserts the stream is exactly CLIENT_QUERY followed by CLIENT_RESPONSE; fanout
// itself emits no FORWARDER_* messages because it never got an upstream answer.
func TestChain_DnstapRecordsClientResponseWhenAllUpstreamsFail(t *testing.T) {
	verifyNoLeaks(t)
	d, stub := newTappedFanout(t, downUpstream())

	rcode, err := d.ServeDNS(context.Background(), &test.ResponseWriter{}, chainQuery())
	require.Equal(t, dns.RcodeServerFailure, rcode)
	require.Error(t, err)
	require.Equal(t, []tap.Message_Type{tap.Message_CLIENT_QUERY, tap.Message_CLIENT_RESPONSE}, tapTypes(stub))
}

// TestChain_DnstapRecordsOneClientResponseOnSuccess verifies that a successful
// fanout answer is tapped as one complete conversation and the new deferred-response
// synthesis in CoreDNS does not add a duplicate.
//
// This covers the dnstap handler / fanout seam on the success path, where fanout
// writes the response itself and also reports FORWARDER_* messages for the winning
// upstream.
//
// It asserts the order CLIENT_QUERY, FORWARDER_QUERY, FORWARDER_RESPONSE,
// CLIENT_RESPONSE with exactly one CLIENT_RESPONSE.
func TestChain_DnstapRecordsOneClientResponseOnSuccess(t *testing.T) {
	verifyNoLeaks(t)
	d, stub := newTappedFanout(t, answeringUpstream())

	rcode, err := d.ServeDNS(context.Background(), &test.ResponseWriter{}, chainQuery())
	require.NoError(t, err)
	require.Equal(t, dns.RcodeSuccess, rcode)
	require.Equal(t, []tap.Message_Type{
		tap.Message_CLIENT_QUERY,
		tap.Message_FORWARDER_QUERY,
		tap.Message_FORWARDER_RESPONSE,
		tap.Message_CLIENT_RESPONSE,
	}, tapTypes(stub))
}
