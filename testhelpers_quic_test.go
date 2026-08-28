// Copyright (c) 2026 Tom Gelhausen; contributors: various coding-agents.
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
	"strings"
	"testing"
	"time"

	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// quicTestTimeout is the watchdog deadline for a QUIC-based request in a test.
//
// It is a watchdog, not a latency assertion: no loopback DoQ or DoH3 exchange should
// take anywhere near this long, and nothing asserts that it does. The previous value
// of 5s was actively harmful because it collided with quic-go's own default
// HandshakeIdleTimeout, which is also 5s. When a handshake stalled, whichever of the
// two fired first decided the error message, so the same underlying event surfaced
// sometimes as "context deadline exceeded" and sometimes as "timeout: no recent
// network activity". Giving the context plenty of room makes quic-go the only thing
// that can time out a stalled handshake, so the failure has one signature and
// retryingClient below can recognise it.
const quicTestTimeout = 30 * time.Second

// isQUICHandshakeStall reports whether err is the loopback stall described on
// retryingClient.
//
// Both DoQ and DoH3 dial QUIC directly (neither keeps an http.Client.Timeout or other
// clock of its own any more - see doqQUICConfig and doh3QUICConfig), so quic-go's
// HandshakeIdleTimeout is what gives up on a stall, with "no recent network activity".
// newRetryingDoH3Client raises DoH3's copy of it to quicTestTimeout for the same reason
// DoQ's production default is already below quicTestTimeout: so quic-go, not our own
// context deadline, is what is left to time out the handshake. The
// "Client.Timeout exceeded while awaiting headers" match is dead in production now that
// doh3Client has no Client.Timeout, but costs nothing to keep as a defensive fallback.
//
// Neither string matches a plain context deadline, which several tests assert on
// purpose, and neither matches a DNS- or protocol-level error.
func isQUICHandshakeStall(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "no recent network activity") ||
		strings.Contains(msg, "Client.Timeout exceeded while awaiting headers")
}

// retryingClient retries a request once when the QUIC handshake stalled.
//
// Roughly one loopback QUIC handshake in a few hundred never completes. This was
// measured directly, in-process, with counting wrappers on the server's PacketConn:
// in a stalled attempt the server read 8 packets and wrote 12 replies, so it was
// receiving the client's Initials and answering them - the answers simply never
// reached the client, which then hit quic-go's 5s HandshakeIdleTimeout. The stall is
// independent of our context deadlines, does not need CPU load to appear (it survives
// full saturation of all cores), and disappears when quic-go debug logging slows
// things down. It is not something the fanout code or these test servers control.
//
// At about 0.2-0.5% per test and roughly 30 QUIC tests, that alone failed something
// like one full suite run in six. Retrying makes it negligible without weakening any
// assertion: the retry fires only on the stall signature, so a genuine protocol or
// DNS-level error still fails the test on the first attempt.
//
// Production is unaffected. It is not that fanout ignores this case - it is that
// fanout already retries at a higher layer, in processClient, per the configured
// Attempts. These tests call Client.Request directly and so bypass that retry; this
// wrapper puts it back for the tests that are about DNS semantics rather than about
// failure handling.
type retryingClient struct {
	Client
	tb testing.TB
	// reset drops whatever the failed attempt left behind, so the next attempt dials a
	// genuinely new connection. Without it the retry is pointless.
	reset func()
}

// quicStallAttempts is how many times a request may be re-sent after a stalled
// handshake before the test is allowed to fail.
//
// One retry is not always enough. The reset below cannot drop a pooled DoH3
// connection whose use count has not fallen back to zero yet, so a retry can land on
// the same dead connection and stall again; a short pause between attempts gives that
// bookkeeping time to settle. Three attempts takes the residual far below the rate of
// the stall itself while still failing promptly on a real defect, which reproduces on
// every attempt rather than intermittently.
const quicStallAttempts = 3

// Request implements Client.
func (c retryingClient) Request(ctx context.Context, r *request.Request) (*dns.Msg, error) {
	c.tb.Helper()
	var resp *dns.Msg
	var err error
	for attempt := range quicStallAttempts {
		resp, err = c.Client.Request(ctx, r)
		if !isQUICHandshakeStall(err) {
			return resp, err
		}
		c.tb.Logf("attempt %d hit a stalled QUIC handshake: %v", attempt+1, err)
		if c.reset != nil {
			c.reset()
		}
		if ctx.Err() != nil {
			break
		}
		time.Sleep(quicStallResetDelay)
	}
	return resp, err
}

// quicStallResetDelay lets a just-failed connection finish leaving the pool before
// the next attempt dials.
const quicStallResetDelay = 50 * time.Millisecond

// unwrap returns the wrapped client, for the few tests that need the concrete type.
func (c retryingClient) unwrap() Client { return c.Client }

// newRetryingDoQClient builds a DoQ client that tolerates the handshake stall above.
//
// resetConn is enough here: doqClient caches a single *quic.Conn and clearing it makes
// the next request dial afresh.
func newRetryingDoQClient(tb testing.TB, addr string, cfg *tls.Config) Client {
	tb.Helper()
	inner := newDoQClientWithTLS(addr, cfg)
	reset := func() {
		if dc, ok := inner.(*doqClient); ok {
			dc.resetConn()
		}
	}
	return retryingClient{Client: inner, tb: tb, reset: reset}
}

// newRetryingDoH3Client builds a DoH3 client that tolerates the handshake stall above.
//
// It also raises the transport's QUIC handshake timeout for the duration of the test. In
// production doh3Client sets QUICConfig.HandshakeIdleTimeout to maxAttemptBudget (4s, see
// doh3QUICConfig) so a stalled dial gives up on the same clock as everything else instead
// of outliving the ctx deadline it is bound to. That is shorter than quicTestTimeout, so
// left alone it would still be what cuts a stalled handshake off, rather than letting it
// fail on quic-go's own terms with a single clear signature. Raising it here does not
// touch production: doh3Client has no Client.Timeout of its own any more, so the request's
// only remaining clock is whichever of ctx and QUICConfig is shorter, and the caller's ctx
// (quicTestTimeout) is what's meant to own it in these tests.
//
// Resetting a DoH3 client is harder than resetting a DoQ one, and getting it wrong is
// what made the earlier retries useless. http3.Transport.Close is documented as
// terminal, so it cannot be used on a client that has to keep working;
// CloseIdleConnections looked right but silently skips any connection whose use count
// has not dropped back to zero, which is exactly the state a stalled dial leaves behind
// - so every retry went back to the same dead connection and stalled again, three times
// over. SetTLSConfig is the one path that genuinely swaps in a fresh http3.Transport,
// and it retires the old one through the client's normal grace-period machinery, so
// Close still cleans everything up and goleak stays satisfied.
func newRetryingDoH3Client(tb testing.TB, endpoint string, cfg *tls.Config) Client {
	tb.Helper()
	inner := newDoH3ClientWithTLS(endpoint, cfg)
	liftHandshakeIdleTimeout(inner)
	reset := func() {
		inner.SetTLSConfig(cfg)
		liftHandshakeIdleTimeout(inner)
	}
	return retryingClient{Client: inner, tb: tb, reset: reset}
}

// liftHandshakeIdleTimeout raises a doh3Client's QUIC handshake timeout to
// quicTestTimeout, so a stalled handshake fails on quic-go's own terms during tests
// instead of the shorter production default (see newRetryingDoH3Client).
func liftHandshakeIdleTimeout(c Client) {
	dc, ok := c.(*doh3Client)
	if !ok {
		return
	}
	dc.mu.Lock()
	defer dc.mu.Unlock()
	if dc.transport.QUICConfig == nil {
		dc.transport.QUICConfig = &quic.Config{}
	}
	dc.transport.QUICConfig.HandshakeIdleTimeout = quicTestTimeout
}

// concreteClient unwraps the retry wrapper, for tests that reach into the concrete
// client to inspect or manipulate its connection state.
func concreteClient(c Client) Client {
	if rc, ok := c.(retryingClient); ok {
		return rc.unwrap()
	}
	return c
}
