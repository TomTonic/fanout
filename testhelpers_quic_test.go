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
// retryingClient, which surfaces with two different messages depending on the client.
//
// DoQ dials QUIC directly, so quic-go's HandshakeIdleTimeout is what gives up, with
// "no recent network activity". DoH3 goes through an http.Client whose Timeout is
// readTimeout+dialTimeout (4s), and that cap is reached first, so the stall arrives
// as "Client.Timeout exceeded while awaiting headers" instead - the server never sent
// response headers because the QUIC handshake underneath never completed.
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
}

// Request implements Client.
func (c retryingClient) Request(ctx context.Context, r *request.Request) (*dns.Msg, error) {
	resp, err := c.Client.Request(ctx, r)
	if !isQUICHandshakeStall(err) {
		return resp, err
	}
	c.tb.Helper()
	c.tb.Logf("retrying after a stalled QUIC handshake: %v", err)
	if rc, ok := c.Client.(interface{ resetConn() }); ok {
		rc.resetConn()
	}
	return c.Client.Request(ctx, r)
}

// unwrap returns the wrapped client, for the few tests that need the concrete type.
func (c retryingClient) unwrap() Client { return c.Client }

// newRetryingDoQClient builds a DoQ client that tolerates the handshake stall above.
func newRetryingDoQClient(tb testing.TB, addr string, cfg *tls.Config) Client {
	tb.Helper()
	return retryingClient{Client: newDoQClientWithTLS(addr, cfg), tb: tb}
}

// newRetryingDoH3Client builds a DoH3 client that tolerates the handshake stall above.
func newRetryingDoH3Client(tb testing.TB, endpoint string, cfg *tls.Config) Client {
	tb.Helper()
	return retryingClient{Client: newDoH3ClientWithTLS(endpoint, cfg), tb: tb}
}

// concreteClient unwraps the retry wrapper, for tests that reach into the concrete
// client to inspect or manipulate its connection state.
func concreteClient(c Client) Client {
	if rc, ok := c.(retryingClient); ok {
		return rc.unwrap()
	}
	return c
}
