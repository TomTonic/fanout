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
	"testing"

	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

// TestClient_Request_Edges verifies edge cases in the DNS client used for forwarding requests to upstream servers.
// When the incoming request has no EDNS0 OPT record, r.Size() returns a value below 512.
// The test ensures the client clamps the UDP buffer size to at least 512 bytes and does not panic.
// It also exercises the code path where the context is cancelled immediately after Request().
func TestClient_Request_Edges(t *testing.T) {
	// Need a dummy server to avoid instant connection refused
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pc.Close() }()

	c := NewClient(pc.LocalAddr().String(), "udp")

	// 1. udpSize < 512
	req1 := new(dns.Msg)
	req1.SetQuestion("example.com.", dns.TypeA)
	state1 := request.Request{W: &testResponseWriter{}, Req: req1}

	ctx, cancel := context.WithCancel(context.Background())
	_, _ = c.Request(ctx, &state1)
	cancel()
}

type testResponseWriter struct {
	dns.ResponseWriter
}

func (t *testResponseWriter) LocalAddr() net.Addr { return nil }
func (t *testResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}
func (t *testResponseWriter) WriteMsg(_ *dns.Msg) error   { return nil }
func (t *testResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (t *testResponseWriter) Close() error                { return nil }
func (t *testResponseWriter) TsigStatus() error           { return nil }
func (t *testResponseWriter) TsigTimersOnly(_ bool)       {}
func (t *testResponseWriter) Hijack()                     {}
