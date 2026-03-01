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
	"testing"

	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// TestUseRequestSizeOnConn verifies that the client propagates the EDNS0 buffer size from the
// original request onto the upstream connection, so that large responses are not silently truncated.
// A query with dns.DefaultMsgSize is sent to a dummy server returning three large A records.
// The test asserts all three records arrive intact, confirming the buffer size is set correctly.
func TestUseRequestSizeOnConn(t *testing.T) {
	s := newServer("udp", func(w dns.ResponseWriter, r *dns.Msg) {
		msg := dns.Msg{
			Answer: []dns.RR{
				makeRecordA("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk. 3600	IN	A 10.0.0.1"),
				makeRecordA("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk. 3600	IN	A 10.0.0.1"),
				makeRecordA("abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk. 3600	IN	A 10.0.0.1"),
			},
		}
		msg.SetReply(r)
		logErrIfNotNil(w.WriteMsg(&msg))
	})
	defer s.close()
	c := NewClient(s.addr, "udp")
	req := new(dns.Msg)
	req.SetEdns0(dns.DefaultMsgSize, false)
	req.SetQuestion(testQuery, dns.TypeA)

	ctx, cancel := context.WithCancel(context.TODO())
	defer cancel()
	d, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.Nil(t, err)
	require.Len(t, d.Answer, 3)
}
