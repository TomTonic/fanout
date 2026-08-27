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
	"testing"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/pkg/fuzz"
	"github.com/miekg/dns"
)

// FuzzDomainAddAndContains fuzzes the Domain trie that backs the except / except-file
// directives. It feeds arbitrary strings into AddString and Contains to find panics,
// index-out-of-range errors, or infinite loops in the trie traversal logic.
func FuzzDomainAddAndContains(f *testing.F) {
	// Seed corpus with representative inputs
	f.Add("example.com.")
	f.Add(".")
	f.Add("a.b.c.d.e.f.")
	f.Add("")
	f.Add("a")
	f.Add("..")
	f.Add("com.")
	f.Add("very.deep.sub.domain.example.org.")

	f.Fuzz(func(_ *testing.T, input string) {
		d := NewDomain()
		d.AddString(input)  // must not panic
		d.Contains(input)   // must not panic
		d.Contains("other") // must not panic even with arbitrary trie state
	})
}

// FuzzServeDNS fuzzes the full plugin request path: arbitrary bytes are parsed as a DNS
// message and served through Fanout against a live reflecting upstream. Where
// FuzzDomainAddAndContains covers only the exclusion trie, this exercises message
// parsing, upstream forwarding, response selection and the write-back path together.
func FuzzServeDNS(f *testing.F) {
	// Seed with well-formed queries so the fuzzer starts from inputs that reach the
	// forwarding path, rather than spending its budget on messages that fail to unpack.
	seedQuery := func(qname string, qtype uint16) {
		f.Helper()
		m := new(dns.Msg)
		m.SetQuestion(qname, qtype)
		packed, err := m.Pack()
		if err != nil {
			f.Fatalf("packing seed query %q: %v", qname, err)
		}
		f.Add(packed)
	}
	seedQuery("example.com.", dns.TypeA)
	seedQuery(".", dns.TypeNS)
	seedQuery("a.very.deep.sub.domain.example.org.", dns.TypeAAAA)
	seedQuery("example.org.", dns.TypeTXT)
	f.Add([]byte{})     // empty input
	f.Add([]byte{0x00}) // too short to be a header

	upstream := dnstest.NewServer(func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(r)
		logErrIfNotNil(w.WriteMsg(reply))
	})
	f.Cleanup(upstream.Close)

	// Two upstreams over different transports, so fan-out and response selection are
	// exercised rather than a single-client short path.
	fan := New()
	fan.From = "."
	fan.AddClient(NewClient(upstream.Addr, TCP))
	fan.AddClient(NewClient(upstream.Addr, UDP))
	f.Cleanup(func() { logErrIfNotNil(fan.OnShutdown()) })

	f.Fuzz(func(_ *testing.T, data []byte) {
		fuzz.Do(fan, data) // must not panic on any input
	})
}
