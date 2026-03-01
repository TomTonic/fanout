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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/metadata"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// ---------------------------------------------------------------------------
// P1 – Critical functional gaps
// ---------------------------------------------------------------------------

// TestServeDNS_ConcurrentRequests verifies that calling ServeDNS from many goroutines
// simultaneously does not cause data races, panics, or goroutine leaks.
// This exercises the thread-safety of the Fanout instance, the client pool,
// the response channel, and the server-selection policy under concurrent load.
func TestServeDNS_ConcurrentRequests(t *testing.T) {
	defer goleak.VerifyNone(t)
	s := newServer(TCP, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, test.A("example1. IN A 10.0.0.1"))
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer s.close()

	f := New()
	f.From = "."
	f.net = TCP
	f.AddClient(NewClient(s.addr, TCP))

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	var errCount int32

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			req := new(dns.Msg)
			req.SetQuestion(testQuery, dns.TypeA)
			_, err := f.ServeDNS(context.Background(), &test.ResponseWriter{}, req)
			if err != nil {
				atomic.AddInt32(&errCount, 1)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, int32(0), atomic.LoadInt32(&errCount), "no ServeDNS call should fail")
}

// TestServeDNS_MetadataUpstream verifies that after a successful fanout, the plugin sets
// the metadata label "fanout/upstream" to the endpoint address of the server that provided
// the selected response. Other plugins (e.g. logging, metrics) consume this metadata.
func TestServeDNS_MetadataUpstream(t *testing.T) {
	defer goleak.VerifyNone(t)
	s := newServer(TCP, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, test.A("example1. IN A 10.0.0.1"))
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer s.close()

	f := New()
	f.From = "."
	f.net = TCP
	f.AddClient(NewClient(s.addr, TCP))

	ctx := metadata.ContextWithMetadata(context.Background())
	req := new(dns.Msg)
	req.SetQuestion(testQuery, dns.TypeA)
	_, err := f.ServeDNS(ctx, &test.ResponseWriter{}, req)
	require.NoError(t, err)

	vf := metadata.ValueFunc(ctx, "fanout/upstream")
	require.NotNil(t, vf, "metadata 'fanout/upstream' must be set after successful fanout")
	require.Equal(t, s.addr, vf(), "metadata value must equal the answering server's endpoint")
}

// TestServeDNS_MalformedUpstreamResponse verifies that the plugin handles a server that
// returns garbage bytes (not a valid DNS message) gracefully. The client's ReadMsg call
// must return an error, the plugin must not panic, and it should return ServerFailure.
func TestServeDNS_MalformedUpstreamResponse(t *testing.T) {
	defer goleak.VerifyNone(t)
	s := newServer(TCP, func(w dns.ResponseWriter, _ *dns.Msg) {
		// Write invalid DNS wire data; for TCP the dns library adds the 2-byte length prefix.
		_, _ = w.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF})
	})
	defer s.close()

	f := New()
	f.From = "."
	f.net = TCP
	f.Attempts = 1
	f.Timeout = 2 * time.Second
	f.AddClient(NewClient(s.addr, TCP))

	req := new(dns.Msg)
	req.SetQuestion(testQuery, dns.TypeA)
	rcode, err := f.ServeDNS(context.Background(), &test.ResponseWriter{}, req)
	require.Equal(t, dns.RcodeServerFailure, rcode, "malformed upstream response must cause SERVFAIL")
	require.Error(t, err)
}

// ---------------------------------------------------------------------------
// P2 – Robustness
// ---------------------------------------------------------------------------

// TestServeDNS_InfiniteRetryWithContextTimeout verifies that when Attempts is set to 0
// (infinite retries) and the upstream server never responds, the plugin does not hang
// but terminates cleanly once the configured timeout expires, returning ServerFailure.
func TestServeDNS_InfiniteRetryWithContextTimeout(t *testing.T) {
	defer goleak.VerifyNone(t)
	s := newServer(TCP, func(_ dns.ResponseWriter, _ *dns.Msg) {
		time.Sleep(10 * time.Second) // never respond in time
	})
	defer s.close()

	f := New()
	f.From = "."
	f.net = TCP
	f.Attempts = 0 // infinite retries
	f.Timeout = 500 * time.Millisecond
	f.AddClient(NewClient(s.addr, TCP))

	req := new(dns.Msg)
	req.SetQuestion(testQuery, dns.TypeA)

	start := time.Now()
	rcode, _ := f.ServeDNS(context.Background(), &test.ResponseWriter{}, req)
	elapsed := time.Since(start)

	require.Equal(t, dns.RcodeServerFailure, rcode)
	require.Less(t, elapsed, 5*time.Second, "should not hang; must respect the timeout")
}

// TestServeDNS_TruncatedResponse verifies that when an upstream server returns a response
// with the TC (Truncated) bit set, the plugin forwards it as-is to the client. Unlike the
// forward plugin, fanout does not perform automatic TCP retry on truncation.
func TestServeDNS_TruncatedResponse(t *testing.T) {
	defer goleak.VerifyNone(t)
	s := newServer(UDP, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Truncated = true
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer s.close()

	f := New()
	f.From = "."
	f.AddClient(NewClient(s.addr, UDP))

	req := new(dns.Msg)
	req.SetQuestion(testQuery, dns.TypeA)
	writer := &cachedDNSWriter{ResponseWriter: new(test.ResponseWriter)}
	_, err := f.ServeDNS(context.Background(), writer, req)
	require.NoError(t, err)
	require.Len(t, writer.answers, 1)
	require.True(t, writer.answers[0].Truncated, "TC bit must be preserved in forwarded response")
}

// TestServeDNS_ConcurrentStress_ManyServersShortTimeout stress-tests the fanout pipeline
// with many upstream servers, high worker count, and a short timeout. Queries are sent
// concurrently. This exercises the worker pool, response channel, context cancellation,
// and goroutine cleanup under realistic contention.
func TestServeDNS_ConcurrentStress_ManyServersShortTimeout(t *testing.T) {
	defer goleak.VerifyNone(t)
	const numServers = 8
	const numQueries = 30

	var servers []*server
	for i := 0; i < numServers; i++ {
		delay := time.Duration(i*50) * time.Millisecond // 0ms–350ms spread
		s := newServer(TCP, func(w dns.ResponseWriter, r *dns.Msg) {
			time.Sleep(delay)
			msg := new(dns.Msg)
			msg.SetReply(r)
			msg.Answer = append(msg.Answer, test.A("example1. IN A 10.0.0.1"))
			logErrIfNotNil(w.WriteMsg(msg))
		})
		servers = append(servers, s)
	}
	defer func() {
		for _, s := range servers {
			s.close()
		}
	}()

	f := New()
	f.From = "."
	f.net = TCP
	f.Timeout = 2 * time.Second
	f.Attempts = 1
	for _, s := range servers {
		f.AddClient(NewClient(s.addr, TCP))
	}

	var wg sync.WaitGroup
	wg.Add(numQueries)
	var errCount int32
	for i := 0; i < numQueries; i++ {
		go func() {
			defer wg.Done()
			req := new(dns.Msg)
			req.SetQuestion(testQuery, dns.TypeA)
			_, err := f.ServeDNS(context.Background(), &test.ResponseWriter{}, req)
			if err != nil {
				atomic.AddInt32(&errCount, 1)
			}
		}()
	}
	wg.Wait()
	require.Equal(t, int32(0), atomic.LoadInt32(&errCount), "stress run should not produce errors")
	// Primary assertion: no panics, no goroutine leaks (verified by goleak).
}

// TestServeDNS_UpstreamWrongIdThenCorrectId verifies the client's read loop that discards
// responses with non-matching DNS message IDs. The server sends a response with a tampered
// ID first, followed by the correct one. The client must ignore the wrong ID and return the
// matching response without error.
func TestServeDNS_UpstreamWrongIdThenCorrectId(t *testing.T) {
	defer goleak.VerifyNone(t)
	s := newServer(TCP, func(w dns.ResponseWriter, r *dns.Msg) {
		// 1st response: wrong ID
		wrong := new(dns.Msg)
		wrong.SetReply(r)
		wrong.Id = r.Id + 1
		wrong.Answer = append(wrong.Answer, test.A("example1. IN A 10.0.0.99"))
		logErrIfNotNil(w.WriteMsg(wrong))

		// 2nd response: correct ID
		correct := new(dns.Msg)
		correct.SetReply(r)
		correct.Answer = append(correct.Answer, test.A("example1. IN A 10.0.0.1"))
		logErrIfNotNil(w.WriteMsg(correct))
	})
	defer s.close()

	f := New()
	f.From = "."
	f.net = TCP
	f.AddClient(NewClient(s.addr, TCP))

	req := new(dns.Msg)
	req.SetQuestion(testQuery, dns.TypeA)
	writer := &cachedDNSWriter{ResponseWriter: new(test.ResponseWriter)}
	_, err := f.ServeDNS(context.Background(), writer, req)
	require.NoError(t, err)
	require.Len(t, writer.answers, 1)
	require.Equal(t, "10.0.0.1", writer.answers[0].Answer[0].(*dns.A).A.String(),
		"must return the response with the matching ID, not the wrong one")
}

// TestServeDNS_ThreeServersSelectBestResponse verifies the best-response selection when
// three servers return different rcodes: SERVFAIL, NXDOMAIN, and SUCCESS. The plugin must
// always return the successful response, exercising the integration of isBetter() in
// getFanoutResult with more than two servers.
func TestServeDNS_ThreeServersSelectBestResponse(t *testing.T) {
	defer goleak.VerifyNone(t)
	// Server 1: SERVFAIL
	s1 := newServer(TCP, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetRcode(r, dns.RcodeServerFailure)
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer s1.close()
	// Server 2: NXDOMAIN
	s2 := newServer(TCP, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetRcode(r, dns.RcodeNameError)
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer s2.close()
	// Server 3: SUCCESS
	s3 := newServer(TCP, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, test.A("example1. IN A 10.0.0.1"))
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer s3.close()

	f := New()
	f.From = "."
	f.net = TCP
	f.AddClient(NewClient(s1.addr, TCP))
	f.AddClient(NewClient(s2.addr, TCP))
	f.AddClient(NewClient(s3.addr, TCP))

	writer := &cachedDNSWriter{ResponseWriter: new(test.ResponseWriter)}
	for i := 0; i < 5; i++ {
		req := new(dns.Msg)
		req.SetQuestion(testQuery, dns.TypeA)
		_, err := f.ServeDNS(context.Background(), writer, req)
		require.NoError(t, err)
	}
	for _, m := range writer.answers {
		require.Equal(t, dns.RcodeSuccess, m.Rcode, "SUCCESS must always win over SERVFAIL/NXDOMAIN")
	}
}

// ---------------------------------------------------------------------------
// P3 – Security & edge cases
// ---------------------------------------------------------------------------

// TestExceptFile_SymlinkIsFollowed documents that except-file follows symbolic links.
// A symlink within the working directory pointing to a file elsewhere will be read.
// This is the current behavior; the test exists to make it explicit and detectable
// if the security posture changes in the future.
func TestExceptFile_SymlinkIsFollowed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks require elevated privileges on Windows")
	}

	// Create target file in a separate directory
	targetDir := t.TempDir()
	targetPath := filepath.Join(targetDir, "domains.txt")
	require.NoError(t, os.WriteFile(targetPath, []byte("symlink-target.example.com."), 0o600))

	// Create symlink in CWD
	cwd, err := os.Getwd()
	require.NoError(t, err)
	symlinkName := "test-symlink-" + t.Name() + ".txt"
	symlinkPath := filepath.Join(cwd, symlinkName)
	require.NoError(t, os.Symlink(targetPath, symlinkPath))
	defer func() { _ = os.Remove(symlinkPath) }()

	source := "fanout . 127.0.0.1 {\nexcept-file " + symlinkName + "\n}"
	c := caddy.NewTestController("dns", source)
	f, parseErr := parseFanout(c)
	require.NoError(t, parseErr, "symlinks in CWD are accepted")
	require.True(t, f.ExcludeDomains.Contains("symlink-target.example.com."),
		"domain from symlinked file must be loaded")
}

// TestDomain_VeryLongDomainName verifies that the Domain trie handles domain names at and
// beyond DNS limits (label max 63 chars, name max 253 chars) without panicking.
// The trie is a pure string structure and does not enforce DNS length constraints itself.
func TestDomain_VeryLongDomainName(t *testing.T) {
	d := NewDomain()

	// Maximum legal DNS name: 3 labels of 63 chars each
	longLabel := strings.Repeat("a", 63)
	longDomain := longLabel + "." + longLabel + "." + longLabel + "."
	d.AddString(longDomain)
	require.True(t, d.Contains(longDomain))

	// Over-long name (>253 chars) – still must not panic
	overLong := strings.Repeat("a.", 200)
	d.AddString(overLong)
	require.True(t, d.Contains(overLong))

	// Empty string – must not panic (trie stores it as any other key)
	d.AddString("")
	d.Contains("")
}

// TestSetup_UnknownDirective verifies that an unrecognized directive inside the fanout block
// is rejected during Corefile parsing with a clear "unknown property" error message.
func TestSetup_UnknownDirective(t *testing.T) {
	source := "fanout . 127.0.0.1 {\nunknown-thing value\n}"
	c := caddy.NewTestController("dns", source)
	_, err := parseFanout(c)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown property")
}

// TestServeDNS_PartialUpstreamResponse verifies that when an upstream server closes the TCP
// connection after sending an incomplete response (length prefix promises more bytes than
// delivered), the client returns an error and the plugin does not panic or hang.
func TestServeDNS_PartialUpstreamResponse(t *testing.T) {
	defer goleak.VerifyNone(t)

	// Raw TCP server that sends a length prefix claiming 255 bytes, then closes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			// Read the client's DNS request (discard it)
			buf := make([]byte, 1024)
			_, _ = conn.Read(buf)
			// Write a TCP DNS length prefix claiming 255 bytes, then close immediately
			_, _ = conn.Write([]byte{0x00, 0xFF})
			_ = conn.Close()
		}
	}()

	f := New()
	f.From = "."
	f.net = TCP
	f.Attempts = 1
	f.Timeout = 2 * time.Second
	f.AddClient(NewClient(ln.Addr().String(), TCP))

	req := new(dns.Msg)
	req.SetQuestion(testQuery, dns.TypeA)
	rcode, sErr := f.ServeDNS(context.Background(), &test.ResponseWriter{}, req)
	require.Equal(t, dns.RcodeServerFailure, rcode)
	require.Error(t, sErr, "partial TCP response must cause an error, not a hang or panic")
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

// BenchmarkServeDNS_Throughput measures end-to-end request throughput of the fanout plugin
// with a single upstream server over TCP. This establishes a performance baseline for
// the full pipeline: client creation, upstream request, response selection, and writing.
func BenchmarkServeDNS_Throughput(b *testing.B) {
	s := newServer(TCP, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, test.A("example1. IN A 10.0.0.1"))
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer s.close()

	f := New()
	f.From = "."
	f.net = TCP
	f.AddClient(NewClient(s.addr, TCP))

	req := new(dns.Msg)
	req.SetQuestion(testQuery, dns.TypeA)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = f.ServeDNS(context.Background(), &test.ResponseWriter{}, req)
	}
}
