// Copyright (c) 2020 Doc.ai and/or its affiliates.
// Copyright (c) 2024 MWS and/or its affiliates.
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
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/goleak"
)

const testQuery = "example1."

type cachedDNSWriter struct {
	answers []*dns.Msg
	mutex   sync.Mutex
	*test.ResponseWriter
}

func (w *cachedDNSWriter) WriteMsg(m *dns.Msg) error {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.answers = append(w.answers, m)
	return w.ResponseWriter.WriteMsg(m)
}

type failingDNSWriter struct {
	*test.ResponseWriter
	err error
}

func (w *failingDNSWriter) WriteMsg(_ *dns.Msg) error {
	return w.err
}

type server struct {
	addr  string
	inner *dns.Server
}

func (s *server) close() {
	logErrIfNotNil(s.inner.Shutdown())
}

// testListenHost is the address every test server binds to.
//
// It must be a concrete loopback address, not the wildcard ":0". A wildcard bind
// reports its address back as "[::]:port", and dialing the unspecified address sends
// Go down the dual-stack Happy Eyeballs path (net.resolveAddrList expands "::" into
// both loopback families, so sysDialer.dialParallel runs instead of dialSerial).
// That path costs a second socket, two extra goroutines and a 300ms fallback timer
// per dial, and the losing branch outlives the request: after ServeDNS picks a winner
// and cancels, a dial parked in dialParallel kept the whole worker tree alive for
// ~1s in about a quarter of requests, which is longer than goleak's ~431ms retry
// budget - the direct cause of the intermittent "found unexpected goroutines"
// failures in TestServeDNS_ThreeServersSelectBestResponse and TestFanoutTCPSuite.
//
// Binding loopback explicitly yields a single candidate address, so dialParallel is
// never reached. Measured over 20 request bursts, worst-case teardown dropped from
// 1.07s to 394us and dials got about twice as fast.
const testListenHost = "127.0.0.1"

// newServer starts a DNS test server and registers its shutdown with tb, so callers
// do not carry a defer. It takes testing.TB rather than *testing.T because one caller
// is a benchmark.
//
// Shutdown runs as a cleanup, which is after the caller's own defers. A test that
// unblocks a parked handler by defer therefore still releases it before the server
// waits on it in Shutdown.
func newServer(tb testing.TB, network string, f dns.HandlerFunc) *server {
	tb.Helper()
	ch := make(chan bool)
	s := &dns.Server{}
	s.Handler = f

	// A UDP server needs the same port on both protocols, and the TCP bind is what
	// allocates it. That can lose a race against another process, so retry - closing
	// the TCP listener first, or the next attempt leaks it.
	for range 10 {
		l, err := net.Listen(TCP, testListenHost+":0")
		if err != nil {
			continue
		}
		if network == TCP {
			s.Listener = l
			break
		}
		pc, err := net.ListenPacket(UDP, l.Addr().String())
		if err != nil {
			logErrIfNotNil(l.Close())
			continue
		}
		s.Listener, s.PacketConn = l, pc
		break
	}
	if s.Listener == nil || (network != TCP && s.PacketConn == nil) {
		panic("failed to bind a test server on " + testListenHost)
	}

	s.NotifyStartedFunc = func() { close(ch) }
	go func() {
		logErrIfNotNil(s.ActivateAndServe())
	}()

	<-ch
	srv := &server{inner: s, addr: s.Listener.Addr().String()}
	tb.Cleanup(srv.close)
	return srv
}

// testTimeout is a Fanout.Timeout for tests whose upstreams are deliberately left
// silent, so the per-attempt budget attemptBudget derives from it (see fanout.go) stays
// short instead of the production default.
//
// A silent upstream costs one full per-attempt budget before the caller moves on. With
// the production default (30s / 3 attempts, capped at maxAttemptBudget) that is 4s per
// silent contact. That single value accounted for roughly three quarters of the suite's
// runtime - TestBusyServer paid it five times and TestWorkerCountLessThenServers four
// times, in each of the UDP and TCP suites. Over loopback a response either arrives in
// microseconds or is not coming at all, so 50ms is generous.
const testTimeout = 50 * time.Millisecond

// verifyNoLeaks asserts that a test leaves behind no goroutine that it started.
//
// The baseline matters. goleak.VerifyNone inspects every goroutine in the process, not
// only those belonging to the calling test, so a neighbour's teardown that is still in
// motion - a socket mid-close, a losing Happy Eyeballs dial unwinding - gets reported
// against whichever test happens to check at that moment. That is what made
// TestServeDNS_ThreeServersSelectBestResponse and TestFanoutTCPSuite fail
// intermittently, and it got easier to hit once the suite stopped spacing tests out
// with multi-second sleeps.
//
// IgnoreCurrent records what is already running at the start of the test, so only
// goroutines this test is responsible for can fail it. Registering the check here also
// puts it first in the cleanup order, which - cleanups being LIFO - means it runs last,
// after every server and client the test registers afterwards has shut down.
func verifyNoLeaks(tb testing.TB) {
	tb.Helper()
	ignore := goleak.IgnoreCurrent()
	tb.Cleanup(func() { goleak.VerifyNone(tb, ignore) })
}

// shutdownAfterTest registers f's shutdown with tb, so the upstream clients built
// during Corefile parsing are closed when the test ends rather than outliving it.
// This matters most for h3:// upstreams, whose transports otherwise sit around until
// their grace period expires and show up as leaked goroutines in a later test.
//
// A nil f is accepted and ignored, which is what parseFanout returns on a parse error.
func shutdownAfterTest(tb testing.TB, f *Fanout) {
	tb.Helper()
	if f == nil {
		return
	}
	tb.Cleanup(func() { logErrIfNotNil(f.OnShutdown()) })
}

func makeRecordA(rr string) *dns.A {
	r, _ := dns.NewRR(rr)
	return r.(*dns.A)
}

type fanoutTestSuite struct {
	suite.Suite
	network string
}

// TestFanout_ExceptFile verifies that the except-file Corefile directive reads domain names from
// a file and populates the exclusion list. Writes two domains to a temp file, parses a Corefile
// referencing it, and asserts both domains appear in ExcludeDomains.
func TestFanout_ExceptFile(t *testing.T) {
	file, err := os.CreateTemp(os.TempDir(), t.Name())
	exclude := []string{"example1.com.", "example2.com."}
	require.Nil(t, err)
	defer func() {
		require.Nil(t, os.Remove(file.Name()))
	}()
	_, err = file.WriteString(strings.Join(exclude, "\n"))
	require.Nil(t, err)
	source := fmt.Sprintf(`fanout . 0.0.0.0:53 {
	except-file %v
}`, file.Name())
	c := caddy.NewTestController("dns", source)
	f, err := parseFanout(c)
	shutdownAfterTest(t, f)
	require.Nil(t, err)
	for _, e := range exclude {
		require.True(t, f.ExcludeDomains.Contains(e))
	}
}

// TestConfigFromCorefile is an end-to-end integration test from Corefile parsing through ServeDNS.
// Parses a Corefile with "fanout . <addr> { NETWORK <net> }", starts the plugin lifecycle (OnStartup),
// sends a query, and asserts the correct answer is returned. Runs for both UDP and TCP via the suite.
func (t *fanoutTestSuite) TestConfigFromCorefile() {
	verifyNoLeaks(t.T())
	s := newServer(t.T(), t.network, func(w dns.ResponseWriter, r *dns.Msg) {
		ret := new(dns.Msg)
		ret.SetReply(r)
		ret.Answer = append(ret.Answer, test.A("example.org. IN A 127.0.0.1"))
		logErrIfNotNil(w.WriteMsg(ret))
	})
	source := `fanout . %v {
	NETWORK %v
}`
	c := caddy.NewTestController("dns", fmt.Sprintf(source, s.addr, t.network))
	f, err := parseFanout(c)
	t.Nil(err)
	err = f.OnStartup()
	t.Nil(err)
	defer func() {
		logErrIfNotNil(f.OnShutdown())
	}()

	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})

	_, err = f.ServeDNS(context.TODO(), rec, m)
	t.Nil(err)
	t.Equal(rec.Msg.Answer[0].Header().Name, "example.org.")
}

// TestWorkerCountLessThenServers verifies that WorkerCount limits concurrent upstream queries.
// Sets up 5 servers but WorkerCount=1, so only one server is contacted per query.
// Asserts exactly one answer is produced and no extra goroutines leak.
func (t *fanoutTestSuite) TestWorkerCountLessThenServers() {
	verifyNoLeaks(t.T())
	const expected = 1
	answerCount := 0
	var mutex sync.Mutex
	f := New()
	shutdownAfterTest(t.T(), f)
	f.From = "."

	// These four answer immediately with SERVFAIL rather than staying silent. With
	// WorkerCount=1 they are contacted one after the other before the real server is
	// reached, and an immediate response - rather than a deliberately silent upstream -
	// keeps that walk fast without needing to shrink Fanout.Timeout: processClient's
	// retry loop only waits out the per-attempt budget when an upstream fails to
	// respond at all, not when it responds quickly with a non-success Rcode.
	for range 4 {
		incorrectServer := newServer(t.T(), t.network, func(w dns.ResponseWriter, r *dns.Msg) {
			msg := new(dns.Msg)
			msg.SetRcode(r, dns.RcodeServerFailure)
			logErrIfNotNil(w.WriteMsg(msg))
		})
		f.AddClient(NewClient(incorrectServer.addr, t.network))
	}
	correctServer := newServer(t.T(), t.network, func(w dns.ResponseWriter, r *dns.Msg) {
		if r.Question[0].Name == testQuery {
			msg := dns.Msg{
				Answer: []dns.RR{makeRecordA("example1 3600	IN	A 10.0.0.1")},
			}
			mutex.Lock()
			answerCount++
			mutex.Unlock()
			msg.SetReply(r)
			logErrIfNotNil(w.WriteMsg(&msg))
		}
	})

	f.AddClient(NewClient(correctServer.addr, t.network))
	f.WorkerCount = 1
	f.Attempts = 1
	req := new(dns.Msg)
	req.SetQuestion(testQuery, dns.TypeA)
	_, err := f.ServeDNS(context.TODO(), &test.ResponseWriter{}, req)
	t.Nil(err)
	// No settle time needed. The handler increments answerCount before it writes the
	// reply, and that write is what lets ServeDNS return, so the count is already
	// final here. A second contact is impossible too: WorkerCount=1 means one worker
	// walking the upstreams in sequence, and Attempts=1 means it visits each once.
	mutex.Lock()
	defer mutex.Unlock()
	t.Equal(answerCount, expected)
}

// TestTwoServersUnsuccessfulResponse verifies that when one server returns non-success codes
// (cycling through all rcodes) and the other returns success, the plugin always prefers the
// successful response. Sends 10 queries and asserts every written answer has RcodeSuccess.
func (t *fanoutTestSuite) TestTwoServersUnsuccessfulResponse() {
	verifyNoLeaks(t.T())
	rcode := 1
	rcodeMutex := sync.Mutex{}
	s1 := newServer(t.T(), t.network, func(w dns.ResponseWriter, r *dns.Msg) {
		if r.Question[0].Name == testQuery {
			msg := nxdomainMsg()
			rcodeMutex.Lock()
			msg.SetRcode(r, rcode)
			rcode++
			rcode %= dns.RcodeNotZone
			rcodeMutex.Unlock()
			logErrIfNotNil(w.WriteMsg(msg))
		}
	})
	s2 := newServer(t.T(), t.network, func(w dns.ResponseWriter, r *dns.Msg) {
		if r.Question[0].Name == testQuery {
			msg := dns.Msg{
				Answer: []dns.RR{makeRecordA("example1. 3600	IN	A 10.0.0.1")},
			}
			msg.SetReply(r)
			logErrIfNotNil(w.WriteMsg(&msg))
		}
	})
	c1 := NewClient(s1.addr, t.network)
	c2 := NewClient(s2.addr, t.network)
	f := New()
	shutdownAfterTest(t.T(), f)
	f.net = t.network
	f.From = "."
	f.AddClient(c1)
	f.AddClient(c2)
	writer := &cachedDNSWriter{ResponseWriter: new(test.ResponseWriter)}
	for range 10 {
		req := new(dns.Msg)
		req.SetQuestion(testQuery, dns.TypeA)
		_, err := f.ServeDNS(context.TODO(), writer, req)
		t.Nil(err)
	}
	for _, m := range writer.answers {
		t.Equal(m.Rcode, dns.RcodeSuccess)
	}
}

// TestCanReturnUnsuccessfulRepose verifies that when all upstream servers return NXDOMAIN and
// there is no successful answer to prefer, the plugin still forwards the first negative response
// to the client rather than producing an error.
func (t *fanoutTestSuite) TestCanReturnUnsuccessfulRepose() {
	verifyNoLeaks(t.T())
	s := newServer(t.T(), t.network, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := nxdomainMsg()
		msg.SetRcode(r, msg.Rcode)
		logErrIfNotNil(w.WriteMsg(msg))
	})
	f := New()
	shutdownAfterTest(t.T(), f)
	f.net = t.network
	f.From = "."
	c := NewClient(s.addr, t.network)
	f.AddClient(c)
	req := new(dns.Msg)
	req.SetQuestion(testQuery, dns.TypeA)
	writer := &cachedDNSWriter{ResponseWriter: new(test.ResponseWriter)}
	_, err := f.ServeDNS(context.Background(), writer, req)
	t.Nil(err)
	t.Len(writer.answers, 1)
	t.Equal(writer.answers[0].Rcode, dns.RcodeNameError, "fanout plugin returns first negative answer if other answers on request are negative")
}

// TestBusyServer verifies the retry loop during request forwarding: a server that drops
// every other request should eventually answer all queries. Sends 5 queries and asserts
// that 5 successful answers are received.
//
// This uses a large bounded Attempts rather than 0 (infinite retries). With Attempts==0,
// attemptBudget gives every attempt the full maxAttemptBudget (4s) regardless of
// f.Timeout, since there is no attempt count to divide it by - so this test would cost
// up to 4s per silent round instead of the millisecond-scale budget below. Attempts==0's
// own contract (retry until Timeout, never hang past it) is covered separately by
// TestServeDNS_InfiniteRetryWithContextTimeout.
func (t *fanoutTestSuite) TestBusyServer() {
	verifyNoLeaks(t.T())
	var requestNum, answerCount int32
	totalRequestNum := int32(5)
	s := newServer(t.T(), t.network, func(w dns.ResponseWriter, r *dns.Msg) {
		serverIsBusy := atomic.LoadInt32(&requestNum)%2 == 0
		if !serverIsBusy && r.Question[0].Name == testQuery {
			msg := dns.Msg{
				Answer: []dns.RR{makeRecordA("example1 3600	IN	A 10.0.0.1")},
			}
			atomic.AddInt32(&answerCount, 1)
			msg.SetReply(r)
			logErrIfNotNil(w.WriteMsg(&msg))
		}
		atomic.AddInt32(&requestNum, 1)
	})
	c := NewClient(s.addr, t.network)
	f := New()
	shutdownAfterTest(t.T(), f)
	f.net = t.network
	f.From = "."
	// Attempts and Timeout are chosen together: attemptBudget is timeout/Attempts
	// (capped at maxAttemptBudget), and picking them this way lands it on testTimeout
	// while leaving Timeout - the actual backstop, since each round also pays
	// attemptDelay between attempts - room for well over a dozen rounds. The server
	// stays silent on every other contact, so a run of consecutive silent contacts
	// long enough to exhaust that margin is not realistically expected.
	f.Attempts = 40
	f.Timeout = time.Duration(f.Attempts) * testTimeout
	f.AddClient(c)
	req := new(dns.Msg)
	req.SetQuestion(testQuery, dns.TypeA)
	for range totalRequestNum {
		_, err := f.ServeDNS(context.TODO(), &test.ResponseWriter{}, req)
		t.Nil(err)
	}
	t.Equal(totalRequestNum, atomic.LoadInt32(&answerCount))
}

// TestTwoServers verifies that each query reaches the correct upstream: server 1 answers
// "example1.", server 2 answers "example2.". After both queries, each server has been
// contacted exactly once, confirming fanout routes to all configured upstreams.
func (t *fanoutTestSuite) TestTwoServers() {
	verifyNoLeaks(t.T())
	const expected = 1
	var mutex sync.Mutex
	answerCount1 := 0
	answerCount2 := 0
	s1 := newServer(t.T(), t.network, func(w dns.ResponseWriter, r *dns.Msg) {
		if r.Question[0].Name == testQuery {
			msg := dns.Msg{
				Answer: []dns.RR{makeRecordA("example1 3600	IN	A 10.0.0.1")},
			}
			mutex.Lock()
			answerCount1++
			mutex.Unlock()
			msg.SetReply(r)
			logErrIfNotNil(w.WriteMsg(&msg))
		}
	})
	s2 := newServer(t.T(), t.network, func(w dns.ResponseWriter, r *dns.Msg) {
		if r.Question[0].Name == "example2." {
			msg := dns.Msg{
				Answer: []dns.RR{makeRecordA("example2. 3600	IN	A 10.0.0.1")},
			}
			mutex.Lock()
			answerCount2++
			mutex.Unlock()
			msg.SetReply(r)
			logErrIfNotNil(w.WriteMsg(&msg))
		}
	})

	c1 := NewClient(s1.addr, t.network)
	c2 := NewClient(s2.addr, t.network)
	f := New()
	shutdownAfterTest(t.T(), f)
	f.net = t.network
	f.From = "."
	f.AddClient(c1)
	f.AddClient(c2)

	req := new(dns.Msg)
	req.SetQuestion(testQuery, dns.TypeA)
	_, err := f.ServeDNS(context.TODO(), &test.ResponseWriter{}, req)
	t.Nil(err)
	// No settle time needed: each handler increments its counter before writing the
	// reply that releases ServeDNS, and the other server ignores a name it does not
	// own, so neither counter can still move once the call has returned.
	req = new(dns.Msg)
	req.SetQuestion("example2.", dns.TypeA)
	_, err = f.ServeDNS(context.TODO(), &test.ResponseWriter{}, req)
	t.Nil(err)
	mutex.Lock()
	defer mutex.Unlock()
	t.Equal(answerCount1, expected)
	t.Equal(answerCount2, expected)
}

// TestServerCount verifies that serverCount caps the number of upstreams polled per query.
// With serverCount=1 and a WeightedPolicy, only one of two servers should be contacted.
// Asserts exactly one answer is produced.
func (t *fanoutTestSuite) TestServerCount() {
	verifyNoLeaks(t.T())
	const expected = 1
	var mutex sync.Mutex
	answerCount := 0

	testFunc := func(w dns.ResponseWriter, r *dns.Msg) {
		if r.Question[0].Name == testQuery {
			msg := dns.Msg{
				Answer: []dns.RR{makeRecordA("example1 3600	IN	A 10.0.0.1")},
			}
			mutex.Lock()
			answerCount++
			mutex.Unlock()
			msg.SetReply(r)
			logErrIfNotNil(w.WriteMsg(&msg))
		}
	}
	s1 := newServer(t.T(), t.network, testFunc)
	s2 := newServer(t.T(), t.network, testFunc)

	c1 := NewClient(s1.addr, t.network)
	c2 := NewClient(s2.addr, t.network)
	f := New()
	shutdownAfterTest(t.T(), f)
	f.ServerSelectionPolicy = &WeightedPolicy{
		loadFactor: []int{50, 100},
	}
	f.net = t.network
	f.From = "."
	f.AddClient(c1)
	f.AddClient(c2)
	f.serverCount = 1

	req := new(dns.Msg)
	req.SetQuestion(testQuery, dns.TypeA)
	_, err := f.ServeDNS(context.TODO(), &test.ResponseWriter{}, req)
	t.Nil(err)

	mutex.Lock()
	t.Equal(expected, answerCount)
	mutex.Unlock()
}

// TestFanoutUDPSuite runs the full fanoutTestSuite over UDP.
func TestFanoutUDPSuite(t *testing.T) {
	suite.Run(t, &fanoutTestSuite{network: UDP})
}

// TestFanoutTCPSuite runs the full fanoutTestSuite over TCP.
func TestFanoutTCPSuite(t *testing.T) {
	suite.Run(t, &fanoutTestSuite{network: TCP})
}

func nxdomainMsg() *dns.Msg {
	return &dns.Msg{MsgHdr: dns.MsgHdr{Rcode: dns.RcodeNameError},
		Question: []dns.Question{{Name: "wwww.example1.", Qclass: dns.ClassINET, Qtype: dns.TypeTXT}},
		Ns:       []dns.RR{test.SOA("example1.	1800	IN	SOA	example1.net. example1.com 1461471181 14400 3600 604800 14400")},
	}
}
