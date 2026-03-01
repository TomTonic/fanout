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
	"crypto/tls"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

// TestSetup is a comprehensive table-driven test for Corefile parsing via parseFanout.
// Covers 9 valid configurations (minimal, weighted-random with load-factor, except + worker-count,
// two hosts with TCP, worker-count + timeout, attempt-count, default load-factor, sequential policy)
// and 12 invalid configurations (bad host, bad from, worker-count too low, non-integer worker-count,
// invalid except domain, unknown network, negative server-count, load-factor too high/zero/count
// mismatch, missing load-factor args). For valid cases, asserts From, Timeout, Attempts, WorkerCount,
// net, serverCount, policyType, loadFactor, ExcludeDomains, and client endpoints.
func TestSetup(t *testing.T) {
	tests := []struct {
		name                                string
		input                               string
		expectedFrom                        string
		expectedTo                          []string
		expectedIgnored                     []string
		expectedWorkers                     int
		expectedAttempts                    int
		expectedTimeout                     time.Duration
		expectedNetwork                     string
		expectedRace                        bool
		expectedRaceContinueOnErrorResponse bool
		expectedServerCount                 int
		expectedLoadFactor                  []int
		expectedPolicy                      string
		expectedErr                         string
	}{
		// positive
		{name: "weighted-random-with-load-factor", input: "fanout . 127.0.0.1 {\npolicy weighted-random \nweighted-random-server-count 5 weighted-random-load-factor 100\n}", expectedFrom: ".", expectedAttempts: 3, expectedWorkers: 1, expectedTimeout: defaultTimeout, expectedNetwork: "udp", expectedRace: false, expectedRaceContinueOnErrorResponse: false, expectedServerCount: 1, expectedLoadFactor: []int{100}, expectedPolicy: policyWeightedRandom},
		{name: "minimal-config", input: "fanout . 127.0.0.1", expectedFrom: ".", expectedAttempts: 3, expectedWorkers: 1, expectedTimeout: defaultTimeout, expectedNetwork: "udp", expectedRace: false, expectedRaceContinueOnErrorResponse: false, expectedServerCount: 1, expectedLoadFactor: nil, expectedPolicy: ""},
		{name: "weighted-random-short-aliases", input: "fanout . 127.0.0.1 {\npolicy weighted-random \nweighted-random-server-count 5\nweighted-random-load-factor 100\n}", expectedFrom: ".", expectedAttempts: 3, expectedWorkers: 1, expectedTimeout: defaultTimeout, expectedNetwork: "udp", expectedRace: false, expectedRaceContinueOnErrorResponse: false, expectedServerCount: 1, expectedLoadFactor: []int{100}, expectedPolicy: policyWeightedRandom},
		{name: "except-and-worker-count", input: "fanout . 127.0.0.1 {\nexcept a b\nworker-count 3\n}", expectedFrom: ".", expectedTimeout: defaultTimeout, expectedAttempts: 3, expectedWorkers: 1, expectedIgnored: []string{"a.", "b."}, expectedNetwork: "udp", expectedRace: false, expectedRaceContinueOnErrorResponse: false, expectedServerCount: 1, expectedLoadFactor: nil, expectedPolicy: ""},
		{name: "two-hosts-tcp", input: "fanout . 127.0.0.1 127.0.0.2 {\nnetwork tcp\n}", expectedFrom: ".", expectedTimeout: defaultTimeout, expectedAttempts: 3, expectedWorkers: 2, expectedNetwork: "tcp", expectedRace: false, expectedRaceContinueOnErrorResponse: false, expectedTo: []string{"127.0.0.1:53", "127.0.0.2:53"}, expectedServerCount: 2, expectedLoadFactor: nil, expectedPolicy: ""},
		{name: "worker-count-and-timeout", input: "fanout . 127.0.0.1 127.0.0.2 127.0.0.3 127.0.0.4 {\nworker-count 3\ntimeout 1m\n}", expectedTimeout: time.Minute, expectedAttempts: 3, expectedFrom: ".", expectedWorkers: 3, expectedNetwork: "udp", expectedRace: false, expectedRaceContinueOnErrorResponse: false, expectedServerCount: 4, expectedLoadFactor: nil, expectedPolicy: ""},
		{name: "attempt-count", input: "fanout . 127.0.0.1 127.0.0.2 127.0.0.3 127.0.0.4 {\nattempt-count 2\n}", expectedTimeout: defaultTimeout, expectedFrom: ".", expectedAttempts: 2, expectedWorkers: 4, expectedNetwork: "udp", expectedRace: false, expectedRaceContinueOnErrorResponse: false, expectedServerCount: 4, expectedLoadFactor: nil, expectedPolicy: ""},
		{name: "weighted-random-default-load-factor", input: "fanout . 127.0.0.1 127.0.0.2 127.0.0.3 {\npolicy weighted-random \n}", expectedFrom: ".", expectedAttempts: 3, expectedWorkers: 3, expectedTimeout: defaultTimeout, expectedNetwork: "udp", expectedRace: false, expectedRaceContinueOnErrorResponse: false, expectedServerCount: 3, expectedLoadFactor: []int{100, 100, 100}, expectedPolicy: policyWeightedRandom},
		{name: "sequential-policy", input: "fanout . 127.0.0.1 127.0.0.2 127.0.0.3 {\npolicy sequential\nworker-count 3\n}", expectedFrom: ".", expectedAttempts: 3, expectedWorkers: 3, expectedTimeout: defaultTimeout, expectedNetwork: "udp", expectedRace: false, expectedRaceContinueOnErrorResponse: false, expectedServerCount: 3, expectedLoadFactor: nil, expectedPolicy: policySequential},
		{name: "race-with-continue-on-error-response", input: "fanout . 127.0.0.1 {\nrace\nrace-continue-on-error-response\n}", expectedFrom: ".", expectedAttempts: 3, expectedWorkers: 1, expectedTimeout: defaultTimeout, expectedNetwork: "udp", expectedRace: true, expectedRaceContinueOnErrorResponse: true, expectedServerCount: 1, expectedLoadFactor: nil, expectedPolicy: ""},

		// negative
		{name: "err-invalid-host", input: "fanout . aaa", expectedErr: "not an IP address or file"},
		{name: "err-invalid-from", input: "fanout .: aaa", expectedErr: "unable to normalize '.:'"},
		{name: "err-worker-count-too-low", input: "fanout . 127.0.0.1 {\nexcept a b\nworker-count 1\n}", expectedErr: "use Forward plugin"},
		{name: "err-worker-count-not-int", input: "fanout . 127.0.0.1 {\nexcept a b\nworker-count ten\n}", expectedErr: "'ten'"},
		{name: "err-invalid-except-domain", input: "fanout . 127.0.0.1 {\nexcept a:\nworker-count ten\n}", expectedErr: "unable to normalize 'a:'"},
		{name: "err-unknown-network", input: "fanout . 127.0.0.1 127.0.0.2 {\nnetwork XXX\n}", expectedErr: "unknown network protocol"},
		{name: "err-negative-server-count", input: "fanout . 127.0.0.1 {\npolicy weighted-random \nweighted-random-server-count -100\n}", expectedErr: "Wrong argument count or unexpected line ending"},
		{name: "err-load-factor-too-high", input: "fanout . 127.0.0.1 {\npolicy weighted-random \nweighted-random-load-factor 150\n}", expectedErr: "load-factor 150 should be less than 100"},
		{name: "err-load-factor-zero", input: "fanout . 127.0.0.1 {\npolicy weighted-random \nweighted-random-load-factor 0\n}", expectedErr: "load-factor should be more or equal 1"},
		{name: "err-load-factor-count-mismatch-more", input: "fanout . 127.0.0.1 {\npolicy weighted-random \nweighted-random-load-factor 50 100\n}", expectedErr: "load-factor params count must be the same as the number of hosts"},
		{name: "err-load-factor-count-mismatch-less", input: "fanout . 127.0.0.1 127.0.0.2 {\npolicy weighted-random \nweighted-random-load-factor 50\n}", expectedErr: "load-factor params count must be the same as the number of hosts"},
		{name: "err-load-factor-missing-args", input: "fanout . 127.0.0.1 127.0.0.2 {\npolicy weighted-random \nweighted-random-load-factor \n}", expectedErr: "Wrong argument count or unexpected line ending"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.input)
			f, err := parseFanout(c)
			if tc.expectedErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q but got none", tc.expectedErr)
				}
				if !strings.Contains(err.Error(), tc.expectedErr) {
					t.Fatalf("expected error to contain: %v, found error: %v", tc.expectedErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if f.Timeout != tc.expectedTimeout {
				t.Fatalf("expected timeout: %v, got: %v", tc.expectedTimeout, f.Timeout)
			}
			if f.Attempts != tc.expectedAttempts {
				t.Fatalf("expected attempts: %d, got: %d", tc.expectedAttempts, f.Attempts)
			}
			if f.From != tc.expectedFrom && tc.expectedFrom != "" {
				t.Fatalf("expected from: %s, got: %s", tc.expectedFrom, f.From)
			}
			if tc.expectedIgnored != nil {
				for _, expected := range tc.expectedIgnored {
					if !f.ExcludeDomains.Contains(expected) {
						t.Fatalf("missed exclude domain name: %v", tc.expectedIgnored)
					}
				}
			}
			if tc.expectedTo != nil {
				var to []string
				for j := 0; j < len(f.clients); j++ {
					to = append(to, f.clients[j].Endpoint())
				}
				if !reflect.DeepEqual(to, tc.expectedTo) {
					t.Fatalf("expected: %q, actual: %q", tc.expectedTo, to)
				}
			}
			if f.WorkerCount != tc.expectedWorkers {
				t.Fatalf("expected workers: %d, got: %d", tc.expectedWorkers, f.WorkerCount)
			}
			if f.net != tc.expectedNetwork {
				t.Fatalf("expected network: %v, got: %v", tc.expectedNetwork, f.net)
			}
			if f.Race != tc.expectedRace {
				t.Fatalf("expected race: %v, got: %v", tc.expectedRace, f.Race)
			}
			if f.RaceContinueOnErrorResponse != tc.expectedRaceContinueOnErrorResponse {
				t.Fatalf("expected race-continue-on-error-response: %v, got: %v", tc.expectedRaceContinueOnErrorResponse, f.RaceContinueOnErrorResponse)
			}
			if f.serverCount != tc.expectedServerCount {
				t.Fatalf("expected serverCount: %d, got: %d", tc.expectedServerCount, f.serverCount)
			}
			if f.policyType != tc.expectedPolicy {
				t.Fatalf("expected policy: %s, got: %s", tc.expectedPolicy, f.policyType)
			}

			selectionPolicy, ok := f.ServerSelectionPolicy.(*WeightedPolicy)
			if len(tc.expectedLoadFactor) > 0 {
				if !ok {
					t.Fatalf("expected weighted policy to be set, got: %T", f.ServerSelectionPolicy)
				}
				if !reflect.DeepEqual(selectionPolicy.loadFactor, tc.expectedLoadFactor) {
					t.Fatalf("expected loadFactor: %d, got: %d", tc.expectedLoadFactor, selectionPolicy.loadFactor)
				}
			} else if ok {
				t.Fatalf("expected sequential policy to be set, got: %T", f.ServerSelectionPolicy)
			}
		})
	}
}

// TestSetupResolvconf verifies that during Corefile parsing, if the upstream argument is a
// resolv.conf-format file, parseFanout extracts nameserver addresses from it.
// Writes a resolv.conf with two nameservers and verifies both appear as client endpoints with port 53.
func TestSetupResolvconf(t *testing.T) {
	const resolv = "resolv.conf"
	if err := os.WriteFile(resolv,
		[]byte(`nameserver 10.10.255.252
nameserver 10.10.255.253`), 0o600); err != nil {
		t.Fatalf("Failed to write resolv.conf file: %s", err)
	}
	defer func() {
		logErrIfNotNil(os.Remove(resolv))
	}()

	tests := []struct {
		input         string
		shouldErr     bool
		expectedErr   string
		expectedNames []string
	}{
		{`fanout . ` + resolv, false, "", []string{"10.10.255.252:53", "10.10.255.253:53"}},
	}

	for i, test := range tests {
		c := caddy.NewTestController("dns", test.input)
		f, err := parseFanout(c)

		if test.shouldErr && err == nil {
			t.Errorf("Test %d: expected error but found %s for input %s", i, err, test.input)
			continue
		}

		if err != nil {
			if !test.shouldErr {
				t.Errorf("Test %d: expected no error but found one for input %s, got: %v", i, test.input, err)
			}

			if !strings.Contains(err.Error(), test.expectedErr) {
				t.Errorf("Test %d: expected error to contain: %v, found error: %v, input: %s", i, test.expectedErr, err, test.input)
			}
		}

		if !test.shouldErr {
			for j, n := range test.expectedNames {
				addr := f.clients[j].Endpoint()
				if n != addr {
					t.Errorf("Test %d, expected %q, got %q", j, n, addr)
				}
			}
		}
	}
}

// closableClient is a test double that implements both Client and io.Closer,
// tracking whether Close was called.
type closableClient struct {
	closed atomic.Bool
	addr   string
}

func (c *closableClient) Request(_ context.Context, _ *request.Request) (*dns.Msg, error) {
	return nil, nil
}
func (c *closableClient) Endpoint() string           { return c.addr }
func (c *closableClient) Net() string                { return UDP }
func (c *closableClient) SetTLSConfig(_ *tls.Config) {}
func (c *closableClient) Close() error {
	c.closed.Store(true)
	return nil
}

// TestOnShutdown verifies that OnShutdown closes all clients that implement io.Closer.
// This ensures resources such as connection pools, QUIC transports, and HTTP transports
// are released during plugin shutdown, preventing goroutine leaks.
func TestOnShutdown(t *testing.T) {
	f := New()
	c1 := &closableClient{addr: "127.0.0.1:53"}
	c2 := &closableClient{addr: "127.0.0.2:53"}
	f.AddClient(c1)
	f.AddClient(c2)

	err := f.OnShutdown()
	if err != nil {
		t.Fatalf("OnShutdown returned unexpected error: %v", err)
	}

	if !c1.closed.Load() {
		t.Error("expected client 1 to be closed after OnShutdown")
	}
	if !c2.closed.Load() {
		t.Error("expected client 2 to be closed after OnShutdown")
	}
}
