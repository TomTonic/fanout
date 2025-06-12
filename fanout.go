// Copyright (c) 2020 Doc.ai and/or its affiliates.
//
// Copyright (c) 2024 MWS and/or its affiliates.
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
	"sync"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/debug"
	"github.com/coredns/coredns/plugin/dnstap"
	"github.com/coredns/coredns/plugin/metadata"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

var log = clog.NewWithPlugin("fanout")

// Fanout represents a plugin instance that can do async requests to list of DNS servers.
type Fanout struct {
	clients               []Client
	tlsConfig             *tls.Config
	ExcludeDomains        Domain
	tlsServerName         string
	Timeout               time.Duration
	Race                  bool
	net                   string
	From                  string
	Attempts              int
	WorkerCount           int
	serverCount           int
	loadFactor            []int
	policyType            string
	ServerSelectionPolicy policy
	TapPlugin             *dnstap.Dnstap
	Next                  plugin.Handler
}

// New returns reference to new Fanout plugin instance with default configs.
func New() *Fanout {
	return &Fanout{
		tlsConfig:             new(tls.Config),
		net:                   "udp",
		Attempts:              3,
		Timeout:               defaultTimeout,
		ExcludeDomains:        NewDomain(),
		ServerSelectionPolicy: &SequentialPolicy{}, // default policy
	}
}

// AddClient is used to add a new DNS server to the fanout
func (f *Fanout) AddClient(p Client) {
	f.clients = append(f.clients, p)
	f.WorkerCount++
	f.serverCount++
}

// Name implements plugin.Handler.
func (f *Fanout) Name() string {
	return "fanout"
}

// ServeDNS implements plugin.Handler.
func (f *Fanout) ServeDNS(ctx context.Context, w dns.ResponseWriter, m *dns.Msg) (int, error) {
	req := request.Request{W: w, Req: m}
	if !f.match(&req) {
		return plugin.NextOrFailure(f.Name(), f.Next, ctx, w, m)
	}
	timeoutContext, cancel := context.WithTimeout(ctx, f.Timeout)
	defer cancel()
	result := f.getFanoutResult(timeoutContext, f.runWorkers(timeoutContext, &req))
	if result == nil {
		return dns.RcodeServerFailure, timeoutContext.Err()
	}
	metadata.SetValueFunc(ctx, "fanout/upstream", func() string {
		return result.client.Endpoint()
	})
	if result.err != nil {
		return dns.RcodeServerFailure, result.err
	}
	if f.TapPlugin != nil {
		toDnstap(f.TapPlugin, result.client, &req, result.response, result.start)
	}
	if !req.Match(result.response) {
		debug.Hexdumpf(result.response, "Wrong reply for id: %d, %s %d", result.response.Id, req.QName(), req.QType())
		formerr := new(dns.Msg)
		formerr.SetRcode(req.Req, dns.RcodeFormatError)
		logErrIfNotNil(w.WriteMsg(formerr))
		return 0, nil
	}
	logErrIfNotNil(w.WriteMsg(result.response))
	return 0, nil
}

func (f *Fanout) runWorkers(ctx context.Context, req *request.Request) chan *response {
	sel := f.ServerSelectionPolicy.selector(f.clients)
	workerCh := make(chan Client, f.WorkerCount)
	responseCh := make(chan *response, f.serverCount)
	go func() {
		defer close(workerCh)
		for i := 0; i < f.serverCount; i++ {
			select {
			case <-ctx.Done():
				return
			case workerCh <- sel.Pick():
			}
		}
	}()

	go func() {
		var wg sync.WaitGroup
		wg.Add(f.WorkerCount)

		for i := 0; i < f.WorkerCount; i++ {
			go func() {
				defer wg.Done()
				for c := range workerCh {
					select {
					case <-ctx.Done():
						return
					case responseCh <- f.processClient(ctx, c, &request.Request{W: req.W, Req: req.Req}):
					}
				}
			}()
		}

		wg.Wait()
		close(responseCh)
	}()

	return responseCh
}

func (f *Fanout) getFanoutResult(ctx context.Context, responseCh <-chan *response) *response {
	var result *response
	for {
		select {
		case <-ctx.Done():
			return result
		case r, ok := <-responseCh:
			if !ok {
				return result
			}
			if isBetter(result, r) {
				result = r
			}
			if r.err != nil {
				break
			}
			if f.Race {
				return r
			}
			if r.response.Rcode != dns.RcodeSuccess {
				break
			}
			return r
		}
	}
}

func (f *Fanout) match(state *request.Request) bool {
	if !plugin.Name(f.From).Matches(state.Name()) || f.ExcludeDomains.Contains(state.Name()) {
		return false
	}
	return true
}

func (f *Fanout) processClient(ctx context.Context, c Client, r *request.Request) *response {
	start := time.Now()
	var err error
	for j := 0; j < f.Attempts || f.Attempts == 0; <-time.After(attemptDelay) {
		if ctx.Err() != nil {
			return &response{client: c, response: nil, start: start, err: ctx.Err()}
		}
		var msg *dns.Msg
		msg, err = c.Request(ctx, r)
		if err == nil {
			return &response{client: c, response: msg, start: start, err: err}
		}
		if f.Attempts != 0 {
			j++
		}
	}
	return &response{client: c, response: nil, start: start, err: errors.Wrapf(err, "attempt limit has been reached")}
}
