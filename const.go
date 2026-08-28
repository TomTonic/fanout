// Copyright (c) 2020 Doc.ai and/or its affiliates.
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

import "time"

const (
	pluginName           = "fanout"
	maxIPCount           = 100
	maxLoadFactor        = 100
	minLoadFactor        = 1
	policyWeightedRandom = "weighted-random"
	policySequential     = "sequential"
	maxWorkerCount       = 32
	minWorkerCount       = 2
	// dialTimeout bounds the bootstrap resolver's own dials when resolving upstream
	// hostnames (see bootstrap.go); it plays no part in a regular upstream request.
	dialTimeout    = 2 * time.Second
	defaultTimeout = 30 * time.Second
	maxTimeout     = 5 * time.Minute
	minTimeout     = 100 * time.Millisecond
	// readTimeout is deadlineFromCtx's fallback budget, used only when a Client is
	// invoked without a context deadline (direct API use outside of Fanout). Every
	// upstream request made through Fanout carries a deadline set by processClient
	// (see attemptBudget), which takes precedence via deadlineFromCtx.
	readTimeout  = 2 * time.Second
	attemptDelay = 100 * time.Millisecond
	// maxAttemptBudget is the hard ceiling processClient places on the context deadline
	// it carves out for a single upstream attempt (see attemptBudget). It is not
	// configurable: it is what DoH and DoH3 already ran under before every transport
	// was made to share one clock, chosen because those two have the most expensive
	// handshake of the bunch.
	maxAttemptBudget = 4 * time.Second
	// maxReadLoopIterations is the maximum number of DNS response messages the client will read
	// while waiting for one whose ID matches the request. This guards against a malicious or
	// misbehaving upstream that sends many responses with wrong IDs.
	maxReadLoopIterations = 100
	// TCPTLS net type for a DNS-over-TLS Client (DoT, RFC 7858).
	TCPTLS = "tcp-tls"
	// TCP net type for a Client (plain DNS over TCP).
	TCP = "tcp"
	// UDP net type for a Client (plain DNS over UDP).
	UDP = "udp"
	// DOH net type for a DNS-over-HTTPS Client (DoH, RFC 8484 over HTTP/2).
	DOH = "dns-over-https"
	// DOH3 net type for a DNS-over-HTTPS Client using HTTP/3 over QUIC (DoH3, RFC 8484 + RFC 9114).
	DOH3 = "dns-over-https3"
	// DOQ net type for a DNS-over-QUIC Client (DoQ, RFC 9250).
	DOQ = "dns-over-quic"
)
