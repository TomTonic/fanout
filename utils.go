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

import (
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/coredns/coredns/plugin/dnstap"
	"github.com/coredns/coredns/plugin/dnstap/msg"
	"github.com/coredns/coredns/request"

	tap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
)

func logErrIfNotNil(err error) {
	if err == nil {
		return
	}
	log.Error(err)
}

// endpointToAddr parses a client endpoint string into a net.Addr.
// It handles both host:port (plain DNS, DoT, DoQ) and URL-style (DoH, DoH3) endpoints.
// The network type determines the returned address type (TCP vs UDP).
func endpointToAddr(endpoint, network string) net.Addr {
	host, portStr := parseEndpoint(endpoint)
	port, _ := strconv.ParseUint(portStr, 10, 32)
	ip := net.ParseIP(host)

	switch network {
	case TCP, TCPTLS, DOH, DOH3:
		return &net.TCPAddr{IP: ip, Port: int(port)}
	default:
		return &net.UDPAddr{IP: ip, Port: int(port)}
	}
}

// parseEndpoint extracts host and port from an endpoint string.
// For URL-style endpoints (DoH, DoH3), it parses the URL and infers port 443 if omitted.
// For host:port endpoints (plain DNS, DoT, DoQ), it uses net.SplitHostPort directly.
func parseEndpoint(endpoint string) (host, port string) {
	// Try URL parsing for known schemes (DoH, DoH3 use https://).
	if u, err := url.Parse(endpoint); err == nil && u.Scheme == "https" {
		host = u.Hostname()
		port = u.Port()
		if port == "" {
			port = "443"
		}
		return host, port
	}
	// Fall back to host:port parsing (plain DNS, DoT, DoQ).
	host, port, _ = net.SplitHostPort(endpoint)
	return host, port
}

func toDnstap(tapPlugin *dnstap.Dnstap, client Client, state *request.Request, reply *dns.Msg, start time.Time) {
	// Query
	q := new(tap.Message)
	msg.SetQueryTime(q, start)

	ta := endpointToAddr(client.Endpoint(), client.Net())
	logErrIfNotNil(msg.SetQueryAddress(q, ta))

	if tapPlugin.IncludeRawMessage {
		buf, _ := state.Req.Pack()
		q.QueryMessage = buf
	}
	msg.SetType(q, tap.Message_FORWARDER_QUERY)
	tapPlugin.TapMessage(q)

	// Response
	if reply != nil {
		r := new(tap.Message)

		if tapPlugin.IncludeRawMessage {
			buf, _ := reply.Pack()
			r.ResponseMessage = buf
		}
		msg.SetQueryTime(r, start)
		logErrIfNotNil(msg.SetQueryAddress(r, ta))
		msg.SetResponseTime(r, time.Now())
		msg.SetType(r, tap.Message_FORWARDER_RESPONSE)
		tapPlugin.TapMessage(r)
	}
}
