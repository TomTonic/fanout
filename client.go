// Copyright (c) 2020 Doc.ai and/or its affiliates.
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
	"fmt"
	"math"
	"time"

	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	ot "github.com/opentracing/opentracing-go"
	otext "github.com/opentracing/opentracing-go/ext"
)

// Client represents the proxy for remote DNS server
type Client interface {
	Request(context.Context, *request.Request) (*dns.Msg, error)
	Endpoint() string
	Net() string
	SetTLSConfig(*tls.Config)
}

type client struct {
	transport Transport
	addr      string
	net       string
}

// NewClient creates new client with specific addr and network
func NewClient(addr, net string) Client {
	a := &client{
		addr:      addr,
		net:       net,
		transport: NewTransport(addr),
	}
	return a
}

// SetTLSConfig sets tls config for client
func (c *client) SetTLSConfig(cfg *tls.Config) {
	if cfg != nil {
		c.net = TCPTLS
	}
	c.transport.SetTLSConfig(cfg)
}

// Network type of client
func (c *client) Net() string {
	return c.net
}

// Endpoint returns address of DNS server
func (c *client) Endpoint() string {
	return c.addr
}

// Request sends request to DNS server
func (c *client) Request(ctx context.Context, r *request.Request) (*dns.Msg, error) {
	ctx, finish := withRequestSpan(ctx, c.addr)
	defer finish()
	start := time.Now()
	conn, err := c.transport.Dial(ctx, c.net)
	if err != nil {
		return nil, err
	}

	// Set buffer size correctly for this conn.
	udpSize := r.Size()
	if udpSize < 512 {
		udpSize = 512
	}
	if udpSize > math.MaxUint16 {
		udpSize = math.MaxUint16
	}
	conn.UDPSize = uint16(udpSize)

	defer func() {
		_ = conn.Close()
	}()
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	if err = conn.SetWriteDeadline(time.Now().Add(maxTimeout)); err != nil {
		return nil, err
	}
	if err = conn.WriteMsg(r.Req); err != nil {
		return nil, err
	}
	if err = conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return nil, err
	}
	var ret *dns.Msg

	for {
		ret, err = conn.ReadMsg()
		if err != nil {
			return nil, err
		}
		if r.Req.Id == ret.Id {
			break
		}
	}
	rc, ok := dns.RcodeToString[ret.Rcode]
	if !ok {
		rc = fmt.Sprint(ret.Rcode)
	}
	RequestCount.WithLabelValues(c.addr).Add(1)
	RcodeCount.WithLabelValues(rc, c.addr).Add(1)
	RequestDuration.WithLabelValues(c.addr).Observe(time.Since(start).Seconds())
	return ret, nil
}

func withRequestSpan(ctx context.Context, addr string) (context.Context, func()) {
	span := ot.SpanFromContext(ctx)
	if span == nil {
		return ctx, func() {}
	}
	childSpan := span.Tracer().StartSpan("request", ot.ChildOf(span.Context()))
	otext.PeerAddress.Set(childSpan, addr)
	return ot.ContextWithSpan(ctx, childSpan), childSpan.Finish
}
