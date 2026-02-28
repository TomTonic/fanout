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
	"sync/atomic"
	"time"

	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	ot "github.com/opentracing/opentracing-go"
	otext "github.com/opentracing/opentracing-go/ext"
	"github.com/pkg/errors"
)

var errMaxReadLoopExceeded = errors.New("maximum read loop iterations exceeded without matching response ID")

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

// Close releases resources held by this client (drains the connection pool).
func (c *client) Close() error {
	c.transport.Close()
	return nil
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

	conn.UDPSize = clampUDPSize(r.Size())

	// cancelled tracks whether the context-cancellation goroutine closed the connection.
	// If so, we must not return the connection to the pool.
	var cancelled atomic.Bool
	done := make(chan struct{})
	defer func() {
		close(done)
		// Only yield the connection back to the pool if the request succeeded
		// and the context goroutine did not close it.
		if err != nil || cancelled.Load() {
			_ = conn.Close()
		} else {
			c.transport.Yield(conn)
		}
	}()
	go func() {
		select {
		case <-ctx.Done():
			cancelled.Store(true)
			_ = conn.Close()
		case <-done:
		}
	}()

	ret, err := c.exchangeMsg(conn, r)
	if err != nil {
		return nil, err
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

// clampUDPSize restricts the UDP buffer size to the valid DNS range [512, 65535].
func clampUDPSize(size int) uint16 {
	if size < 512 {
		size = 512
	}
	if size > math.MaxUint16 {
		size = math.MaxUint16
	}
	return uint16(size)
}

// exchangeMsg writes the DNS query and reads responses until a matching ID is found.
func (c *client) exchangeMsg(conn *dns.Conn, r *request.Request) (*dns.Msg, error) {
	if err := conn.SetWriteDeadline(time.Now().Add(dialTimeout)); err != nil {
		return nil, err
	}
	if err := conn.WriteMsg(r.Req); err != nil {
		return nil, err
	}
	if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return nil, err
	}
	for range maxReadLoopIterations {
		ret, err := conn.ReadMsg()
		if err != nil {
			return nil, err
		}
		if r.Req.Id == ret.Id {
			return ret, nil
		}
	}
	return nil, errMaxReadLoopExceeded
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
