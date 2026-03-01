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
	"net"
	"sync"

	"github.com/miekg/dns"
	ot "github.com/opentracing/opentracing-go"
)

const connPoolSize = 2

// Transport represent a solution to connect to remote DNS endpoint with specific network
type Transport interface {
	Dial(ctx context.Context, net string) (*dns.Conn, error)
	// Yield returns a healthy connection to the pool for reuse.
	// Only call this for connections that completed a successful request-response cycle.
	// For failed connections, call conn.Close() instead.
	Yield(conn *dns.Conn)
	SetTLSConfig(*tls.Config)
	// Close drains the connection pool and releases resources.
	Close()
}

// NewTransport creates new transport with address
func NewTransport(addr string) Transport {
	return &transportImpl{
		addr: addr,
		pool: make(chan *dns.Conn, connPoolSize),
	}
}

type transportImpl struct {
	tlsConfig *tls.Config
	addr      string
	mu        sync.Mutex // protects tlsConfig reads during concurrent Dial
	pool      chan *dns.Conn
}

// SetTLSConfig sets tls config for transport
func (t *transportImpl) SetTLSConfig(c *tls.Config) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tlsConfig = c
}

// Close drains pooled connections and releases resources.
func (t *transportImpl) Close() {
	for {
		select {
		case conn := <-t.pool:
			_ = conn.Close()
		default:
			return
		}
	}
}

// Yield returns a connection to the pool for reuse.
// If the pool is full, the connection is closed instead.
// UDP connections are always closed since they are cheap to create.
func (t *transportImpl) Yield(conn *dns.Conn) {
	if conn == nil {
		return
	}
	select {
	case t.pool <- conn:
		// returned to pool
	default:
		// pool full, discard
		_ = conn.Close()
	}
}

// Dial returns a pooled connection if available, or creates a new one.
func (t *transportImpl) Dial(ctx context.Context, network string) (*dns.Conn, error) {
	t.mu.Lock()
	tlsCfg := t.tlsConfig
	t.mu.Unlock()

	if tlsCfg != nil {
		network = TCPTLS
	}

	// Try to get a pooled connection for TCP/TLS
	if network == TCP || network == TCPTLS {
		select {
		case conn := <-t.pool:
			return conn, nil
		default:
			// pool empty, dial new
		}
	}

	if network == TCPTLS {
		return t.dial(ctx, &dns.Client{Net: network, Dialer: &net.Dialer{Timeout: dialTimeout}, TLSConfig: tlsCfg})
	}
	return t.dial(ctx, &dns.Client{Net: network, Dialer: &net.Dialer{Timeout: dialTimeout}})
}

func (t *transportImpl) dial(ctx context.Context, c *dns.Client) (*dns.Conn, error) {
	span := ot.SpanFromContext(ctx)
	if span != nil {
		childSpan := span.Tracer().StartSpan("connect", ot.ChildOf(span.Context()))
		ctx = ot.ContextWithSpan(ctx, childSpan)
		defer childSpan.Finish()
	}
	var d net.Dialer
	if c.Dialer == nil {
		d = net.Dialer{Timeout: dialTimeout}
	} else {
		d = *c.Dialer
	}
	network := c.Net
	if network == "" {
		network = "udp"
	}
	var conn = new(dns.Conn)
	var err error
	if network == TCPTLS {
		tlsDialer := &tls.Dialer{Config: c.TLSConfig, NetDialer: &d}
		conn.Conn, err = tlsDialer.DialContext(ctx, "tcp", t.addr)
	} else {
		conn.Conn, err = d.DialContext(ctx, network, t.addr)
	}
	if err != nil {
		return nil, err
	}
	return conn, nil
}
