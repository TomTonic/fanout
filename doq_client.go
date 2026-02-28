// Copyright (c) 2026 Doc.ai and/or its affiliates.
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
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/quic-go/quic-go"
)

// doqALPN is the ALPN token for DNS over QUIC as specified in RFC 9250 §7.2.
const doqALPN = "doq"

// doqMaxMessageSize is the maximum DNS message payload allowed over DoQ (64 KiB).
// This protects against excessive memory consumption from malicious peers.
const doqMaxMessageSize = 64 * 1024

// doqNoError is the DoQ error code for a clean close (RFC 9250 §8.4).
const doqNoError quic.ApplicationErrorCode = 0x0

// doqInternalError is the DoQ error code for internal errors (RFC 9250 §8.4).
const doqInternalError quic.ApplicationErrorCode = 0x1

// doqClient implements the Client interface for DNS-over-QUIC (RFC 9250).
// It uses one QUIC stream per query on a persistent connection, providing
// low-latency DNS resolution with TLS 1.3 encryption and multiplexing.
type doqClient struct {
	addr      string     // host:port of the DoQ server
	mu        sync.Mutex // protects conn and tlsConfig
	conn      *quic.Conn
	tlsConfig *tls.Config
}

// NewDoQClient creates a new DNS-over-QUIC client for the given address.
// The address should be in host:port format (e.g. "dns.example.com:853").
func NewDoQClient(addr string) Client {
	return newDoQClientWithTLS(addr, nil)
}

// newDoQClientWithTLS creates a DoQ client with an optional TLS configuration override.
func newDoQClientWithTLS(addr string, tlsConfig *tls.Config) Client {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	}
	// QUIC mandates TLS 1.3 minimum.
	if tlsConfig.MinVersion < tls.VersionTLS13 {
		tlsConfig.MinVersion = tls.VersionTLS13
	}
	// Set the ALPN token for DNS over QUIC (RFC 9250 §7.2).
	tlsConfig.NextProtos = []string{doqALPN}

	return &doqClient{
		addr:      addr,
		tlsConfig: tlsConfig,
	}
}

// SetTLSConfig updates the TLS configuration used for QUIC connections.
// Any existing connection is closed to force reconnection with the new config.
// QUIC requires TLS 1.3 minimum; this is enforced automatically.
func (c *doqClient) SetTLSConfig(cfg *tls.Config) {
	if cfg == nil {
		return
	}
	if cfg.MinVersion < tls.VersionTLS13 {
		cfg.MinVersion = tls.VersionTLS13
	}
	cfg.NextProtos = []string{doqALPN}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Close existing connection to force reconnect with new TLS config.
	if c.conn != nil {
		_ = c.conn.CloseWithError(doqNoError, "TLS config changed")
		c.conn = nil
	}
	c.tlsConfig = cfg
}

// Net returns the network type identifier for this client.
func (c *doqClient) Net() string {
	return DOQ
}

// Endpoint returns the server address in host:port format.
func (c *doqClient) Endpoint() string {
	return c.addr
}

// Request sends a DNS query to the DoQ server over a dedicated QUIC stream (RFC 9250).
// Each query opens a new bidirectional QUIC stream, writes the DNS message prefixed
// with a 2-byte length, reads the response, and closes its half of the stream.
func (c *doqClient) Request(ctx context.Context, r *request.Request) (*dns.Msg, error) {
	ctx, finish := withRequestSpan(ctx, c.addr)
	defer finish()
	start := time.Now()

	conn, err := c.getOrDialConn(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "DoQ: failed to establish QUIC connection")
	}

	// RFC 9250 §4.2: Each DNS query-response pair uses a single QUIC stream.
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		// Connection may have been closed; reset and retry once.
		c.resetConn()
		conn, err = c.getOrDialConn(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "DoQ: failed to re-establish QUIC connection")
		}
		stream, err = conn.OpenStreamSync(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "DoQ: failed to open QUIC stream")
		}
	}

	ret, err := c.exchangeOnStream(ctx, stream, r.Req)
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

// exchangeOnStream writes a DNS query to a QUIC stream and reads the response.
// Per RFC 9250 §4.2, the message is prefixed with a 2-byte length field, and
// the client closes its sending half of the stream after writing.
func (c *doqClient) exchangeOnStream(ctx context.Context, stream *quic.Stream, req *dns.Msg) (*dns.Msg, error) {
	defer stream.Close() //nolint:errcheck // best-effort close

	if err := c.writeQuery(ctx, stream, req); err != nil {
		return nil, err
	}

	return c.readResponse(ctx, stream, req.Id)
}

// writeQuery packs and writes a DNS query to the QUIC stream with a 2-byte length prefix.
func (c *doqClient) writeQuery(ctx context.Context, stream *quic.Stream, req *dns.Msg) error {
	// Set write deadline from context or fallback.
	writeDeadline := deadlineFromCtx(ctx, dialTimeout)
	if err := stream.SetWriteDeadline(writeDeadline); err != nil {
		return errors.Wrap(err, "DoQ: failed to set write deadline")
	}

	// RFC 9250 §4.2: DNS messages are prefixed with a 2-byte length field.
	packed, err := req.Pack()
	if err != nil {
		return errors.Wrap(err, "DoQ: failed to pack DNS request")
	}

	if len(packed) > math.MaxUint16 {
		return errors.Errorf("DoQ: packed DNS message too large (%d bytes)", len(packed))
	}

	// Write length prefix + message in one write for efficiency.
	buf := make([]byte, 2+len(packed))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(packed))) //nolint:gosec // bound checked above
	copy(buf[2:], packed)

	if _, err = stream.Write(buf); err != nil {
		return errors.Wrap(err, "DoQ: failed to write DNS query to stream")
	}

	// RFC 9250 §4.2: The client MUST send a FIN after sending a query.
	if err = stream.Close(); err != nil {
		return errors.Wrap(err, "DoQ: failed to close write half of stream")
	}

	return nil
}

// readResponse reads a DNS response from the QUIC stream.
func (c *doqClient) readResponse(ctx context.Context, stream *quic.Stream, origID uint16) (*dns.Msg, error) {
	// Set read deadline.
	readDeadline := deadlineFromCtx(ctx, readTimeout)
	if err := stream.SetReadDeadline(readDeadline); err != nil {
		return nil, errors.Wrap(err, "DoQ: failed to set read deadline")
	}

	// Read the 2-byte length prefix.
	var lenBuf [2]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return nil, errors.Wrap(err, "DoQ: failed to read response length prefix")
	}
	respLen := binary.BigEndian.Uint16(lenBuf[:])
	if respLen == 0 || int(respLen) > doqMaxMessageSize {
		return nil, errors.Errorf("DoQ: invalid response length %d", respLen)
	}

	// Read the DNS response message.
	respBuf := make([]byte, respLen)
	if _, err := io.ReadFull(stream, respBuf); err != nil {
		return nil, errors.Wrap(err, "DoQ: failed to read DNS response")
	}

	ret := new(dns.Msg)
	if err := ret.Unpack(respBuf); err != nil {
		return nil, errors.Wrap(err, "DoQ: failed to unpack DNS response")
	}

	// RFC 9250 §4.2: The ID MUST be set to 0 in DoQ (set to 0 by server).
	// We restore the original ID for upstream compatibility.
	ret.Id = origID

	return ret, nil
}

// deadlineFromCtx returns the earlier of ctx.Deadline() and now+fallback.
func deadlineFromCtx(ctx context.Context, fallback time.Duration) time.Time {
	d := time.Now().Add(fallback)
	if ctxD, ok := ctx.Deadline(); ok && ctxD.Before(d) {
		return ctxD
	}
	return d
}

// getOrDialConn returns the existing QUIC connection or dials a new one.
// The connection is cached for reuse across multiple streams.
func (c *doqClient) getOrDialConn(ctx context.Context) (*quic.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		// Check if the connection is still usable by inspecting its context.
		select {
		case <-c.conn.Context().Done():
			// Connection was closed, need to reconnect.
			c.conn = nil
		default:
			return c.conn, nil
		}
	}

	tlsCfg := c.tlsConfig.Clone()

	conn, err := quic.DialAddr(ctx, c.addr, tlsCfg, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
	})
	if err != nil {
		return nil, err
	}

	c.conn = conn
	return conn, nil
}

// resetConn closes the current connection and clears it so the next call
// to getOrDialConn will establish a fresh connection.
func (c *doqClient) resetConn() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		_ = c.conn.CloseWithError(doqInternalError, "connection reset")
		c.conn = nil
	}
}

// closeConn closes the QUIC connection gracefully. Used by tests for cleanup.
func (c *doqClient) closeConn() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		_ = c.conn.CloseWithError(doqNoError, "client shutdown")
		c.conn = nil
	}
}
