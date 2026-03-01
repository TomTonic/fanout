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
	"net/http"
	"sync"

	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
)

// doh3Client implements the Client interface for DNS-over-HTTPS using HTTP/3 (QUIC transport).
// It follows RFC 8484 at the application layer while using QUIC (RFC 9000) as the transport,
// providing reduced connection-establishment latency and improved multiplexing.
type doh3Client struct {
	endpoint      string     // full URL, e.g. "https://dns.google/dns-query"
	mu            sync.Mutex // protects h3Client, transport, and oldTransports during SetTLSConfig
	h3Client      *http.Client
	transport     *http3.Transport
	oldTransports []*http3.Transport // transports replaced by SetTLSConfig, awaiting cleanup
}

// NewDoH3Client creates a new DNS-over-HTTPS client using HTTP/3 (QUIC) transport.
// The endpoint must be a full HTTPS URL (e.g. "https://dns.google/dns-query").
func NewDoH3Client(endpoint string) Client {
	return newDoH3ClientWithTLS(endpoint, nil)
}

// newDoH3ClientWithTLS creates a DoH3 client with an optional TLS configuration override.
// The TLS config is cloned defensively to prevent external mutation.
func newDoH3ClientWithTLS(endpoint string, tlsConfig *tls.Config) Client {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	// HTTP/3 over QUIC mandates TLS 1.3 as minimum.
	if tlsConfig.MinVersion < tls.VersionTLS13 {
		tlsConfig.MinVersion = tls.VersionTLS13
	}

	h3Transport := &http3.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &doh3Client{
		endpoint:  endpoint,
		transport: h3Transport,
		h3Client: &http.Client{
			Transport: h3Transport,
			Timeout:   readTimeout + dialTimeout,
		},
	}
}

// SetTLSConfig updates the TLS configuration used by the HTTP/3 QUIC transport.
// HTTP/3 requires TLS 1.3 as a minimum; this is enforced automatically.
// A new http.Client and transport are created. The old transport is not closed
// eagerly to avoid racing with in-flight requests; it will be garbage-collected
// once all references (including in-flight snapshots) are released.
func (c *doh3Client) SetTLSConfig(cfg *tls.Config) {
	if cfg == nil {
		return
	}
	// QUIC requires TLS 1.3 minimum.
	if cfg.MinVersion < tls.VersionTLS13 {
		cfg.MinVersion = tls.VersionTLS13
	}

	newTransport := &http3.Transport{
		TLSClientConfig: cfg.Clone(),
	}
	newClient := &http.Client{
		Transport: newTransport,
		Timeout:   readTimeout + dialTimeout,
	}

	c.mu.Lock()
	c.oldTransports = append(c.oldTransports, c.transport)
	c.transport = newTransport
	c.h3Client = newClient
	c.mu.Unlock()
}

// Net returns the network type identifier for this client.
func (c *doh3Client) Net() string {
	return DOH3
}

// Endpoint returns the DoH server URL.
func (c *doh3Client) Endpoint() string {
	return c.endpoint
}

// Close releases resources held by this DoH3 client.
// It closes the current and all previously abandoned QUIC transports,
// stopping background goroutines started by quic-go.
func (c *doh3Client) Close() error {
	c.closeTransports()
	return nil
}

// closeTransports closes the current and all previously abandoned QUIC transports.
// This stops background goroutines started by quic-go and should be called during shutdown.
func (c *doh3Client) closeTransports() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.transport != nil {
		_ = c.transport.Close()
		c.transport = nil
	}
	for _, t := range c.oldTransports {
		_ = t.Close()
	}
	c.oldTransports = nil
}

// Request sends a DNS query to the DoH server over HTTP/3 (QUIC) using HTTP POST (RFC 8484).
// The DNS message is serialized in wire format, sent with content-type
// application/dns-message, and the response is deserialized from wire format.
func (c *doh3Client) Request(ctx context.Context, r *request.Request) (*dns.Msg, error) {
	c.mu.Lock()
	hc := c.h3Client
	c.mu.Unlock()
	return dohRoundTrip(ctx, hc, c.endpoint, r)
}
