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

	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
)

// doh3Client implements the Client interface for DNS-over-HTTPS using HTTP/3 (QUIC transport).
// It follows RFC 8484 at the application layer while using QUIC (RFC 9000) as the transport,
// providing reduced connection-establishment latency and improved multiplexing.
type doh3Client struct {
	endpoint  string // full URL, e.g. "https://dns.google/dns-query"
	h3Client  *http.Client
	transport *http3.Transport
}

// NewDoH3Client creates a new DNS-over-HTTPS client using HTTP/3 (QUIC) transport.
// The endpoint must be a full HTTPS URL (e.g. "https://dns.google/dns-query").
func NewDoH3Client(endpoint string) Client {
	return newDoH3ClientWithTLS(endpoint, nil)
}

// newDoH3ClientWithTLS creates a DoH3 client with an optional TLS configuration override.
func newDoH3ClientWithTLS(endpoint string, tlsConfig *tls.Config) Client {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
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
func (c *doh3Client) SetTLSConfig(cfg *tls.Config) {
	if cfg == nil {
		return
	}
	// QUIC requires TLS 1.3 minimum.
	if cfg.MinVersion < tls.VersionTLS13 {
		cfg.MinVersion = tls.VersionTLS13
	}

	_ = c.transport.Close()

	c.transport = &http3.Transport{
		TLSClientConfig: cfg,
	}
	c.h3Client.Transport = c.transport
}

// Net returns the network type identifier for this client.
func (c *doh3Client) Net() string {
	return DOH3
}

// Endpoint returns the DoH server URL.
func (c *doh3Client) Endpoint() string {
	return c.endpoint
}

// Request sends a DNS query to the DoH server over HTTP/3 (QUIC) using HTTP POST (RFC 8484).
// The DNS message is serialized in wire format, sent with content-type
// application/dns-message, and the response is deserialized from wire format.
func (c *doh3Client) Request(ctx context.Context, r *request.Request) (*dns.Msg, error) {
	return dohRoundTrip(ctx, c.h3Client, c.endpoint, r)
}
