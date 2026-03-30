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
	"net/http"
	"sync"

	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// doh3Client implements the Client interface for DNS-over-HTTPS using HTTP/3 (QUIC transport).
// It follows RFC 8484 at the application layer while using QUIC (RFC 9000) as the transport,
// providing reduced connection-establishment latency and improved multiplexing.
type doh3Client struct {
	endpoint          string           // full URL, e.g. "https://dns.google/dns-query"
	bootstrap         *bootstrapConfig // bootstrap config for hostname resolution (nil = system default)
	mu                sync.Mutex       // protects h3Client, transport, and retiredTransports during SetTLSConfig
	h3Client          *http.Client
	transport         *http3.Transport
	retiredTransports map[*http3.Transport]struct{} // replaced transports waiting for grace-period cleanup
}

var doh3RetiredTransportCloseDelay = readTimeout + dialTimeout

// NewDoH3Client creates a new DNS-over-HTTPS client using HTTP/3 (QUIC) transport.
// The endpoint must be a full HTTPS URL (e.g. "https://dns.google/dns-query").
func NewDoH3Client(endpoint string) Client {
	return newDoH3ClientFull(endpoint, nil, nil)
}

// newDoH3ClientWithTLS creates a DoH3 client with an optional TLS configuration override.
func newDoH3ClientWithTLS(endpoint string, tlsConfig *tls.Config) Client {
	return newDoH3ClientFull(endpoint, tlsConfig, nil)
}

// newDoH3ClientFull creates a DoH3 client with optional TLS override and bootstrap resolver.
// When a bootstrap resolver is provided the QUIC transport uses a custom Dial
// function that resolves the server hostname through the bootstrap resolver
// instead of the system default, breaking circular DNS dependencies.
func newDoH3ClientFull(endpoint string, tlsConfig *tls.Config, bootstrap *bootstrapConfig) Client {
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
	if bootstrap != nil {
		h3Transport.Dial = bootstrapQUICDial(bootstrap)
	}

	return &doh3Client{
		endpoint:          endpoint,
		bootstrap:         bootstrap,
		transport:         h3Transport,
		retiredTransports: make(map[*http3.Transport]struct{}),
		h3Client: &http.Client{
			Transport: h3Transport,
			Timeout:   readTimeout + dialTimeout,
		},
	}
}

// bootstrapQUICDial returns a Dial function for http3.Transport that resolves
// the target hostname through the given bootstrap config before establishing
// the QUIC connection. The original hostname is preserved as TLS ServerName.
func bootstrapQUICDial(bootstrap *bootstrapConfig) func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	return func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		resolvedAddrs, hostname, err := bootstrap.resolveHostCandidates(ctx, addr)
		if err != nil {
			return nil, err
		}
		if hostname != "" && tlsCfg.ServerName == "" {
			tlsCfg = tlsCfg.Clone()
			tlsCfg.ServerName = hostname
		}
		var lastErr error
		for _, resolved := range resolvedAddrs {
			conn, err := quic.DialAddrEarly(ctx, resolved, tlsCfg, cfg)
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		if lastErr != nil {
			return nil, errors.Wrapf(lastErr, "bootstrap QUIC dial to %s failed", addr)
		}
		return nil, errors.Errorf("bootstrap QUIC dial to %s failed: no addresses resolved", addr)
	}
}

// SetTLSConfig updates the TLS configuration used by the HTTP/3 QUIC transport.
// HTTP/3 requires TLS 1.3 as a minimum; this is enforced automatically.
// A new http.Client and transport are created. The previous transport is kept
// alive briefly so in-flight requests can finish, then closed after a grace
// period to avoid accumulating retired QUIC transports indefinitely.
func (c *doh3Client) SetTLSConfig(cfg *tls.Config) {
	if cfg == nil {
		return
	}
	nextCfg := cfg.Clone()
	// QUIC requires TLS 1.3 minimum.
	if nextCfg.MinVersion < tls.VersionTLS13 {
		nextCfg.MinVersion = tls.VersionTLS13
	}

	newTransport := &http3.Transport{
		TLSClientConfig: nextCfg,
	}
	if c.bootstrap != nil {
		newTransport.Dial = bootstrapQUICDial(c.bootstrap)
	}
	newClient := &http.Client{
		Transport: newTransport,
		Timeout:   readTimeout + dialTimeout,
	}

	var old *http3.Transport
	c.mu.Lock()
	old = c.transport
	if old != nil {
		if c.retiredTransports == nil {
			c.retiredTransports = make(map[*http3.Transport]struct{})
		}
		c.retiredTransports[old] = struct{}{}
	}
	c.transport = newTransport
	c.h3Client = newClient
	c.mu.Unlock()

	if old != nil {
		c.scheduleRetiredTransportClose(old)
	}
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
	current := c.transport
	c.transport = nil
	retired := c.retiredTransports
	c.retiredTransports = nil
	c.mu.Unlock()

	if current != nil {
		_ = current.Close()
	}
	for t := range retired {
		_ = t.Close()
	}
}

func (c *doh3Client) closeRetiredTransport(t *http3.Transport) {
	c.mu.Lock()
	if c.retiredTransports == nil {
		c.mu.Unlock()
		return
	}
	if _, ok := c.retiredTransports[t]; !ok {
		c.mu.Unlock()
		return
	}
	delete(c.retiredTransports, t)
	c.mu.Unlock()
	_ = t.Close()
}

func (c *doh3Client) scheduleRetiredTransportClose(t *http3.Transport) {
	ctx, cancel := context.WithTimeout(context.Background(), doh3RetiredTransportCloseDelay)
	go func() {
		defer cancel()
		<-ctx.Done()
		if ctx.Err() == context.DeadlineExceeded {
			c.closeRetiredTransport(t)
		}
	}()
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
