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
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

// dohMaxResponseSize is the maximum DNS response body we will read over DoH (64 KiB).
// This prevents a malicious server from forcing unbounded memory allocation.
const dohMaxResponseSize = 64 * 1024

// dohClient implements the Client interface for DNS-over-HTTPS (RFC 8484).
// It uses HTTP POST with the application/dns-message content type.
type dohClient struct {
	endpoint   string // full URL, e.g. "https://dns.google/dns-query"
	httpClient *http.Client
}

// NewDoHClient creates a new DNS-over-HTTPS client for the given endpoint URL.
// The endpoint must be a full URL (e.g. "https://dns.google/dns-query").
// The client uses HTTP/2 with a connection-pooling transport for performance.
func NewDoHClient(endpoint string) Client {
	return newDoHClientWithTLS(endpoint, nil)
}

// newDoHClientWithTLS creates a DoH client with an optional TLS configuration override.
func newDoHClientWithTLS(endpoint string, tlsConfig *tls.Config) Client {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}
	tr := &http.Transport{
		TLSClientConfig:     tlsConfig,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        connPoolSize,
		MaxIdleConnsPerHost: connPoolSize,
		IdleConnTimeout:     90 * time.Second,
		DialContext: (&net.Dialer{
			Timeout: dialTimeout,
		}).DialContext,
	}
	return &dohClient{
		endpoint: endpoint,
		httpClient: &http.Client{
			Transport: tr,
			Timeout:   readTimeout + dialTimeout,
		},
	}
}

// SetTLSConfig updates the TLS configuration used by the HTTP transport.
// This replaces the underlying transport with a new one using the provided config.
func (c *dohClient) SetTLSConfig(cfg *tls.Config) {
	if cfg == nil {
		return
	}
	cfg.MinVersion = tls.VersionTLS12
	tr := &http.Transport{
		TLSClientConfig:     cfg,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        connPoolSize,
		MaxIdleConnsPerHost: connPoolSize,
		IdleConnTimeout:     90 * time.Second,
		DialContext: (&net.Dialer{
			Timeout: dialTimeout,
		}).DialContext,
	}
	c.httpClient.Transport = tr
}

// Net returns the network type identifier for this client.
func (c *dohClient) Net() string {
	return DOH
}

// Endpoint returns the DoH server URL.
func (c *dohClient) Endpoint() string {
	return c.endpoint
}

// Request sends a DNS query to the DoH server using HTTP POST (RFC 8484).
// The DNS message is serialized in wire format, sent with content-type
// application/dns-message, and the response is deserialized from wire format.
func (c *dohClient) Request(ctx context.Context, r *request.Request) (*dns.Msg, error) {
	ctx, finish := withRequestSpan(ctx, c.endpoint)
	defer finish()
	start := time.Now()

	msg, err := r.Req.Pack()
	if err != nil {
		return nil, errors.Wrap(err, "failed to pack DNS request for DoH")
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(msg))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create DoH HTTP request")
	}
	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, errors.Wrap(err, "DoH HTTP request failed")
	}
	defer func() {
		// Drain any remaining body bytes so the connection can be reused.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Errorf("DoH server returned HTTP %d", resp.StatusCode)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "application/dns-message" {
		return nil, errors.Errorf("DoH server returned unexpected content-type %q", ct)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, dohMaxResponseSize))
	if err != nil {
		return nil, errors.Wrap(err, "failed to read DoH response body")
	}

	ret := new(dns.Msg)
	if err = ret.Unpack(body); err != nil {
		return nil, errors.Wrap(err, "failed to unpack DoH DNS response")
	}

	rc, ok := dns.RcodeToString[ret.Rcode]
	if !ok {
		rc = fmt.Sprint(ret.Rcode)
	}
	RequestCount.WithLabelValues(c.endpoint).Add(1)
	RcodeCount.WithLabelValues(rc, c.endpoint).Add(1)
	RequestDuration.WithLabelValues(c.endpoint).Observe(time.Since(start).Seconds())

	return ret, nil
}
