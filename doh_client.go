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
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
)

// dohMaxResponseSize is the maximum DNS response body we will read over DoH (64 KiB).
// This prevents a malicious server from forcing unbounded memory allocation.
const dohMaxResponseSize = 64 * 1024

// dohContentType is the MIME type for DNS wire-format messages (RFC 8484 §6).
const dohContentType = "application/dns-message"

// dohClient implements the Client interface for DNS-over-HTTPS (RFC 8484).
// It uses HTTP POST with the application/dns-message content type.
type dohClient struct {
	endpoint   string        // full URL, e.g. "https://dns.google/dns-query"
	netType    string        // DOH or DOH3
	resolver   *net.Resolver // bootstrap resolver for hostname resolution (nil = system default)
	mu         sync.Mutex    // protects httpClient during SetTLSConfig
	httpClient *http.Client
}

// NewDoHClient creates a new DNS-over-HTTPS client for the given endpoint URL.
// The endpoint must be a full URL (e.g. "https://dns.google/dns-query").
// The client uses HTTP/2 with a connection-pooling transport for performance.
func NewDoHClient(endpoint string) Client {
	return newDoHClientFull(endpoint, nil, nil)
}

// newDoHClientWithTLS creates a DoH client with an optional TLS configuration override.
func newDoHClientWithTLS(endpoint string, tlsConfig *tls.Config) Client {
	return newDoHClientFull(endpoint, tlsConfig, nil)
}

// newDoHClientFull creates a DoH client with optional TLS override and bootstrap resolver.
func newDoHClientFull(endpoint string, tlsConfig *tls.Config, resolver *net.Resolver) Client {
	return &dohClient{
		endpoint:   endpoint,
		netType:    DOH,
		resolver:   resolver,
		httpClient: newHTTP2ClientWithResolver(tlsConfig, resolver),
	}
}

// newHTTP2Client creates an http.Client backed by an HTTP/2-capable transport.
// The TLS config is cloned defensively to prevent external mutation.
func newHTTP2Client(tlsConfig *tls.Config) *http.Client {
	return newHTTP2ClientWithResolver(tlsConfig, nil)
}

// newHTTP2ClientWithResolver creates an http.Client backed by an HTTP/2-capable transport.
// If resolver is non-nil it is used for hostname lookups, breaking circular
// dependencies when the system default resolver points at this DNS service.
func newHTTP2ClientWithResolver(tlsConfig *tls.Config, resolver *net.Resolver) *http.Client {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	} else {
		tlsConfig = tlsConfig.Clone()
	}
	tr := &http.Transport{
		TLSClientConfig:     tlsConfig,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        connPoolSize,
		MaxIdleConnsPerHost: connPoolSize,
		IdleConnTimeout:     90 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:  dialTimeout,
			Resolver: resolver,
		}).DialContext,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   readTimeout + dialTimeout,
	}
}

// SetTLSConfig updates the TLS configuration used by the HTTP transport.
// A new http.Client is created with the new config. The old transport is closed
// to release idle connections and avoid leaking goroutines.
func (c *dohClient) SetTLSConfig(cfg *tls.Config) {
	if cfg == nil {
		return
	}
	cfg.MinVersion = tls.VersionTLS12

	newClient := newHTTP2ClientWithResolver(cfg, c.resolver)

	c.mu.Lock()
	old := c.httpClient
	c.httpClient = newClient
	c.mu.Unlock()

	// Close idle connections on the old transport.
	if tr, ok := old.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
}

// Close releases resources held by this DoH client (closes idle HTTP connections).
func (c *dohClient) Close() error {
	c.mu.Lock()
	hc := c.httpClient
	c.mu.Unlock()
	if tr, ok := hc.Transport.(*http.Transport); ok {
		tr.CloseIdleConnections()
	}
	return nil
}

// Net returns the network type identifier for this client.
func (c *dohClient) Net() string {
	return c.netType
}

// Endpoint returns the DoH server URL.
func (c *dohClient) Endpoint() string {
	return c.endpoint
}

// Request sends a DNS query to the DoH server using HTTP POST (RFC 8484).
// The DNS message is serialized in wire format, sent with content-type
// application/dns-message, and the response is deserialized from wire format.
func (c *dohClient) Request(ctx context.Context, r *request.Request) (*dns.Msg, error) {
	c.mu.Lock()
	hc := c.httpClient
	c.mu.Unlock()
	return dohRoundTrip(ctx, hc, c.endpoint, r)
}

// dohRoundTrip performs a DNS-over-HTTPS round trip using the given http.Client.
// It packs the DNS request to wire format, sends it as an HTTP POST, validates
// the response, and unpacks the DNS reply. Shared by both DoH (HTTP/2) and DoH3 (HTTP/3).
func dohRoundTrip(ctx context.Context, httpClient *http.Client, endpoint string, r *request.Request) (*dns.Msg, error) {
	ctx, finish := withRequestSpan(ctx, endpoint)
	defer finish()
	start := time.Now()
	observeRequestAttempt(endpoint)

	msg, err := r.Req.Pack()
	if err != nil {
		observeRequestError(endpoint, requestErrorRequestEncode)
		return nil, withRequestErrorClass(errors.Wrap(err, "failed to pack DNS request for DoH"), requestErrorRequestEncode)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(msg))
	if err != nil {
		observeRequestError(endpoint, requestErrorRequestBuild)
		return nil, withRequestErrorClass(errors.Wrap(err, "failed to create DoH HTTP request"), requestErrorRequestBuild)
	}
	httpReq.Header.Set("Content-Type", dohContentType)
	httpReq.Header.Set("Accept", dohContentType)

	ret, err := dohDo(httpClient, httpReq)
	if err != nil {
		if shouldSuppressRequestFailure(ctx, err) {
			return nil, observeSuppressedRequestFailure(ctx, endpoint, err)
		}
		observeRequestError(endpoint, requestErrorClassOf(err))
		return nil, err
	}

	observeRequestResponse(endpoint, start, ret)
	return ret, nil
}

func dohDo(httpClient *http.Client, httpReq *http.Request) (*dns.Msg, error) {
	resp, err := httpClient.Do(httpReq) //nolint:gosec // G704: URL comes from plugin configuration, not user input
	if err != nil {
		return nil, withRequestErrorClass(errors.Wrap(err, "DoH HTTP request failed"), requestErrorRequestSend)
	}
	defer func() {
		// Drain any remaining body bytes so the connection can be reused.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, withRequestErrorClass(errors.Errorf("DoH server returned HTTP %d", resp.StatusCode), requestErrorResponseStatus)
	}

	if ct := resp.Header.Get("Content-Type"); ct != dohContentType {
		return nil, withRequestErrorClass(errors.Errorf("DoH server returned unexpected content-type %q", ct), requestErrorResponseContentType)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, dohMaxResponseSize))
	if err != nil {
		return nil, withRequestErrorClass(errors.Wrap(err, "failed to read DoH response body"), requestErrorResponseRead)
	}

	ret := new(dns.Msg)
	if err = ret.Unpack(body); err != nil {
		return nil, withRequestErrorClass(errors.Wrap(err, "failed to unpack DoH DNS response"), requestErrorResponseDecode)
	}

	return ret, nil
}
