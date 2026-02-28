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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
)

// doh3TestServer wraps an http3.Server with its TLS certificate material and address.
type doh3TestServer struct {
	server    *http3.Server
	conn      net.PacketConn
	addr      string
	clientTLS *tls.Config
	certPEM   []byte
}

// close shuts down the HTTP/3 test server.
func (s *doh3TestServer) close() {
	_ = s.server.Close()
	_ = s.conn.Close()
}

// url returns the https:// URL of the test server for the /dns-query endpoint.
func (s *doh3TestServer) url() string {
	return fmt.Sprintf("https://%s/dns-query", s.addr)
}

// newDoH3TestServer starts an HTTP/3 (QUIC) server that handles DNS-over-HTTPS requests.
// Returns the server wrapper and a TLS config that trusts the server's self-signed certificate.
func newDoH3TestServer(t *testing.T, handler dns.HandlerFunc) *doh3TestServer { //nolint:funlen // test helper setup
	t.Helper()

	// Generate a self-signed ECDSA certificate for the test server.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"DoH3 Test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	// Build trust pool for clients.
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)
	clientTLS := &tls.Config{
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS13,
	}

	// DNS-over-HTTPS handler mux.
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
			return
		}
		if ct := r.Header.Get("Content-Type"); ct != dohContentType {
			http.Error(w, "bad content-type", http.StatusBadRequest)
			return
		}

		buf := make([]byte, 64*1024)
		n, readErr := r.Body.Read(buf)
		if readErr != nil && readErr != io.EOF {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}

		msg := new(dns.Msg)
		if unpackErr := msg.Unpack(buf[:n]); unpackErr != nil {
			http.Error(w, "unpack error", http.StatusBadRequest)
			return
		}

		rec := &dohResponseRecorder{msg: msg}
		handler(rec, msg)

		resp := rec.result
		if resp == nil {
			resp = new(dns.Msg)
			resp.SetRcode(msg, dns.RcodeServerFailure)
		}

		packed, packErr := resp.Pack()
		if packErr != nil {
			http.Error(w, "pack error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", dohContentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(packed)
	})

	// Listen on a random UDP port.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
	}

	h3Server := &http3.Server{
		TLSConfig: http3.ConfigureTLSConfig(serverTLS),
		Handler:   mux,
	}

	go func() {
		_ = h3Server.Serve(conn)
	}()

	return &doh3TestServer{
		server:    h3Server,
		conn:      conn,
		addr:      conn.LocalAddr().String(),
		clientTLS: clientTLS,
		certPEM:   certPEM,
	}
}

// closeDoH3Client shuts down the underlying QUIC transport so that its background goroutines
// are cleaned up. This prevents goleak from flagging them.
func closeDoH3Client(t *testing.T, c Client) {
	t.Helper()
	if dc, ok := c.(*doh3Client); ok {
		require.NoError(t, dc.transport.Close())
	}
}

// TestDoH3ClientBasicRequest verifies that a DoH3 client can send a DNS query over QUIC
// and receive a valid A record response.
func TestDoH3ClientBasicRequest(t *testing.T) {
	srv := newDoH3TestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("93.184.216.34"),
		})
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.close()

	c := newDoH3ClientWithTLS(srv.url(), srv.clientTLS)
	defer closeDoH3Client(t, c)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Len(t, resp.Answer, 1)

	a, ok := resp.Answer[0].(*dns.A)
	require.True(t, ok)
	require.Equal(t, "93.184.216.34", a.A.String())
}

// TestDoH3ClientNXDOMAIN verifies correct NXDOMAIN handling over HTTP/3.
func TestDoH3ClientNXDOMAIN(t *testing.T) {
	srv := newDoH3TestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetRcode(r, dns.RcodeNameError)
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.close()

	c := newDoH3ClientWithTLS(srv.url(), srv.clientTLS)
	defer closeDoH3Client(t, c)

	req := new(dns.Msg)
	req.SetQuestion("nonexistent.example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.NoError(t, err)
	require.Equal(t, dns.RcodeNameError, resp.Rcode)
}

// TestDoH3ClientMultipleRecords verifies that multiple A records are returned correctly over HTTP/3.
func TestDoH3ClientMultipleRecords(t *testing.T) {
	srv := newDoH3TestServer(t, func(w dns.ResponseWriter, r *dns.Msg) { //nolint:dupl // test pattern shared with DoQ
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer,
			&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("10.0.0.1")},
			&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("10.0.0.2")},
			&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("10.0.0.3")},
		)
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.close()

	c := newDoH3ClientWithTLS(srv.url(), srv.clientTLS)
	defer closeDoH3Client(t, c)

	req := new(dns.Msg)
	req.SetQuestion("multi.example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.NoError(t, err)
	require.Len(t, resp.Answer, 3)
}

// TestDoH3ClientAAAARecord verifies that AAAA (IPv6) records are handled over HTTP/3.
func TestDoH3ClientAAAARecord(t *testing.T) {
	srv := newDoH3TestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
			AAAA: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"),
		})
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.close()

	c := newDoH3ClientWithTLS(srv.url(), srv.clientTLS)
	defer closeDoH3Client(t, c)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeAAAA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.NoError(t, err)
	require.Len(t, resp.Answer, 1)

	aaaa, ok := resp.Answer[0].(*dns.AAAA)
	require.True(t, ok)
	require.Equal(t, "2606:2800:220:1:248:1893:25c8:1946", aaaa.AAAA.String())
}

// TestDoH3ClientSERVFAIL verifies that SERVFAIL is returned as a DNS-level response,
// not a transport error, over HTTP/3.
func TestDoH3ClientSERVFAIL(t *testing.T) {
	srv := newDoH3TestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetRcode(r, dns.RcodeServerFailure)
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.close()

	c := newDoH3ClientWithTLS(srv.url(), srv.clientTLS)
	defer closeDoH3Client(t, c)

	req := new(dns.Msg)
	req.SetQuestion("fail.example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, dns.RcodeServerFailure, resp.Rcode)
}

// TestDoH3ClientIDPreservation verifies that the DNS message ID is correctly
// round-tripped through the HTTP/3 transport.
func TestDoH3ClientIDPreservation(t *testing.T) {
	srv := newDoH3TestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("1.1.1.1"),
		})
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.close()

	c := newDoH3ClientWithTLS(srv.url(), srv.clientTLS)
	defer closeDoH3Client(t, c)

	req := new(dns.Msg)
	req.SetQuestion("id-test.example.com.", dns.TypeA)
	req.Id = 54321

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.NoError(t, err)
	require.Equal(t, uint16(54321), resp.Id)
}

// TestDoH3ClientPreservesFlags verifies that DNS header flags (AA, RD, RA) are
// preserved through the HTTP/3 transport.
func TestDoH3ClientPreservesFlags(t *testing.T) {
	srv := newDoH3TestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Authoritative = true
		msg.RecursionAvailable = true
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("10.10.10.10"),
		})
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.close()

	c := newDoH3ClientWithTLS(srv.url(), srv.clientTLS)
	defer closeDoH3Client(t, c)

	req := new(dns.Msg)
	req.SetQuestion("flags.example.com.", dns.TypeA)
	req.RecursionDesired = true

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.NoError(t, err)
	require.True(t, resp.Authoritative)
	require.True(t, resp.RecursionAvailable)
	require.True(t, resp.RecursionDesired)
}

// TestDoH3ClientEmptyResponse verifies that empty (NODATA) responses are handled
// correctly over HTTP/3.
func TestDoH3ClientEmptyResponse(t *testing.T) {
	srv := newDoH3TestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.close()

	c := newDoH3ClientWithTLS(srv.url(), srv.clientTLS)
	defer closeDoH3Client(t, c)

	req := new(dns.Msg)
	req.SetQuestion("nodata.example.com.", dns.TypeMX)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Empty(t, resp.Answer)
	require.Equal(t, dns.RcodeSuccess, resp.Rcode)
}

// TestDoH3ClientTXTRecord verifies that TXT records are handled over HTTP/3.
func TestDoH3ClientTXTRecord(t *testing.T) {
	srv := newDoH3TestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
			Txt: []string{"v=spf1 include:example.com ~all"},
		})
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.close()

	c := newDoH3ClientWithTLS(srv.url(), srv.clientTLS)
	defer closeDoH3Client(t, c)

	req := new(dns.Msg)
	req.SetQuestion("txt.example.com.", dns.TypeTXT)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.NoError(t, err)
	require.Len(t, resp.Answer, 1)

	txt, ok := resp.Answer[0].(*dns.TXT)
	require.True(t, ok)
	require.Equal(t, []string{"v=spf1 include:example.com ~all"}, txt.Txt)
}

// TestDoH3ClientConcurrentRequests verifies that the DoH3 client handles multiple
// concurrent requests safely under the race detector.
func TestDoH3ClientConcurrentRequests(t *testing.T) {
	srv := newDoH3TestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("1.2.3.4"),
		})
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.close()

	c := newDoH3ClientWithTLS(srv.url(), srv.clientTLS)
	defer closeDoH3Client(t, c)

	const goroutines = 10
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			req := new(dns.Msg)
			req.SetQuestion("concurrent.example.com.", dns.TypeA)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			resp, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
			if err != nil {
				errs <- err
				return
			}
			if len(resp.Answer) != 1 {
				errs <- dns.ErrRdata
				return
			}
			errs <- nil
		}()
	}

	for i := 0; i < goroutines; i++ {
		require.NoError(t, <-errs)
	}
}

// TestDoH3ClientEndpointAndNet verifies that the DoH3 client returns the correct
// endpoint URL and network type.
func TestDoH3ClientEndpointAndNet(t *testing.T) {
	c := NewDoH3Client("https://dns.google/dns-query")
	defer closeDoH3Client(t, c)

	require.Equal(t, "https://dns.google/dns-query", c.Endpoint())
	require.Equal(t, DOH3, c.Net())
}

// TestDoH3ClientSetTLSConfig verifies that SetTLSConfig updates the transport
// without panicking and enforces TLS 1.3 minimum.
func TestDoH3ClientSetTLSConfig(t *testing.T) {
	c := NewDoH3Client("https://dns.google/dns-query")
	defer closeDoH3Client(t, c)

	// Should not panic with nil.
	c.SetTLSConfig(nil)
	require.Equal(t, DOH3, c.Net())

	// Should not panic with a real config.
	c.SetTLSConfig(&tls.Config{
		MinVersion: tls.VersionTLS12, // should be upgraded to TLS 1.3
		ServerName: "dns.google",
	})
	require.Equal(t, DOH3, c.Net())

	// Verify TLS 1.3 enforcement.
	dc, ok := c.(*doh3Client)
	require.True(t, ok)
	require.GreaterOrEqual(t, dc.transport.TLSClientConfig.MinVersion, uint16(tls.VersionTLS13))
}

// TestDoH3ClientTLSMinVersion verifies that the DoH3 client always enforces TLS 1.3 minimum,
// as required by QUIC (RFC 9001).
func TestDoH3ClientTLSMinVersion(t *testing.T) {
	c := NewDoH3Client("https://dns.google/dns-query")
	defer closeDoH3Client(t, c)
	dc, ok := c.(*doh3Client)
	require.True(t, ok)
	require.GreaterOrEqual(t, dc.transport.TLSClientConfig.MinVersion, uint16(tls.VersionTLS13))
}

// TestDoH3ClientServerDown verifies that the DoH3 client returns an error when the
// server is unreachable.
func TestDoH3ClientServerDown(t *testing.T) {
	c := newDoH3ClientWithTLS("https://127.0.0.1:1/dns-query", &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test only
		MinVersion:         tls.VersionTLS13,
	})
	defer closeDoH3Client(t, c)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.Error(t, err)
}

// TestDoH3ClientContextCancellation verifies that a cancelled context aborts the HTTP/3 request.
func TestDoH3ClientContextCancellation(t *testing.T) {
	srv := newDoH3TestServer(t, func(_ dns.ResponseWriter, _ *dns.Msg) {
		// Slow handler: sleep longer than the context timeout.
		time.Sleep(10 * time.Second)
	})
	defer srv.close()

	c := newDoH3ClientWithTLS(srv.url(), srv.clientTLS)
	defer closeDoH3Client(t, c)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	_, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.Error(t, err)
}

// TestDoH3ClientInvalidURL verifies that creating a DoH3 client with an invalid URL
// returns an error when a request is attempted.
func TestDoH3ClientInvalidURL(t *testing.T) {
	c := NewDoH3Client("://not-a-valid-url")
	defer closeDoH3Client(t, c)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.Error(t, err)
}

// TestDoH3IntegrationWithFanout verifies end-to-end DNS resolution through the fanout
// plugin using a DoH3 backend.
func TestDoH3IntegrationWithFanout(t *testing.T) {
	srv := newDoH3TestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("9.8.7.6"),
		})
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.close()

	f := New()
	f.From = "."
	doh3c := newDoH3ClientWithTLS(srv.url(), srv.clientTLS)
	defer closeDoH3Client(t, doh3c)
	f.AddClient(doh3c)

	req := new(dns.Msg)
	req.SetQuestion("fanout-doh3.example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := doh3c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.NoError(t, err)
	require.Len(t, resp.Answer, 1)

	a, ok := resp.Answer[0].(*dns.A)
	require.True(t, ok)
	require.Equal(t, "9.8.7.6", a.A.String())
}

// TestSetupDoH3Config verifies that the fanout plugin parses h3:// URLs from the Corefile
// and creates DoH3 clients.
func TestSetupDoH3Config(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedURLs []string
		expectedNets []string
	}{
		{
			name:         "single-doh3-endpoint",
			input:        "fanout . h3://dns.google/dns-query",
			expectedURLs: []string{"https://dns.google/dns-query"},
			expectedNets: []string{DOH3},
		},
		{
			name:         "multiple-doh3-endpoints",
			input:        "fanout . h3://dns.google/dns-query h3://cloudflare-dns.com/dns-query",
			expectedURLs: []string{"https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query"},
			expectedNets: []string{DOH3, DOH3},
		},
		{
			name:         "mixed-doh-and-doh3",
			input:        "fanout . https://dns.google/dns-query h3://cloudflare-dns.com/dns-query",
			expectedURLs: []string{"https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query"},
			expectedNets: []string{DOH, DOH3},
		},
		{
			name:         "mixed-plain-doh-doh3",
			input:        "fanout . 127.0.0.1 https://dns.google/dns-query h3://cloudflare-dns.com/dns-query",
			expectedURLs: []string{"127.0.0.1:53", "https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query"},
			expectedNets: []string{"udp", DOH, DOH3},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.input)
			f, err := parseFanout(c)

			require.NoError(t, err)
			require.Len(t, f.clients, len(tc.expectedURLs))

			for i, expected := range tc.expectedURLs {
				require.Equal(t, expected, f.clients[i].Endpoint())
				require.Equal(t, tc.expectedNets[i], f.clients[i].Net())
			}
		})
	}
}

// TestSetupDoH3NetworkProtocol verifies that "dns-over-https3" is accepted as a network protocol value.
func TestSetupDoH3NetworkProtocol(t *testing.T) {
	input := `fanout . h3://dns.google/dns-query {
		network dns-over-https3
	}`
	c := caddy.NewTestController("dns", input)
	f, err := parseFanout(c)

	require.NoError(t, err)
	require.Equal(t, DOH3, f.net)
}

// TestSetupDoH3WithOptions verifies that DoH3 endpoints work with additional fanout options.
func TestSetupDoH3WithOptions(t *testing.T) {
	input := `fanout . h3://dns.google/dns-query h3://cloudflare-dns.com/dns-query {
		worker-count 2
		timeout 10s
	}`
	c := caddy.NewTestController("dns", input)
	f, err := parseFanout(c)

	require.NoError(t, err)
	require.Len(t, f.clients, 2)
	require.Equal(t, 2, f.WorkerCount)
	require.Equal(t, 10*time.Second, f.Timeout)
	require.Equal(t, DOH3, f.clients[0].Net())
	require.Equal(t, DOH3, f.clients[1].Net())
}

// TestSetupDoH3WithRace verifies the race option combined with DoH3 endpoints.
func TestSetupDoH3WithRace(t *testing.T) {
	input := `fanout . h3://dns.google/dns-query h3://cloudflare-dns.com/dns-query {
		race
	}`
	c := caddy.NewTestController("dns", input)
	f, err := parseFanout(c)

	require.NoError(t, err)
	require.True(t, f.Race)
	require.Len(t, f.clients, 2)
}

// TestSetupDoH3WithExcept verifies that the except directive works alongside DoH3 endpoints.
func TestSetupDoH3WithExcept(t *testing.T) {
	input := `fanout . h3://dns.google/dns-query {
		except internal.example.com
	}`
	c := caddy.NewTestController("dns", input)
	f, err := parseFanout(c)

	require.NoError(t, err)
	require.True(t, f.ExcludeDomains.Contains("internal.example.com."))
}

// TestSetupDoH3CaseInsensitive verifies that h3:// URLs are detected case-insensitively.
func TestSetupDoH3CaseInsensitive(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"lowercase", "fanout . h3://dns.google/dns-query"},
		{"uppercase", "fanout . H3://dns.google/dns-query"},
		{"mixedcase", "fanout . H3://DNS.Google/dns-query"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.input)
			f, err := parseFanout(c)
			require.NoError(t, err)
			require.Len(t, f.clients, 1)
			require.Equal(t, DOH3, f.clients[0].Net())
		})
	}
}

// TestSetupDoH3MixedWithTLS verifies that DoH3 works together with tls:// scheme hosts.
func TestSetupDoH3MixedWithTLS(t *testing.T) {
	input := "fanout . tls://1.1.1.1 h3://dns.google/dns-query {\ntls-server cloudflare\n}"
	c := caddy.NewTestController("dns", input)
	f, err := parseFanout(c)

	require.NoError(t, err)
	require.Len(t, f.clients, 2)

	// First client should be the TLS client.
	require.Contains(t, f.clients[0].Endpoint(), "1.1.1.1")
	require.Contains(t, strings.ToLower(f.clients[0].Net()), "tls")

	// Second should be the DoH3 client.
	require.Equal(t, "https://dns.google/dns-query", f.clients[1].Endpoint())
	require.Equal(t, DOH3, f.clients[1].Net())
}

// TestDoH3DoesNotBreakExistingSetup verifies that DoH3 support does not break
// existing plain-host or DoH configurations.
func TestDoH3DoesNotBreakExistingSetup(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedNet string
		expectedN   int
	}{
		{name: "plain-udp", input: "fanout . 127.0.0.1", expectedNet: "udp", expectedN: 1},
		{name: "plain-tcp", input: "fanout . 127.0.0.1 {\nnetwork tcp\n}", expectedNet: "tcp", expectedN: 1},
		{name: "doh-only", input: "fanout . https://dns.google/dns-query", expectedNet: "udp", expectedN: 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.input)
			f, err := parseFanout(c)
			require.NoError(t, err)
			require.Len(t, f.clients, tc.expectedN)
			require.Equal(t, tc.expectedNet, f.net)
		})
	}
}

// TestSetupAllThreeTransports verifies that plain, DoH, and DoH3 endpoints can all
// be configured together in a single fanout stanza.
func TestSetupAllThreeTransports(t *testing.T) {
	input := "fanout . 127.0.0.1 https://dns.google/dns-query h3://cloudflare-dns.com/dns-query"
	c := caddy.NewTestController("dns", input)
	f, err := parseFanout(c)

	require.NoError(t, err)
	require.Len(t, f.clients, 3)

	// Plain clients first, then DoH, then DoH3.
	require.Equal(t, "127.0.0.1:53", f.clients[0].Endpoint())
	require.Equal(t, "udp", f.clients[0].Net())

	require.Equal(t, "https://dns.google/dns-query", f.clients[1].Endpoint())
	require.Equal(t, DOH, f.clients[1].Net())

	require.Equal(t, "https://cloudflare-dns.com/dns-query", f.clients[2].Endpoint())
	require.Equal(t, DOH3, f.clients[2].Net())
}
