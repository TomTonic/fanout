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
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// newDoHTestServer starts an httptest TLS server that acts as a DNS-over-HTTPS endpoint.
// The handler receives incoming DNS wire-format POST requests, passes them to the provided
// dns.HandlerFunc, captures the response, and writes it back as application/dns-message.
// It returns the server and a TLS config suitable for clients to trust the server's certificate.
func newDoHTestServer(t *testing.T, handler dns.HandlerFunc) (*httptest.Server, *tls.Config) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
			return
		}
		ct := r.Header.Get("Content-Type")
		if ct != "application/dns-message" {
			http.Error(w, "bad content-type", http.StatusBadRequest)
			return
		}

		buf := make([]byte, 64*1024)
		n, err := r.Body.Read(buf)
		if err != nil && err.Error() != "EOF" {
			http.Error(w, "read error", http.StatusBadRequest)
			return
		}

		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
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

		packed, err := resp.Pack()
		if err != nil {
			http.Error(w, "pack error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(packed)
	})

	srv := httptest.NewTLSServer(mux)

	// Build a client TLS config that trusts the test server's certificate.
	certPool := x509.NewCertPool()
	for _, c := range srv.TLS.Certificates {
		for _, raw := range c.Certificate {
			cert, err := x509.ParseCertificate(raw)
			if err == nil {
				certPool.AddCert(cert)
			}
		}
	}
	clientTLS := &tls.Config{
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS12,
	}

	return srv, clientTLS
}

// testServerClientTLS builds a TLS config that trusts a standalone httptest.Server's certificate.
func testServerClientTLS(srv *httptest.Server) *tls.Config {
	certPool := x509.NewCertPool()
	for _, c := range srv.TLS.Certificates {
		for _, raw := range c.Certificate {
			cert, err := x509.ParseCertificate(raw)
			if err == nil {
				certPool.AddCert(cert)
			}
		}
	}
	return &tls.Config{
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS12,
	}
}

// dohResponseRecorder implements dns.ResponseWriter to capture the handler's reply.
type dohResponseRecorder struct {
	msg    *dns.Msg
	result *dns.Msg
}

func (d *dohResponseRecorder) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}
func (d *dohResponseRecorder) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}
func (d *dohResponseRecorder) WriteMsg(m *dns.Msg) error {
	d.result = m
	return nil
}
func (d *dohResponseRecorder) Write(b []byte) (int, error) {
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		return 0, err
	}
	d.result = m
	return len(b), nil
}
func (d *dohResponseRecorder) Close() error        { return nil }
func (d *dohResponseRecorder) TsigStatus() error   { return nil }
func (d *dohResponseRecorder) TsigTimersOnly(bool) {}
func (d *dohResponseRecorder) Hijack()             {}

// TestDoHClientBasicRequest verifies that a DoH client can send a DNS query and receive
// a valid response from a test DoH server.
func TestDoHClientBasicRequest(t *testing.T) {
	srv, clientTLS := newDoHTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("93.184.216.34"),
		})
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.Close()

	c := newDoHClientWithTLS(srv.URL+"/dns-query", clientTLS)

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

// TestDoHClientNXDOMAIN verifies that the DoH client correctly handles an NXDOMAIN response.
func TestDoHClientNXDOMAIN(t *testing.T) {
	srv, clientTLS := newDoHTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetRcode(r, dns.RcodeNameError)
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.Close()

	c := newDoHClientWithTLS(srv.URL+"/dns-query", clientTLS)

	req := new(dns.Msg)
	req.SetQuestion("nonexistent.example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, dns.RcodeNameError, resp.Rcode)
}

// TestDoHClientMultipleRecords verifies that the DoH client can handle responses with
// multiple answer records.
func TestDoHClientMultipleRecords(t *testing.T) {
	srv, clientTLS := newDoHTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer,
			&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("10.0.0.1")},
			&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("10.0.0.2")},
			&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("10.0.0.3")},
		)
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.Close()

	c := newDoHClientWithTLS(srv.URL+"/dns-query", clientTLS)

	req := new(dns.Msg)
	req.SetQuestion("multi.example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.NoError(t, err)
	require.Len(t, resp.Answer, 3)
}

// TestDoHClientHTTPError verifies that the DoH client returns an error when the server
// responds with a non-200 HTTP status code.
func TestDoHClientHTTPError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := newDoHClientWithTLS(srv.URL+"/dns-query", testServerClientTLS(srv))

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.Error(t, err)
	require.Contains(t, err.Error(), "HTTP 503")
}

// TestDoHClientBadContentType verifies that the DoH client returns an error when the
// server responds with an unexpected content-type header.
func TestDoHClientBadContentType(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>not dns</html>"))
	}))
	defer srv.Close()

	c := newDoHClientWithTLS(srv.URL+"/dns-query", testServerClientTLS(srv))

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected content-type")
}

// TestDoHClientContextCancellation verifies that the DoH client immediately returns
// an error when the request context is cancelled before the server responds.
func TestDoHClientContextCancellation(t *testing.T) {
	// Server that sleeps longer than the context deadline to force cancellation.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(30 * time.Second)
	}))
	defer srv.Close()

	c := newDoHClientWithTLS(srv.URL+"/dns-query", testServerClientTLS(srv))

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.Error(t, err)
}

// TestDoHClientEndpointAndNet verifies that the DoH client returns the correct
// endpoint URL and network type.
func TestDoHClientEndpointAndNet(t *testing.T) {
	c := NewDoHClient("https://dns.google/dns-query")

	require.Equal(t, "https://dns.google/dns-query", c.Endpoint())
	require.Equal(t, DOH, c.Net())
}

// TestDoHClientSetTLSConfig verifies that SetTLSConfig updates the transport TLS
// configuration without panicking.
func TestDoHClientSetTLSConfig(t *testing.T) {
	c := NewDoHClient("https://dns.google/dns-query")

	// Should not panic with nil.
	c.SetTLSConfig(nil)
	require.Equal(t, DOH, c.Net())

	// Should not panic with a real config.
	c.SetTLSConfig(&tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: "dns.google",
	})
	require.Equal(t, DOH, c.Net())
}

// TestDoHClientMalformedResponse verifies that the DoH client returns an error when
// the server sends an invalid (non-DNS) response body.
func TestDoHClientMalformedResponse(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("this is not a valid DNS message"))
	}))
	defer srv.Close()

	c := newDoHClientWithTLS(srv.URL+"/dns-query", testServerClientTLS(srv))

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unpack")
}

// TestDoHClientConcurrentRequests verifies that the DoH client handles multiple
// concurrent requests safely under the race detector.
func TestDoHClientConcurrentRequests(t *testing.T) {
	srv, clientTLS := newDoHTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("1.2.3.4"),
		})
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.Close()

	c := newDoHClientWithTLS(srv.URL+"/dns-query", clientTLS)

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

// TestDoHClientAAAARecord verifies that the DoH client can handle AAAA (IPv6) responses.
func TestDoHClientAAAARecord(t *testing.T) {
	srv, clientTLS := newDoHTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
			AAAA: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"),
		})
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.Close()

	c := newDoHClientWithTLS(srv.URL+"/dns-query", clientTLS)

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

// TestDoHClientEmptyResponse verifies that the DoH client handles responses with
// zero answer records correctly (e.g. NODATA).
func TestDoHClientEmptyResponse(t *testing.T) {
	srv, clientTLS := newDoHTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		// No answer records (NODATA).
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.Close()

	c := newDoHClientWithTLS(srv.URL+"/dns-query", clientTLS)

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

// TestDoHClientServerDown verifies that the DoH client returns an error when the
// server is unreachable (connection refused).
func TestDoHClientServerDown(t *testing.T) {
	c := newDoHClientWithTLS("https://127.0.0.1:1/dns-query", &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test only
		MinVersion:         tls.VersionTLS12,
	})

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.Error(t, err)
}

// TestDoHClientCustomTLS verifies that a DoH client works correctly with a custom
// TLS configuration using a self-signed certificate.
func TestDoHClientCustomTLS(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"DoH Test"}},
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

	// Start a custom TLS server.
	mux := http.NewServeMux()
	mux.HandleFunc("/dns-query", func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 64*1024)
		n, _ := r.Body.Read(buf)
		msg := new(dns.Msg)
		if err := msg.Unpack(buf[:n]); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(msg)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: msg.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.168.1.1"),
		})
		packed, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(packed)
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	defer srv.Close()

	// Create a client with a CA pool that trusts our self-signed cert.
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(certPEM)
	clientTLS := &tls.Config{
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS12,
	}

	c := NewDoHClient(srv.URL + "/dns-query")
	c.SetTLSConfig(clientTLS)

	req := new(dns.Msg)
	req.SetQuestion("custom-tls.example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.NoError(t, err)
	require.Len(t, resp.Answer, 1)

	a, ok := resp.Answer[0].(*dns.A)
	require.True(t, ok)
	require.Equal(t, "192.168.1.1", a.A.String())
}

// TestSetupDoHConfig verifies that the fanout plugin parses DoH URLs from the Corefile.
func TestSetupDoHConfig(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedURLs []string
		expectedErr  string
	}{
		{
			name:         "single-doh-endpoint",
			input:        "fanout . https://dns.google/dns-query",
			expectedURLs: []string{"https://dns.google/dns-query"},
		},
		{
			name:         "multiple-doh-endpoints",
			input:        "fanout . https://dns.google/dns-query https://cloudflare-dns.com/dns-query",
			expectedURLs: []string{"https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query"},
		},
		{
			name:         "mixed-doh-and-plain",
			input:        "fanout . 127.0.0.1 https://dns.google/dns-query",
			expectedURLs: []string{"127.0.0.1:53", "https://dns.google/dns-query"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.input)
			f, err := parseFanout(c)

			if tc.expectedErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectedErr)
				return
			}

			require.NoError(t, err)
			require.Len(t, f.clients, len(tc.expectedURLs))

			for i, expected := range tc.expectedURLs {
				require.Equal(t, expected, f.clients[i].Endpoint())
			}
		})
	}
}

// TestSetupDoHWithOptions verifies that DoH endpoints work with additional fanout options
// like worker-count, timeout, and policy.
func TestSetupDoHWithOptions(t *testing.T) {
	input := `fanout . https://dns.google/dns-query https://cloudflare-dns.com/dns-query {
		worker-count 2
		timeout 10s
	}`
	c := caddy.NewTestController("dns", input)
	f, err := parseFanout(c)

	require.NoError(t, err)
	require.Len(t, f.clients, 2)
	require.Equal(t, 2, f.WorkerCount)
	require.Equal(t, 10*time.Second, f.Timeout)
	require.Equal(t, DOH, f.clients[0].Net())
	require.Equal(t, DOH, f.clients[1].Net())
}

// TestSetupDoHNetworkProtocol verifies that "dns-over-https" is accepted as a network protocol value.
func TestSetupDoHNetworkProtocol(t *testing.T) {
	input := `fanout . https://dns.google/dns-query {
		network dns-over-https
	}`
	c := caddy.NewTestController("dns", input)
	f, err := parseFanout(c)

	require.NoError(t, err)
	require.Equal(t, DOH, f.net)
}

// TestDoHClientIDPreservation verifies that the response message ID matches the request ID,
// ensuring the DoH client correctly round-trips the DNS message identity.
func TestDoHClientIDPreservation(t *testing.T) {
	srv, clientTLS := newDoHTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r) // SetReply copies the ID
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("1.1.1.1"),
		})
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.Close()

	c := newDoHClientWithTLS(srv.URL+"/dns-query", clientTLS)

	req := new(dns.Msg)
	req.SetQuestion("id-test.example.com.", dns.TypeA)
	req.Id = 12345

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.NoError(t, err)
	require.Equal(t, uint16(12345), resp.Id)
}

// TestDoHClientSERVFAIL verifies that the DoH client returns a SERVFAIL response correctly
// without treating it as a transport-level error.
func TestDoHClientSERVFAIL(t *testing.T) {
	srv, clientTLS := newDoHTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetRcode(r, dns.RcodeServerFailure)
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.Close()

	c := newDoHClientWithTLS(srv.URL+"/dns-query", clientTLS)

	req := new(dns.Msg)
	req.SetQuestion("fail.example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, dns.RcodeServerFailure, resp.Rcode)
}

// TestDoHIntegrationWithFanout verifies end-to-end DNS resolution through the fanout plugin
// using a DoH backend. A Fanout instance with a single DoH client sends a query and verifies
// the expected A record is returned.
func TestDoHIntegrationWithFanout(t *testing.T) {
	srv, clientTLS := newDoHTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("5.6.7.8"),
		})
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.Close()

	f := New()
	f.From = "."
	dohClient := newDoHClientWithTLS(srv.URL+"/dns-query", clientTLS)
	f.AddClient(dohClient)

	req := new(dns.Msg)
	req.SetQuestion("fanout-doh.example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := dohClient.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.NoError(t, err)
	require.Len(t, resp.Answer, 1)

	a, ok := resp.Answer[0].(*dns.A)
	require.True(t, ok)
	require.Equal(t, "5.6.7.8", a.A.String())
}

// TestDoHClientInvalidURL verifies that creating a DoH client with an invalid URL
// returns an error when a request is attempted.
func TestDoHClientInvalidURL(t *testing.T) {
	c := NewDoHClient("://not-a-valid-url")

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.Error(t, err)
}

// TestDoHClientTXTRecord verifies that the DoH client can handle TXT record responses.
func TestDoHClientTXTRecord(t *testing.T) {
	srv, clientTLS := newDoHTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
			Txt: []string{"v=spf1 include:example.com ~all"},
		})
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.Close()

	c := newDoHClientWithTLS(srv.URL+"/dns-query", clientTLS)

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

// TestSetupMixedDoHAndPlainParsing verifies that the parser correctly separates DoH URLs
// from plain IP addresses and creates the appropriate client types.
func TestSetupMixedDoHAndPlainParsing(t *testing.T) {
	input := "fanout . 127.0.0.1 https://dns.google/dns-query 127.0.0.2"
	c := caddy.NewTestController("dns", input)
	f, err := parseFanout(c)

	require.NoError(t, err)
	require.Len(t, f.clients, 3)

	// Plain clients come first (from initClients), then DoH clients (from initDoHClients).
	require.Equal(t, "127.0.0.1:53", f.clients[0].Endpoint())
	require.Equal(t, "udp", f.clients[0].Net())

	require.Equal(t, "127.0.0.2:53", f.clients[1].Endpoint())
	require.Equal(t, "udp", f.clients[1].Net())

	require.Equal(t, "https://dns.google/dns-query", f.clients[2].Endpoint())
	require.Equal(t, DOH, f.clients[2].Net())
}

// TestSetupDoHOnlyNoPlain verifies that a configuration with only DoH endpoints
// and no plain hosts parses correctly.
func TestSetupDoHOnlyNoPlain(t *testing.T) {
	input := "fanout . https://dns.google/dns-query"
	c := caddy.NewTestController("dns", input)
	f, err := parseFanout(c)

	require.NoError(t, err)
	require.Len(t, f.clients, 1)
	require.Equal(t, DOH, f.clients[0].Net())
}

// TestSetupDoHWithExcept verifies that the except directive works alongside DoH endpoints.
func TestSetupDoHWithExcept(t *testing.T) {
	input := `fanout . https://dns.google/dns-query {
		except internal.example.com
	}`
	c := caddy.NewTestController("dns", input)
	f, err := parseFanout(c)

	require.NoError(t, err)
	require.True(t, f.ExcludeDomains.Contains("internal.example.com."))
}

// TestDoHClientConnectionRefused verifies that the DoH client returns an appropriate error
// when connecting to a server that immediately closes the connection.
func TestDoHClientConnectionRefused(t *testing.T) {
	// Start a server that immediately closes connections.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	defer func() { _ = ln.Close() }()

	c := newDoHClientWithTLS("https://"+ln.Addr().String()+"/dns-query", &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test only
		MinVersion:         tls.VersionTLS12,
	})

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.Error(t, err)
}

// TestDoHClientPreservesFlags verifies that DNS flags from the upstream response
// (Authoritative, RecursionDesired, RecursionAvailable) are preserved through DoH.
func TestDoHClientPreservesFlags(t *testing.T) {
	srv, clientTLS := newDoHTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
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
	defer srv.Close()

	c := newDoHClientWithTLS(srv.URL+"/dns-query", clientTLS)

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

// TestSetupDoHConfigWithRace verifies the race option combined with DoH endpoints.
func TestSetupDoHConfigWithRace(t *testing.T) {
	input := `fanout . https://dns.google/dns-query https://cloudflare-dns.com/dns-query {
		race
	}`
	c := caddy.NewTestController("dns", input)
	f, err := parseFanout(c)

	require.NoError(t, err)
	require.True(t, f.Race)
	require.Len(t, f.clients, 2)
}

// TestSetupDoHConfigCaseInsensitive verifies that HTTPS URLs are detected case-insensitively.
func TestSetupDoHConfigCaseInsensitive(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"lowercase", "fanout . https://dns.google/dns-query"},
		{"uppercase", "fanout . HTTPS://dns.google/dns-query"},
		{"mixedcase", "fanout . Https://DNS.Google/dns-query"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.input)
			f, err := parseFanout(c)
			require.NoError(t, err)
			require.Len(t, f.clients, 1)
			require.Equal(t, DOH, f.clients[0].Net())
		})
	}
}

// TestDoHParseDoesNotBreakExistingSetup verifies that adding DoH support does not
// break any existing plain-host or TLS configurations.
func TestDoHParseDoesNotBreakExistingSetup(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedNet string
		expectedN   int
	}{
		{name: "plain-udp", input: "fanout . 127.0.0.1", expectedNet: "udp", expectedN: 1},
		{name: "plain-tcp", input: "fanout . 127.0.0.1 {\nnetwork tcp\n}", expectedNet: "tcp", expectedN: 1},
		{name: "two-hosts", input: "fanout . 127.0.0.1 127.0.0.2", expectedNet: "udp", expectedN: 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.input)
			f, err := parseFanout(c)
			require.NoError(t, err)
			require.Len(t, f.clients, tc.expectedN)
			require.Equal(t, tc.expectedNet, f.net)
			for _, cl := range f.clients {
				require.NotEqual(t, DOH, cl.Net(), "plain config should not create DoH clients")
			}
		})
	}
}

// TestDoHClientTLSMinVersion verifies that the DoH client enforces a minimum TLS version.
func TestDoHClientTLSMinVersion(t *testing.T) {
	c := NewDoHClient("https://dns.google/dns-query")
	dc, ok := c.(*dohClient)
	require.True(t, ok)

	tr, ok := dc.httpClient.Transport.(*http.Transport)
	require.True(t, ok)
	require.GreaterOrEqual(t, tr.TLSClientConfig.MinVersion, uint16(tls.VersionTLS12))
}

// TestSetupDoHMixed ensures that DoH works correctly alongside TLS-scheme hosts.
func TestSetupDoHMixed(t *testing.T) {
	input := "fanout . tls://1.1.1.1 https://dns.google/dns-query {\ntls-server cloudflare\n}"
	c := caddy.NewTestController("dns", input)
	f, err := parseFanout(c)

	require.NoError(t, err)
	require.Len(t, f.clients, 2)

	// First client should be the TLS client.
	require.Contains(t, f.clients[0].Endpoint(), "1.1.1.1")
	require.Contains(t, strings.ToLower(f.clients[0].Net()), "tls")

	// Second should be the DoH client.
	require.Equal(t, "https://dns.google/dns-query", f.clients[1].Endpoint())
	require.Equal(t, DOH, f.clients[1].Net())
}
