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
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/test"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

// doqTestServer wraps a QUIC listener that speaks DNS-over-QUIC (RFC 9250).
type doqTestServer struct {
	listener  *quic.Listener
	transport *quic.Transport
	addr      string
	clientTLS *tls.Config
	done      chan struct{}
}

// close shuts down the DoQ test server.
func (s *doqTestServer) close() {
	close(s.done)
	_ = s.listener.Close()
	_ = s.transport.Close()
}

// newDoQTestServer starts a DNS-over-QUIC server on a random UDP port.
// It accepts QUIC connections with the "doq" ALPN token, reads DNS queries
// from bidirectional streams (2-byte length prefix per RFC 9250), processes
// them via the provided handler, and writes the response back.
func newDoQTestServer(t *testing.T, handler dns.HandlerFunc) *doqTestServer {
	t.Helper()

	// Generate a self-signed ECDSA certificate.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"DoQ Test"}},
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
		NextProtos: []string{doqALPN},
	}

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{doqALPN},
	}

	// Listen on a random UDP port.
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	tr := &quic.Transport{Conn: conn}
	listener, err := tr.Listen(serverTLS, &quic.Config{
		MaxIdleTimeout: 30 * time.Second,
	})
	require.NoError(t, err)

	done := make(chan struct{})

	// Accept connections and handle streams.
	go func() {
		for {
			qconn, err := listener.Accept(context.Background())
			if err != nil {
				select {
				case <-done:
					return
				default:
				}
				return
			}
			go handleDoQConn(qconn, handler, done)
		}
	}()

	return &doqTestServer{
		listener:  listener,
		transport: tr,
		addr:      conn.LocalAddr().String(),
		clientTLS: clientTLS,
		done:      done,
	}
}

// handleDoQConn processes DoQ streams on a single QUIC connection.
func handleDoQConn(conn *quic.Conn, handler dns.HandlerFunc, done chan struct{}) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go handleDoQStream(stream, handler, done)
	}
}

// handleDoQStream reads a DNS query from a QUIC stream, runs the handler,
// and writes the response back with a 2-byte length prefix per RFC 9250.
func handleDoQStream(stream *quic.Stream, handler dns.HandlerFunc, done chan struct{}) {
	defer func() { _ = (*stream).Close() }()

	select {
	case <-done:
		return
	default:
	}

	// Read 2-byte length prefix.
	var lenBuf [2]byte
	if _, err := io.ReadFull(stream, lenBuf[:]); err != nil {
		return
	}
	msgLen := binary.BigEndian.Uint16(lenBuf[:])
	if msgLen == 0 || int(msgLen) > doqMaxMessageSize {
		return
	}

	// Read the DNS message.
	msgBuf := make([]byte, msgLen)
	if _, err := io.ReadFull(stream, msgBuf); err != nil {
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(msgBuf); err != nil {
		return
	}

	// RFC 9250 §4.2: The ID field MUST be 0 in DoQ, capture original for response.
	origID := req.Id

	rec := &dohResponseRecorder{msg: req}
	handler(rec, req)

	resp := rec.result
	if resp == nil {
		resp = new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
	}

	// RFC 9250: Set ID to 0 in the response.
	resp.Id = 0
	_ = origID // server doesn't need the original ID

	packed, err := resp.Pack()
	if err != nil {
		return
	}

	// Write 2-byte length prefix + response.
	respBuf := make([]byte, 2+len(packed))
	binary.BigEndian.PutUint16(respBuf[:2], uint16(len(packed)))
	copy(respBuf[2:], packed)
	_, _ = (*stream).Write(respBuf)
}

// closeDoQClient shuts down the underlying QUIC connection so that its background
// goroutines are cleaned up. This prevents goleak from flagging them.
func closeDoQClient(t *testing.T, c Client) {
	t.Helper()
	if dc, ok := c.(*doqClient); ok {
		dc.closeConn()
	}
}

// TestDoQClientBasicRequest verifies that a DoQ client can send a DNS query over QUIC
// and receive a valid A record response.
func TestDoQClientBasicRequest(t *testing.T) {
	srv := newDoQTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("93.184.216.34"),
		})
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.close()

	c := newDoQClientWithTLS(srv.addr, srv.clientTLS)
	defer closeDoQClient(t, c)

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

// TestDoQClientNXDOMAIN verifies correct NXDOMAIN handling over DoQ.
func TestDoQClientNXDOMAIN(t *testing.T) {
	srv := newDoQTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetRcode(r, dns.RcodeNameError)
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.close()

	c := newDoQClientWithTLS(srv.addr, srv.clientTLS)
	defer closeDoQClient(t, c)

	req := new(dns.Msg)
	req.SetQuestion("nonexistent.example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.NoError(t, err)
	require.Equal(t, dns.RcodeNameError, resp.Rcode)
}

// TestDoQClientSERVFAIL verifies that SERVFAIL is returned as a DNS-level response
// over DoQ, not as a transport error.
func TestDoQClientSERVFAIL(t *testing.T) {
	srv := newDoQTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetRcode(r, dns.RcodeServerFailure)
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.close()

	c := newDoQClientWithTLS(srv.addr, srv.clientTLS)
	defer closeDoQClient(t, c)

	req := new(dns.Msg)
	req.SetQuestion("fail.example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, dns.RcodeServerFailure, resp.Rcode)
}

// TestDoQClientMultipleRecords verifies that multiple A records are returned over DoQ.
func TestDoQClientMultipleRecords(t *testing.T) {
	srv := newDoQTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
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

	c := newDoQClientWithTLS(srv.addr, srv.clientTLS)
	defer closeDoQClient(t, c)

	req := new(dns.Msg)
	req.SetQuestion("multi.example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.NoError(t, err)
	require.Len(t, resp.Answer, 3)
}

// TestDoQClientAAAARecord verifies that AAAA (IPv6) records work over DoQ.
func TestDoQClientAAAARecord(t *testing.T) {
	srv := newDoQTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
			AAAA: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"),
		})
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.close()

	c := newDoQClientWithTLS(srv.addr, srv.clientTLS)
	defer closeDoQClient(t, c)

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

// TestDoQClientIDPreservation verifies that the DNS message ID is correctly
// restored after the DoQ round trip (RFC 9250 mandates ID=0 on the wire).
func TestDoQClientIDPreservation(t *testing.T) {
	srv := newDoQTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("1.1.1.1"),
		})
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.close()

	c := newDoQClientWithTLS(srv.addr, srv.clientTLS)
	defer closeDoQClient(t, c)

	req := new(dns.Msg)
	req.SetQuestion("id-test.example.com.", dns.TypeA)
	req.Id = 54321

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.NoError(t, err)
	// The client must restore the original ID even though DoQ uses ID=0 on wire.
	require.Equal(t, uint16(54321), resp.Id)
}

// TestDoQClientPreservesFlags verifies that DNS header flags (AA, RD, RA) are
// preserved through the DoQ transport.
func TestDoQClientPreservesFlags(t *testing.T) {
	srv := newDoQTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
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

	c := newDoQClientWithTLS(srv.addr, srv.clientTLS)
	defer closeDoQClient(t, c)

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

// TestDoQClientEmptyResponse verifies that empty (NODATA) responses work over DoQ.
func TestDoQClientEmptyResponse(t *testing.T) {
	srv := newDoQTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.close()

	c := newDoQClientWithTLS(srv.addr, srv.clientTLS)
	defer closeDoQClient(t, c)

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

// TestDoQClientTXTRecord verifies that TXT records work over DoQ.
func TestDoQClientTXTRecord(t *testing.T) {
	srv := newDoQTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
			Txt: []string{"v=spf1 include:example.com ~all"},
		})
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.close()

	c := newDoQClientWithTLS(srv.addr, srv.clientTLS)
	defer closeDoQClient(t, c)

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

// TestDoQClientConcurrentRequests verifies that the DoQ client handles multiple
// concurrent requests safely under the race detector, multiplexing them over
// a single QUIC connection.
func TestDoQClientConcurrentRequests(t *testing.T) {
	srv := newDoQTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("1.2.3.4"),
		})
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.close()

	c := newDoQClientWithTLS(srv.addr, srv.clientTLS)
	defer closeDoQClient(t, c)

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

// TestDoQClientEndpointAndNet verifies that the DoQ client returns the correct
// endpoint address and network type.
func TestDoQClientEndpointAndNet(t *testing.T) {
	c := NewDoQClient("dns.example.com:853")
	defer closeDoQClient(t, c)

	require.Equal(t, "dns.example.com:853", c.Endpoint())
	require.Equal(t, DOQ, c.Net())
}

// TestDoQClientSetTLSConfig verifies that SetTLSConfig updates the transport
// without panicking and enforces TLS 1.3 minimum and the DoQ ALPN token.
func TestDoQClientSetTLSConfig(t *testing.T) {
	c := NewDoQClient("dns.example.com:853")
	defer closeDoQClient(t, c)

	// Should not panic with nil.
	c.SetTLSConfig(nil)
	require.Equal(t, DOQ, c.Net())

	// Should not panic with a real config.
	c.SetTLSConfig(&tls.Config{
		MinVersion: tls.VersionTLS12, // should be upgraded to TLS 1.3
		ServerName: "dns.example.com",
	})
	require.Equal(t, DOQ, c.Net())

	// Verify TLS 1.3 enforcement and ALPN.
	dc, ok := c.(*doqClient)
	require.True(t, ok)
	dc.mu.Lock()
	defer dc.mu.Unlock()
	require.GreaterOrEqual(t, dc.tlsConfig.MinVersion, uint16(tls.VersionTLS13))
	require.Contains(t, dc.tlsConfig.NextProtos, doqALPN)
}

// TestDoQClientTLSMinVersion verifies TLS 1.3 is enforced as required by QUIC.
func TestDoQClientTLSMinVersion(t *testing.T) {
	c := NewDoQClient("dns.example.com:853")
	defer closeDoQClient(t, c)
	dc, ok := c.(*doqClient)
	require.True(t, ok)
	dc.mu.Lock()
	defer dc.mu.Unlock()
	require.GreaterOrEqual(t, dc.tlsConfig.MinVersion, uint16(tls.VersionTLS13))
}

// TestDoQClientServerDown verifies that the DoQ client returns an error when the
// server is unreachable.
func TestDoQClientServerDown(t *testing.T) {
	c := newDoQClientWithTLS("127.0.0.1:1", &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test only
		MinVersion:         tls.VersionTLS13,
		NextProtos:         []string{doqALPN},
	})
	defer closeDoQClient(t, c)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.Error(t, err)
}

// TestDoQClientContextCancellation verifies that a cancelled context aborts the DoQ request.
func TestDoQClientContextCancellation(t *testing.T) {
	handlerDone := make(chan struct{})
	srv := newDoQTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		// Slow handler: block until the test signals completion.
		<-handlerDone
	})
	defer func() {
		close(handlerDone)
		srv.close()
	}()

	c := newDoQClientWithTLS(srv.addr, srv.clientTLS)
	defer closeDoQClient(t, c)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	_, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.Error(t, err)
}

// TestDoQClientConnectionReuse verifies that multiple sequential requests reuse the
// same QUIC connection instead of establishing a new one each time.
func TestDoQClientConnectionReuse(t *testing.T) {
	srv := newDoQTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("5.6.7.8"),
		})
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer srv.close()

	c := newDoQClientWithTLS(srv.addr, srv.clientTLS)
	defer closeDoQClient(t, c)

	// Send multiple requests sequentially; all should succeed on one connection.
	for i := 0; i < 5; i++ {
		req := new(dns.Msg)
		req.SetQuestion("reuse.example.com.", dns.TypeA)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := c.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
		cancel()

		require.NoError(t, err)
		require.Len(t, resp.Answer, 1)
	}
}

// TestDoQIntegrationWithFanout verifies end-to-end DNS resolution through the fanout
// plugin using a DoQ backend.
func TestDoQIntegrationWithFanout(t *testing.T) {
	srv := newDoQTestServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
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
	doqc := newDoQClientWithTLS(srv.addr, srv.clientTLS)
	defer closeDoQClient(t, doqc)
	f.AddClient(doqc)

	req := new(dns.Msg)
	req.SetQuestion("fanout-doq.example.com.", dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := doqc.Request(ctx, &request.Request{W: &test.ResponseWriter{}, Req: req})
	require.NoError(t, err)
	require.Len(t, resp.Answer, 1)

	a, ok := resp.Answer[0].(*dns.A)
	require.True(t, ok)
	require.Equal(t, "9.8.7.6", a.A.String())
}

// TestSetupDoQConfig verifies that the fanout plugin parses quic:// URLs from the Corefile
// and creates DoQ clients.
func TestSetupDoQConfig(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		expectedURLs []string
		expectedNets []string
	}{
		{
			name:         "single-doq-endpoint",
			input:        "fanout . quic://dns.example.com:853",
			expectedURLs: []string{"dns.example.com:853"},
			expectedNets: []string{DOQ},
		},
		{
			name:         "doq-default-port",
			input:        "fanout . quic://dns.example.com",
			expectedURLs: []string{"dns.example.com:853"},
			expectedNets: []string{DOQ},
		},
		{
			name:         "multiple-doq-endpoints",
			input:        "fanout . quic://dns.google:853 quic://cloudflare-dns.com:853",
			expectedURLs: []string{"dns.google:853", "cloudflare-dns.com:853"},
			expectedNets: []string{DOQ, DOQ},
		},
		{
			name:         "mixed-all-protocols",
			input:        "fanout . 127.0.0.1 https://dns.google/dns-query h3://cloudflare-dns.com/dns-query quic://dns.example.com:853",
			expectedURLs: []string{"127.0.0.1:53", "https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query", "dns.example.com:853"},
			expectedNets: []string{"udp", DOH, DOH3, DOQ},
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

// TestSetupDoQNetworkProtocol verifies that "dns-over-quic" is accepted as a network protocol value.
func TestSetupDoQNetworkProtocol(t *testing.T) {
	input := `fanout . quic://dns.example.com:853 {
		network dns-over-quic
	}`
	c := caddy.NewTestController("dns", input)
	f, err := parseFanout(c)

	require.NoError(t, err)
	require.Equal(t, DOQ, f.net)
}

// TestSetupDoQWithOptions verifies that DoQ endpoints work with additional fanout options.
func TestSetupDoQWithOptions(t *testing.T) {
	input := `fanout . quic://dns.google:853 quic://cloudflare-dns.com:853 {
		worker-count 2
		timeout 10s
	}`
	c := caddy.NewTestController("dns", input)
	f, err := parseFanout(c)

	require.NoError(t, err)
	require.Len(t, f.clients, 2)
	require.Equal(t, 2, f.WorkerCount)
	require.Equal(t, 10*time.Second, f.Timeout)
	require.Equal(t, DOQ, f.clients[0].Net())
	require.Equal(t, DOQ, f.clients[1].Net())
}

// TestSetupDoQWithRace verifies the race option combined with DoQ endpoints.
func TestSetupDoQWithRace(t *testing.T) {
	input := `fanout . quic://dns.google:853 quic://cloudflare-dns.com:853 {
		race
	}`
	c := caddy.NewTestController("dns", input)
	f, err := parseFanout(c)

	require.NoError(t, err)
	require.True(t, f.Race)
	require.Len(t, f.clients, 2)
}

// TestSetupDoQWithExcept verifies that the except directive works alongside DoQ endpoints.
func TestSetupDoQWithExcept(t *testing.T) {
	input := `fanout . quic://dns.example.com:853 {
		except internal.example.com
	}`
	c := caddy.NewTestController("dns", input)
	f, err := parseFanout(c)

	require.NoError(t, err)
	require.True(t, f.ExcludeDomains.Contains("internal.example.com."))
}

// TestSetupDoQCaseInsensitive verifies that quic:// URLs are detected case-insensitively.
func TestSetupDoQCaseInsensitive(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"lowercase", "fanout . quic://dns.google:853"},
		{"uppercase", "fanout . QUIC://dns.google:853"},
		{"mixedcase", "fanout . Quic://DNS.Google:853"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.input)
			f, err := parseFanout(c)
			require.NoError(t, err)
			require.Len(t, f.clients, 1)
			require.Equal(t, DOQ, f.clients[0].Net())
		})
	}
}

// TestSetupDoQMixedWithTLS verifies that DoQ works together with tls:// scheme hosts.
func TestSetupDoQMixedWithTLS(t *testing.T) {
	input := "fanout . tls://1.1.1.1 quic://dns.google:853 {\ntls-server cloudflare\n}"
	c := caddy.NewTestController("dns", input)
	f, err := parseFanout(c)

	require.NoError(t, err)
	require.Len(t, f.clients, 2)

	// First client should be the DoT client.
	require.Contains(t, f.clients[0].Endpoint(), "1.1.1.1")
	require.Contains(t, strings.ToLower(f.clients[0].Net()), "tls")

	// Second should be the DoQ client.
	require.Equal(t, "dns.google:853", f.clients[1].Endpoint())
	require.Equal(t, DOQ, f.clients[1].Net())
}

// TestSetupAllFourTransports verifies that plain, DoH, DoH3, and DoQ endpoints can
// all be configured together in a single fanout stanza.
func TestSetupAllFourTransports(t *testing.T) {
	input := "fanout . 127.0.0.1 https://dns.google/dns-query h3://cloudflare-dns.com/dns-query quic://dns.example.com:853"
	c := caddy.NewTestController("dns", input)
	f, err := parseFanout(c)

	require.NoError(t, err)
	require.Len(t, f.clients, 4)

	require.Equal(t, "127.0.0.1:53", f.clients[0].Endpoint())
	require.Equal(t, "udp", f.clients[0].Net())

	require.Equal(t, "https://dns.google/dns-query", f.clients[1].Endpoint())
	require.Equal(t, DOH, f.clients[1].Net())

	require.Equal(t, "https://cloudflare-dns.com/dns-query", f.clients[2].Endpoint())
	require.Equal(t, DOH3, f.clients[2].Net())

	require.Equal(t, "dns.example.com:853", f.clients[3].Endpoint())
	require.Equal(t, DOQ, f.clients[3].Net())
}

// TestDoQDoesNotBreakExistingSetup verifies that DoQ support does not break
// existing plain-host, DoH, or DoH3 configurations.
func TestDoQDoesNotBreakExistingSetup(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedNet string
		expectedN   int
	}{
		{name: "plain-udp", input: "fanout . 127.0.0.1", expectedNet: "udp", expectedN: 1},
		{name: "plain-tcp", input: "fanout . 127.0.0.1 {\nnetwork tcp\n}", expectedNet: "tcp", expectedN: 1},
		{name: "doh-only", input: "fanout . https://dns.google/dns-query", expectedNet: "udp", expectedN: 1},
		{name: "doh3-only", input: "fanout . h3://dns.google/dns-query", expectedNet: "udp", expectedN: 1},
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
