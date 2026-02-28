package fanout

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

// ---------- 2. ServeDNS: Race mode, Domain mismatch, FormatError ----------

// TestServeDNS_RaceMode verifies race mode (enabled via the "race" directive). In this mode
// the plugin returns the first successful response without waiting for all servers.
// Sets up two slow servers (200 ms each) and asserts that exactly one answer is returned with RcodeSuccess.
func TestServeDNS_RaceMode(t *testing.T) {
	defer goleak.VerifyNone(t)
	var answered int32

	// Two slow servers – race mode should return the first successful response
	s1 := newServer(TCP, func(w dns.ResponseWriter, r *dns.Msg) {
		time.Sleep(200 * time.Millisecond)
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, test.A("example1. IN A 10.0.0.1"))
		atomic.AddInt32(&answered, 1)
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer s1.close()
	s2 := newServer(TCP, func(w dns.ResponseWriter, r *dns.Msg) {
		time.Sleep(200 * time.Millisecond)
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, test.A("example1. IN A 10.0.0.2"))
		atomic.AddInt32(&answered, 1)
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer s2.close()

	f := New()
	f.From = "."
	f.Race = true
	f.net = TCP
	f.AddClient(NewClient(s1.addr, TCP))
	f.AddClient(NewClient(s2.addr, TCP))

	req := new(dns.Msg)
	req.SetQuestion(testQuery, dns.TypeA)
	writer := &cachedDNSWriter{ResponseWriter: new(test.ResponseWriter)}
	_, err := f.ServeDNS(context.Background(), writer, req)
	require.NoError(t, err)
	require.Len(t, writer.answers, 1)
	require.Equal(t, dns.RcodeSuccess, writer.answers[0].Rcode)
}

// TestServeDNS_DomainMismatch_CallsNext verifies request routing: if the query name does not
// match the configured From zone, the plugin must delegate to the next plugin in the chain.
// Configures From="example.org.", sends a query for "other.com.", and verifies the next handler is invoked.
func TestServeDNS_DomainMismatch_CallsNext(t *testing.T) {
	defer goleak.VerifyNone(t)
	f := New()
	f.From = "example.org."
	f.Next = plugin.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, test.A("other.com. IN A 1.2.3.4"))
		logErrIfNotNil(w.WriteMsg(msg))
		return dns.RcodeSuccess, nil
	})

	req := new(dns.Msg)
	req.SetQuestion("other.com.", dns.TypeA)
	writer := &cachedDNSWriter{ResponseWriter: new(test.ResponseWriter)}
	rcode, err := f.ServeDNS(context.Background(), writer, req)
	require.NoError(t, err)
	require.Equal(t, dns.RcodeSuccess, rcode)
	require.Len(t, writer.answers, 1)
	require.Equal(t, "other.com.", writer.answers[0].Answer[0].Header().Name)
}

// TestServeDNS_ExcludeDomain_CallsNext verifies that when a queried domain matches the except
// exclusion list, the plugin skips fanout and calls the next handler in the chain.
// Adds "blocked.example.com." to ExcludeDomains, queries it, and asserts the next handler was called.
func TestServeDNS_ExcludeDomain_CallsNext(t *testing.T) {
	defer goleak.VerifyNone(t)
	nextCalled := false
	f := New()
	f.From = "."
	f.ExcludeDomains.AddString("blocked.example.com.")
	f.Next = plugin.HandlerFunc(func(_ context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		nextCalled = true
		msg := new(dns.Msg)
		msg.SetReply(r)
		logErrIfNotNil(w.WriteMsg(msg))
		return dns.RcodeSuccess, nil
	})

	req := new(dns.Msg)
	req.SetQuestion("blocked.example.com.", dns.TypeA)
	_, err := f.ServeDNS(context.Background(), &test.ResponseWriter{}, req)
	require.NoError(t, err)
	require.True(t, nextCalled, "Next handler should be called for excluded domain")
}

// TestServeDNS_FormatError_MismatchedId verifies that when an upstream returns a response whose
// question section does not match the original request, the plugin detects the mismatch via
// req.Match() and returns FORMERR to the client instead of forwarding the bogus response.
func TestServeDNS_FormatError_MismatchedId(t *testing.T) {
	defer goleak.VerifyNone(t)
	// Server responds with a different question name to trigger !req.Match()
	s := newServer(TCP, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		// Tamper the question to cause a mismatch
		msg.Question = []dns.Question{{Name: "wrong.example.", Qclass: dns.ClassINET, Qtype: dns.TypeA}}
		msg.Answer = append(msg.Answer, test.A("wrong.example. IN A 1.2.3.4"))
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer s.close()

	f := New()
	f.From = "."
	f.net = TCP
	f.AddClient(NewClient(s.addr, TCP))

	req := new(dns.Msg)
	req.SetQuestion(testQuery, dns.TypeA)
	writer := &cachedDNSWriter{ResponseWriter: new(test.ResponseWriter)}
	rcode, err := f.ServeDNS(context.Background(), writer, req)
	require.NoError(t, err)
	require.Equal(t, 0, rcode)
	require.Len(t, writer.answers, 1)
	require.Equal(t, dns.RcodeFormatError, writer.answers[0].Rcode, "should return FORMERR for mismatched response")
}

// ---------- 3. except-file error paths ----------

// TestExceptFile_NonexistentFile verifies that except-file pointing to a non-existent path
// produces a parse error containing "no such file" during Corefile parsing.
func TestExceptFile_NonexistentFile(t *testing.T) {
	source := `fanout . 127.0.0.1 {
	except-file /nonexistent/path/file.txt
}`
	c := caddy.NewTestController("dns", source)
	_, err := parseFanout(c)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no such file")
}

// TestExceptFile_PathTraversal verifies that except-file with a path traversal attempt
// (e.g. ../../../etc/passwd) is rejected during Corefile parsing.
func TestExceptFile_PathTraversal(t *testing.T) {
	source := `fanout . 127.0.0.1 {
	except-file ../../../etc/passwd
}`
	c := caddy.NewTestController("dns", source)
	_, err := parseFanout(c)
	require.Error(t, err)
	// Should either reject as path escape or fail to parse
}

// TestExceptFile_InvalidDomainInFile verifies that if except-file references a file containing
// an unparseable domain (e.g. "a:"), Corefile parsing fails with "unable to normalize".
func TestExceptFile_InvalidDomainInFile(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "except-invalid-*")
	require.NoError(t, err)
	// A domain containing ":" like "a:" triggers "unable to normalize" per parseIgnored tests
	_, err = file.WriteString("valid.example.com.\na:")
	require.NoError(t, err)
	require.NoError(t, file.Close())

	source := fmt.Sprintf(`fanout . 127.0.0.1 {
	except-file %v
}`, file.Name())
	c := caddy.NewTestController("dns", source)
	_, err = parseFanout(c)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to normalize")
}

// TestExceptFile_NoArgument verifies that except-file without a filename argument
// produces a parse error during Corefile parsing.
func TestExceptFile_NoArgument(t *testing.T) {
	source := `fanout . 127.0.0.1 {
	except-file
}`
	c := caddy.NewTestController("dns", source)
	_, err := parseFanout(c)
	require.Error(t, err)
}

// TestExceptFile_TooManyArguments verifies that except-file with more than one argument
// produces a parse error during Corefile parsing.
func TestExceptFile_TooManyArguments(t *testing.T) {
	source := `fanout . 127.0.0.1 {
	except-file file1.txt file2.txt
}`
	c := caddy.NewTestController("dns", source)
	_, err := parseFanout(c)
	require.Error(t, err)
}

// ---------- 4. Timeout / Cancellation ----------

// TestServeDNS_AllServersTimeout verifies that when all upstream servers are unresponsive and
// the configured timeout expires, ServeDNS returns RcodeServerFailure and an error.
// Uses a server that sleeps 10 s with a 500 ms plugin timeout.
func TestServeDNS_AllServersTimeout(t *testing.T) {
	defer goleak.VerifyNone(t)
	// Server never responds
	s := newServer(TCP, func(_ dns.ResponseWriter, _ *dns.Msg) {
		time.Sleep(10 * time.Second)
	})
	defer s.close()

	f := New()
	f.From = "."
	f.net = TCP
	f.Timeout = 500 * time.Millisecond
	f.Attempts = 1
	f.AddClient(NewClient(s.addr, TCP))

	req := new(dns.Msg)
	req.SetQuestion(testQuery, dns.TypeA)
	rcode, err := f.ServeDNS(context.Background(), &test.ResponseWriter{}, req)
	require.Equal(t, dns.RcodeServerFailure, rcode)
	// Either a timeout error or context deadline exceeded
	require.Error(t, err)
}

// TestServeDNS_ContextCancelledBeforeRequest verifies that when the caller's context is already
// cancelled before ServeDNS runs, the plugin returns RcodeServerFailure immediately without hanging.
func TestServeDNS_ContextCancelledBeforeRequest(t *testing.T) {
	defer goleak.VerifyNone(t)
	s := newServer(TCP, func(w dns.ResponseWriter, r *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(r)
		msg.Answer = append(msg.Answer, test.A("example1. IN A 10.0.0.1"))
		logErrIfNotNil(w.WriteMsg(msg))
	})
	defer s.close()

	f := New()
	f.From = "."
	f.net = TCP
	f.Timeout = 5 * time.Second
	f.AddClient(NewClient(s.addr, TCP))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	req := new(dns.Msg)
	req.SetQuestion(testQuery, dns.TypeA)
	rcode, _ := f.ServeDNS(ctx, &test.ResponseWriter{}, req)
	// With a pre-cancelled context, we expect server failure
	require.Equal(t, dns.RcodeServerFailure, rcode)
}

// TestProcessClient_AttemptLimitReached verifies the retry mechanism during request forwarding.
// If every attempt to a server fails (connection closed), the plugin retries up to Attempts times.
// With Attempts=2, asserts the error contains "attempt limit has been reached" and rcode is ServerFailure.
func TestProcessClient_AttemptLimitReached(t *testing.T) {
	defer goleak.VerifyNone(t)
	// Server that always closes connection (causes error on client)
	s := newServer(TCP, func(w dns.ResponseWriter, _ *dns.Msg) {
		conn, ok := w.(interface{ Close() error })
		if ok {
			_ = conn.Close()
		}
	})
	defer s.close()

	f := New()
	f.From = "."
	f.net = TCP
	f.Attempts = 2
	c := NewClient(s.addr, TCP)
	f.AddClient(c)

	req := new(dns.Msg)
	req.SetQuestion(testQuery, dns.TypeA)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	writer := &test.ResponseWriter{}
	rcode, err := f.ServeDNS(ctx, writer, req)
	require.Equal(t, dns.RcodeServerFailure, rcode)
	require.Error(t, err)
	require.Contains(t, err.Error(), "attempt limit has been reached")
}

// ---------- 6. TLS Integration ----------

// TestServeDNS_TLS is an end-to-end test of DNS-over-TLS forwarding.
// Creates a TLS DNS server with a self-signed certificate, configures a client with
// InsecureSkipVerify, sends a query, and verifies a successful response is returned.
func TestServeDNS_TLS(t *testing.T) {
	defer goleak.VerifyNone(t)

	// Generate self-signed cert for testing
	certFile, keyFile, cleanup := generateSelfSignedCert(t)
	defer cleanup()

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	require.NoError(t, err)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Create TLS DNS server
	s := &dns.Server{
		Net:       "tcp-tls",
		TLSConfig: tlsConfig,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			msg := new(dns.Msg)
			msg.SetReply(r)
			msg.Answer = append(msg.Answer, test.A("example1. IN A 10.0.0.1"))
			logErrIfNotNil(w.WriteMsg(msg))
		}),
	}

	// Find a free port
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	require.NoError(t, err)
	s.Listener = ln

	ch := make(chan struct{})
	s.NotifyStartedFunc = func() { close(ch) }
	go func() { _ = s.ActivateAndServe() }()
	<-ch
	defer func() { _ = s.Shutdown() }()

	// Client with TLS
	clientTLSConfig := &tls.Config{
		//nolint:gosec // test-only self-signed cert in local integration test
		InsecureSkipVerify: true,
	}
	c := NewClient(ln.Addr().String(), TCPTLS)
	c.SetTLSConfig(clientTLSConfig)

	f := New()
	f.From = "."
	f.net = TCPTLS
	f.clients = append(f.clients, c)
	f.WorkerCount = 1
	f.serverCount = 1

	req := new(dns.Msg)
	req.SetQuestion(testQuery, dns.TypeA)
	writer := &cachedDNSWriter{ResponseWriter: new(test.ResponseWriter)}
	_, err = f.ServeDNS(context.Background(), writer, req)
	require.NoError(t, err)
	require.Len(t, writer.answers, 1)
	require.Equal(t, dns.RcodeSuccess, writer.answers[0].Rcode)
}

// TestSetup_TLSConfig verifies that during Corefile parsing, "tls <cert> <key>" populates
// f.tlsConfig so that clients use TLS for upstream connections.
func TestSetup_TLSConfig(t *testing.T) {
	certFile, keyFile, cleanup := generateSelfSignedCert(t)
	defer cleanup()

	source := fmt.Sprintf(`fanout . 127.0.0.1 {
	tls %s %s
}`, certFile, keyFile)
	c := caddy.NewTestController("dns", source)
	f, err := parseFanout(c)
	require.NoError(t, err)
	require.NotNil(t, f.tlsConfig)
}

// TestSetup_TLSServer verifies that during Corefile parsing, "tls-server <name>" sets
// f.tlsServerName for SNI on upstream TLS connections.
func TestSetup_TLSServer(t *testing.T) {
	source := `fanout . 127.0.0.1 {
	tls-server myserver.example.com
}`
	c := caddy.NewTestController("dns", source)
	f, err := parseFanout(c)
	require.NoError(t, err)
	require.Equal(t, "myserver.example.com", f.tlsServerName)
}

// TestSetup_Race verifies that during Corefile parsing, the "race" directive sets f.Race = true.
func TestSetup_Race(t *testing.T) {
	source := `fanout . 127.0.0.1 127.0.0.2 {
	race
}`
	c := caddy.NewTestController("dns", source)
	f, err := parseFanout(c)
	require.NoError(t, err)
	require.True(t, f.Race)
}

// TestClient_SetTLSConfig verifies that calling SetTLSConfig on a client switches its network
// type from the original (e.g. "udp") to "tcp-tls".
func TestClient_SetTLSConfig(t *testing.T) {
	c := NewClient("127.0.0.1:53", "udp")
	require.Equal(t, "udp", c.Net())

	tlsCfg := &tls.Config{}
	c.SetTLSConfig(tlsCfg)
	require.Equal(t, TCPTLS, c.Net(), "SetTLSConfig should switch network to tcp-tls")
}

// TestClient_NetAndEndpoint verifies that Net() and Endpoint() on a newly created client
// return the network and address passed to NewClient.
func TestClient_NetAndEndpoint(t *testing.T) {
	c := NewClient("10.0.0.1:5353", "tcp")
	require.Equal(t, "tcp", c.Net())
	require.Equal(t, "10.0.0.1:5353", c.Endpoint())
}

// TestFanout_Name verifies that Fanout.Name() returns "fanout", which CoreDNS uses
// for plugin identification and logging.
func TestFanout_Name(t *testing.T) {
	f := New()
	require.Equal(t, "fanout", f.Name())
}

// ---------- helpers ----------

func generateSelfSignedCert(t *testing.T) (certFile, keyFile string, cleanup func()) {
	t.Helper()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	// Generate a self-signed certificate using crypto
	key, err := generateRSAKey()
	require.NoError(t, err)

	certDER, err := generateSelfSignedCertDER(key)
	require.NoError(t, err)

	// Write cert PEM
	certPEM := pemEncode(certDER, "CERTIFICATE")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))

	// Write key PEM
	keyPEM := pemEncode(x509.MarshalPKCS1PrivateKey(key), "RSA PRIVATE KEY")
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	return certPath, keyPath, func() {}
}
