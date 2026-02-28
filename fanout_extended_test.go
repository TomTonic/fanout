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

func TestExceptFile_NonexistentFile(t *testing.T) {
	source := `fanout . 127.0.0.1 {
	except-file /nonexistent/path/file.txt
}`
	c := caddy.NewTestController("dns", source)
	_, err := parseFanout(c)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no such file")
}

func TestExceptFile_PathTraversal(t *testing.T) {
	source := `fanout . 127.0.0.1 {
	except-file ../../../etc/passwd
}`
	c := caddy.NewTestController("dns", source)
	_, err := parseFanout(c)
	require.Error(t, err)
	// Should either reject as path escape or fail to parse
}

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

func TestExceptFile_NoArgument(t *testing.T) {
	source := `fanout . 127.0.0.1 {
	except-file
}`
	c := caddy.NewTestController("dns", source)
	_, err := parseFanout(c)
	require.Error(t, err)
}

func TestExceptFile_TooManyArguments(t *testing.T) {
	source := `fanout . 127.0.0.1 {
	except-file file1.txt file2.txt
}`
	c := caddy.NewTestController("dns", source)
	_, err := parseFanout(c)
	require.Error(t, err)
}

// ---------- 4. Timeout / Cancellation ----------

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

func TestSetup_TLSServer(t *testing.T) {
	source := `fanout . 127.0.0.1 {
	tls-server myserver.example.com
}`
	c := caddy.NewTestController("dns", source)
	f, err := parseFanout(c)
	require.NoError(t, err)
	require.Equal(t, "myserver.example.com", f.tlsServerName)
}

func TestSetup_Race(t *testing.T) {
	source := `fanout . 127.0.0.1 127.0.0.2 {
	race
}`
	c := caddy.NewTestController("dns", source)
	f, err := parseFanout(c)
	require.NoError(t, err)
	require.True(t, f.Race)
}

func TestClient_SetTLSConfig(t *testing.T) {
	c := NewClient("127.0.0.1:53", "udp")
	require.Equal(t, "udp", c.Net())

	tlsCfg := &tls.Config{InsecureSkipVerify: true}
	c.SetTLSConfig(tlsCfg)
	require.Equal(t, TCPTLS, c.Net(), "SetTLSConfig should switch network to tcp-tls")
}

func TestClient_NetAndEndpoint(t *testing.T) {
	c := NewClient("10.0.0.1:5353", "tcp")
	require.Equal(t, "tcp", c.Net())
	require.Equal(t, "10.0.0.1:5353", c.Endpoint())
}

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
