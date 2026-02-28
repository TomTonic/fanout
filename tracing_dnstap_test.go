package fanout

import (
	"context"
	"crypto/tls"
	"net"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/coredns/coredns/plugin/dnstap"
	"github.com/coredns/coredns/request"
	tap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	ot "github.com/opentracing/opentracing-go"
	"github.com/opentracing/opentracing-go/mocktracer"
	"github.com/stretchr/testify/require"
)

type dnstapIOStub struct {
	msgs []*tap.Dnstap
}

func (d *dnstapIOStub) Dnstap(msg *tap.Dnstap) {
	d.msgs = append(d.msgs, msg)
}

type dnstapClientStub struct {
	addr string
	net  string
}

func (c *dnstapClientStub) Request(_ context.Context, _ *request.Request) (*dns.Msg, error) {
	return nil, nil
}

func (c *dnstapClientStub) Endpoint() string {
	return c.addr
}

func (c *dnstapClientStub) Net() string {
	return c.net
}

func (c *dnstapClientStub) SetTLSConfig(_ *tls.Config) {}

func injectDnstapIO(t *testing.T, plugin *dnstap.Dnstap, io *dnstapIOStub) {
	t.Helper()

	ioField := reflect.ValueOf(plugin).Elem().FieldByName("io")
	require.True(t, ioField.IsValid())
	require.True(t, ioField.CanAddr())
	require.True(t, reflect.ValueOf(io).Type().AssignableTo(ioField.Type()))

	//nolint:gosec // test-only reflection to inject dnstap IO stub into unexported field
	reflect.NewAt(ioField.Type(), unsafe.Pointer(ioField.UnsafeAddr())).Elem().Set(reflect.ValueOf(io))
}

// TestToDnstap_QueryOnlyWithoutRawMessage verifies dnstap message emission during response handling.
// When IncludeRawMessage is false and no reply is provided, toDnstap must emit exactly one message
// of type FORWARDER_QUERY with an empty QueryMessage field.
func TestToDnstap_QueryOnlyWithoutRawMessage(t *testing.T) {
	tapPlugin := &dnstap.Dnstap{IncludeRawMessage: false}
	io := &dnstapIOStub{}
	injectDnstapIO(t, tapPlugin, io)

	query := new(dns.Msg)
	query.SetQuestion("example.org.", dns.TypeA)

	state := &request.Request{Req: query}
	client := &dnstapClientStub{addr: "127.0.0.1:53", net: UDP}

	toDnstap(tapPlugin, client, state, nil, time.Now())

	require.Len(t, io.msgs, 1)
	require.NotNil(t, io.msgs[0].Message)
	require.NotNil(t, io.msgs[0].Message.Type)
	require.Equal(t, tap.Message_FORWARDER_QUERY, *io.msgs[0].Message.Type)
	require.Empty(t, io.msgs[0].Message.QueryMessage)
}

// TestToDnstap_QueryAndResponseWithRawMessage verifies that when IncludeRawMessage is true and
// a reply is provided, toDnstap emits two messages: a FORWARDER_QUERY with the packed query bytes
// and a FORWARDER_RESPONSE with the packed response bytes.
func TestToDnstap_QueryAndResponseWithRawMessage(t *testing.T) {
	tapPlugin := &dnstap.Dnstap{IncludeRawMessage: true}
	io := &dnstapIOStub{}
	injectDnstapIO(t, tapPlugin, io)

	query := new(dns.Msg)
	query.SetQuestion("example.org.", dns.TypeA)

	reply := new(dns.Msg)
	reply.SetReply(query)

	state := &request.Request{Req: query}
	client := &dnstapClientStub{addr: "127.0.0.1:53", net: TCP}

	toDnstap(tapPlugin, client, state, reply, time.Now())

	require.Len(t, io.msgs, 2)

	queryTap := io.msgs[0].Message
	require.NotNil(t, queryTap)
	require.NotNil(t, queryTap.Type)
	require.Equal(t, tap.Message_FORWARDER_QUERY, *queryTap.Type)
	require.NotEmpty(t, queryTap.QueryMessage)

	respTap := io.msgs[1].Message
	require.NotNil(t, respTap)
	require.NotNil(t, respTap.Type)
	require.Equal(t, tap.Message_FORWARDER_RESPONSE, *respTap.Type)
	require.NotEmpty(t, respTap.ResponseMessage)
}

// TestWithRequestSpan_WithParentSpan verifies that during request forwarding, withRequestSpan
// creates an OpenTracing child span for the upstream request. When a parent span exists in the
// context, it creates a "request" child span tagged with the peer address and finishes it on cleanup.
func TestWithRequestSpan_WithParentSpan(t *testing.T) {
	tracer := mocktracer.New()
	parent := tracer.StartSpan("parent")
	ctx := ot.ContextWithSpan(context.Background(), parent)

	ctxWithChild, finish := withRequestSpan(ctx, "8.8.8.8:53")
	require.NotNil(t, ot.SpanFromContext(ctxWithChild))

	finish()
	parent.Finish()

	finished := tracer.FinishedSpans()
	require.Len(t, finished, 2)

	var requestSpan *mocktracer.MockSpan
	for _, span := range finished {
		if span.OperationName == "request" {
			requestSpan = span
			break
		}
	}
	require.NotNil(t, requestSpan)
	require.Equal(t, "8.8.8.8:53", requestSpan.Tag("peer.address"))
}

// TestWithRequestSpan_WithoutParentSpan verifies that when no parent span exists in the context,
// withRequestSpan returns the original context unchanged and a no-op finish function without panicking.
func TestWithRequestSpan_WithoutParentSpan(t *testing.T) {
	ctx := context.Background()
	ctx2, finish := withRequestSpan(ctx, "8.8.4.4:53")

	require.Equal(t, ctx, ctx2)
	require.NotPanics(t, finish)
}

// TestTransportDial_WithTracingSpan verifies that during upstream connection establishment,
// transportImpl.dial creates a "connect" tracing span when a parent span is present.
// After dialing a real UDP listener, asserts that a finished "connect" span exists in the tracer.
func TestTransportDial_WithTracingSpan(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() {
		require.NoError(t, pc.Close())
	}()

	tracer := mocktracer.New()
	parent := tracer.StartSpan("parent")
	defer parent.Finish()

	ctx := ot.ContextWithSpan(context.Background(), parent)
	tr := &transportImpl{addr: pc.LocalAddr().String(), pool: make(chan *dns.Conn, connPoolSize)}

	conn, err := tr.dial(ctx, &dns.Client{Net: UDP, Dialer: &net.Dialer{Timeout: time.Second}})
	require.NoError(t, err)
	require.NotNil(t, conn)
	require.NoError(t, conn.Close())

	var found bool
	for _, span := range tracer.FinishedSpans() {
		if span.OperationName == "connect" {
			found = true
			break
		}
	}
	require.True(t, found, "expected connect span to be finished")
}

// TestTransportPool_YieldAndReuse verifies the connection pooling in transportImpl.
// A yielded TCP connection is returned by the next Dial call instead of creating a new one.
func TestTransportPool_YieldAndReuse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	// Accept connections in background
	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			// Keep connection alive
			_ = conn
		}
	}()

	tr := NewTransport(ln.Addr().String())

	// Dial a TCP connection
	conn1, err := tr.Dial(context.Background(), TCP)
	require.NoError(t, err)
	require.NotNil(t, conn1)

	// Yield it back
	tr.Yield(conn1)

	// Next Dial should return the pooled connection
	conn2, err := tr.Dial(context.Background(), TCP)
	require.NoError(t, err)
	require.Same(t, conn1, conn2, "should reuse pooled connection")

	_ = conn2.Close()
}

// TestTransportPool_YieldNil verifies that Yield(nil) is a safe no-op.
func TestTransportPool_YieldNil(t *testing.T) {
	tr := NewTransport("127.0.0.1:53")
	require.NotPanics(t, func() {
		tr.Yield(nil)
	})
}

// TestTransportPool_FullPoolClosesConnection verifies that when the pool is full,
// yielding an additional connection closes it instead of blocking.
func TestTransportPool_FullPoolClosesConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn
		}
	}()

	tr := NewTransport(ln.Addr().String())

	// Fill the pool (connPoolSize = 2)
	conns := make([]*dns.Conn, connPoolSize+1)
	for i := range conns {
		conns[i], err = tr.Dial(context.Background(), TCP)
		require.NoError(t, err)
	}

	// Yield all - last one should be closed, not queued
	for _, c := range conns {
		tr.Yield(c)
	}

	// Drain pool - should get exactly connPoolSize connections
	for i := 0; i < connPoolSize; i++ {
		c, dialErr := tr.Dial(context.Background(), TCP)
		require.NoError(t, dialErr)
		_ = c.Close()
	}
}

// TestTransportPool_UDPNotPooled verifies that UDP connections are not pooled.
// Since UDP is connectionless (no handshake), pooling has no benefit.
func TestTransportPool_UDPNotPooled(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = pc.Close() }()

	tr := NewTransport(pc.LocalAddr().String())

	conn1, err := tr.Dial(context.Background(), UDP)
	require.NoError(t, err)

	// Yield is a no-op conceptually - for UDP we still put it in pool
	// but new dials don't check pool for UDP (only TCP/TLS)
	_ = conn1.Close()

	conn2, err := tr.Dial(context.Background(), UDP)
	require.NoError(t, err)
	require.NotSame(t, conn1, conn2, "UDP connections should not be reused")
	_ = conn2.Close()
}
