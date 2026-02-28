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
	tr := &transportImpl{addr: pc.LocalAddr().String()}

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
