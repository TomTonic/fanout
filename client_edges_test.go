package fanout

import (
	"context"
	"net"
	"testing"

	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

func TestClient_Request_Edges(t *testing.T) {
	// Need a dummy server to avoid instant connection refused
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	c := NewClient(pc.LocalAddr().String(), "udp")

	// 1. udpSize < 512
	req1 := new(dns.Msg)
	req1.SetQuestion("example.com.", dns.TypeA)
	state1 := request.Request{W: &testResponseWriter{}, Req: req1}

	ctx, cancel := context.WithCancel(context.Background())
	c.Request(ctx, &state1)
	cancel()
}

type testResponseWriter struct {
	dns.ResponseWriter
}

func (t *testResponseWriter) LocalAddr() net.Addr { return nil }
func (t *testResponseWriter) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
}
func (t *testResponseWriter) WriteMsg(m *dns.Msg) error   { return nil }
func (t *testResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (t *testResponseWriter) Close() error                { return nil }
func (t *testResponseWriter) TsigStatus() error           { return nil }
func (t *testResponseWriter) TsigTimersOnly(b bool)       {}
func (t *testResponseWriter) Hijack()                     {}
