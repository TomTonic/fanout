package fanout

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	coreplugin "github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/dnstap"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func controllerInstance(t *testing.T, c *caddy.Controller) *caddy.Instance {
	t.Helper()

	v := reflect.ValueOf(c).Elem().FieldByName("instance")
	require.True(t, v.IsValid())
	require.True(t, v.CanAddr())

	inst := reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem().Interface().(*caddy.Instance)
	require.NotNil(t, inst)
	return inst
}

func setConfigRegistryHandler(t *testing.T, cfg *dnsserver.Config, name string, handler coreplugin.Handler) {
	t.Helper()

	v := reflect.ValueOf(cfg).Elem().FieldByName("registry")
	require.True(t, v.IsValid())
	require.True(t, v.CanAddr())

	m := map[string]coreplugin.Handler{name: handler}
	reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem().Set(reflect.ValueOf(m))
}

func TestSetup_RegistersPluginAndLifecycleHooks(t *testing.T) {
	c := caddy.NewTestController("dns", "fanout . 127.0.0.1")
	cfg := dnsserver.GetConfig(c)
	require.NotNil(t, cfg)
	require.Len(t, cfg.Plugin, 0)

	inst := controllerInstance(t, c)
	startupBefore := len(inst.OnStartup)
	shutdownBefore := len(inst.OnShutdown)

	err := setup(c)
	require.NoError(t, err)
	require.Len(t, cfg.Plugin, 1)
	require.Len(t, inst.OnStartup, startupBefore+1)
	require.Len(t, inst.OnShutdown, shutdownBefore+1)

	next := coreplugin.HandlerFunc(func(context.Context, dns.ResponseWriter, *dns.Msg) (int, error) {
		return dns.RcodeSuccess, nil
	})

	h := cfg.Plugin[0](next)
	f, ok := h.(*Fanout)
	require.True(t, ok)
	require.NotNil(t, f.Next)
}

func TestSetup_OnStartupBindsDnstapPluginFromRegistry(t *testing.T) {
	c := caddy.NewTestController("dns", "fanout . 127.0.0.1")
	cfg := dnsserver.GetConfig(c)

	err := setup(c)
	require.NoError(t, err)
	require.Len(t, cfg.Plugin, 1)

	next := coreplugin.HandlerFunc(func(context.Context, dns.ResponseWriter, *dns.Msg) (int, error) {
		return dns.RcodeSuccess, nil
	})
	h := cfg.Plugin[0](next)
	f, ok := h.(*Fanout)
	require.True(t, ok)
	require.Nil(t, f.TapPlugin)

	tapPlugin := &dnstap.Dnstap{}
	setConfigRegistryHandler(t, cfg, "dnstap", tapPlugin)

	inst := controllerInstance(t, c)
	require.NotEmpty(t, inst.OnStartup)
	for _, startupFn := range inst.OnStartup {
		require.NoError(t, startupFn())
	}

	require.Same(t, tapPlugin, f.TapPlugin)
}

func TestSetup_ReturnsErrorWhenTooManyUpstreams(t *testing.T) {
	hosts := make([]string, 0, maxIPCount+1)
	for i := 1; i <= maxIPCount+1; i++ {
		hosts = append(hosts, fmt.Sprintf("10.0.0.%d", i))
	}
	input := fmt.Sprintf("fanout . %s", strings.Join(hosts, " "))

	c := caddy.NewTestController("dns", input)
	err := setup(c)
	require.Error(t, err)
	require.Contains(t, err.Error(), "more than 100 TOs configured")
}
