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

	//nolint:gosec // test-only reflection to access unexported field from caddy test controller
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
	//nolint:gosec // test-only reflection to inject handler registry for startup hook verification
	reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem().Set(reflect.ValueOf(m))
}

// TestSetup_RegistersPluginAndLifecycleHooks verifies that during plugin registration (setup()),
// the fanout plugin adds itself to the CoreDNS plugin chain and registers OnStartup / OnShutdown hooks.
// Asserts that after setup(), exactly one plugin function is registered, startup/shutdown hook counts
// each increased by one, and the plugin function wraps the next handler correctly as a *Fanout instance.
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

// TestSetup_OnStartupBindsDnstapPluginFromRegistry verifies that during OnStartup, if a dnstap
// plugin is registered in the server config registry, fanout binds it to f.TapPlugin for DNS tap
// logging. Injects a dnstap.Dnstap into the config registry, runs the startup hooks, and asserts
// f.TapPlugin points to the injected instance.
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

// TestSetup_ReturnsErrorWhenTooManyUpstreams verifies that during plugin registration,
// configuring more than 100 upstream servers produces an error ("more than 100 TOs configured").
// Generates 101 IPs and verifies setup() rejects the configuration.
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
