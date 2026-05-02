// Copyright (c) 2020 Doc.ai and/or its affiliates.
// Copyright (c) 2024 MWS and/or its affiliates.
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
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/caddy/caddyfile"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/dnstap"
	"github.com/coredns/coredns/plugin/pkg/parse"
	"github.com/coredns/coredns/plugin/pkg/tls"
	"github.com/coredns/coredns/plugin/pkg/transport"
	"github.com/pkg/errors"
)

const (
	devVersion      = "(devel)"
	attemptCountKey = "attempt-count"
)

func init() {
	caddy.RegisterPlugin(pluginName, caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

type buildInfo struct {
	version  string
	revision string
	time     string
	modified bool
}

func readBuildInfo() buildInfo {
	bi := buildInfo{version: devVersion}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		bi.version = "(unknown)"
		return bi
	}
	if info.Main.Version != "" && info.Main.Version != devVersion {
		bi.version = info.Main.Version
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			bi.revision = s.Value
		case "vcs.time":
			bi.time = s.Value
		case "vcs.modified":
			bi.modified = s.Value == "true"
		}
	}
	return bi
}

func (b buildInfo) String() string {
	parts := []string{b.version}
	if b.revision != "" {
		rev := b.revision
		if len(rev) > 12 {
			rev = rev[:12]
		}
		parts = append(parts, "rev "+rev)
	}
	if b.time != "" {
		parts = append(parts, b.time)
	}
	if b.modified {
		parts = append(parts, "dirty")
	}
	return strings.Join(parts, " ")
}

func setup(c *caddy.Controller) error {
	f, err := parseFanout(c)
	if err != nil {
		return plugin.Error(pluginName, err)
	}
	l := len(f.clients)
	if l > maxIPCount {
		return plugin.Error(pluginName, errors.Errorf("more than %d TOs configured: %d", maxIPCount, l))
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		f.Next = next
		return f
	})

	c.OnStartup(func() error {
		if taph := dnsserver.GetConfig(c).Handler("dnstap"); taph != nil {
			if tapPlugin, ok := taph.(*dnstap.Dnstap); ok {
				f.TapPlugin = tapPlugin
			}
		}
		log.Infof("fanout %s", readBuildInfo())
		return f.OnStartup()
	})
	c.OnShutdown(f.OnShutdown)

	return nil
}

// OnStartup starts a goroutines for all clients.
func (f *Fanout) OnStartup() (err error) {
	return nil
}

// OnShutdown stops all configured clients and releases their resources.
func (f *Fanout) OnShutdown() error {
	for _, c := range f.clients {
		if cl, ok := c.(io.Closer); ok {
			_ = cl.Close()
		}
	}
	return nil
}

func parseFanout(c *caddy.Controller) (*Fanout, error) {
	var (
		f   *Fanout
		err error
		i   int
	)
	for c.Next() {
		if i > 0 {
			return nil, plugin.ErrOnce
		}
		i++
		f, err = parseFanoutStanza(&c.Dispenser)
		if err != nil {
			return nil, err
		}
	}

	return f, nil
}

func parseFanoutStanza(c *caddyfile.Dispenser) (*Fanout, error) {
	f := New()
	if !c.Args(&f.From) {
		return f, c.ArgErr()
	}

	normalized := plugin.Host(f.From).NormalizeExact()
	if len(normalized) == 0 {
		return nil, errors.Errorf("unable to normalize '%s'", f.From)
	}
	f.From = normalized[0]

	to := c.RemainingArgs()
	if len(to) == 0 {
		return f, c.ArgErr()
	}

	dohURLs, doh3URLs, doqAddrs, plainHosts := classifyUpstreams(to)

	// Parse non-DoH hosts through the standard host/port/file resolver.
	var toHosts []string
	if len(plainHosts) > 0 {
		var err error
		toHosts, err = parse.HostPortOrFile(plainHosts...)
		if err != nil {
			return f, err
		}
	}

	for c.NextBlock() {
		err := parseValue(strings.ToLower(c.Val()), f, c)
		if err != nil {
			return nil, err
		}
	}
	initClients(f, toHosts)
	initDoHClients(f, dohURLs)
	initDoH3Clients(f, doh3URLs)
	initDoQClients(f, doqAddrs)
	err := initServerSelectionPolicy(f)
	if err != nil {
		return nil, err
	}

	if f.WorkerCount > len(f.clients) || f.WorkerCount == 0 {
		f.WorkerCount = len(f.clients)
	}

	return f, nil
}

// classifyUpstreams separates upstream addresses by protocol scheme.
// Scheme prefixes: https:// → DoH (HTTP/2), h3:// → DoH3 (HTTP/3), quic:// → DoQ (RFC 9250).
func classifyUpstreams(to []string) (dohURLs, doh3URLs, doqAddrs, plainHosts []string) {
	for _, t := range to {
		lower := strings.ToLower(t)
		switch {
		case strings.HasPrefix(lower, "h3://"):
			// h3://host/path -> convert to https://host/path for the HTTP client.
			doh3URLs = append(doh3URLs, "https://"+t[len("h3://"):])
		case strings.HasPrefix(lower, "https://"):
			dohURLs = append(dohURLs, t)
		case strings.HasPrefix(lower, "quic://"):
			// Strip the quic:// scheme, leaving host:port for DoQ (RFC 9250).
			addr := t[len("quic://"):]
			// Default DoQ port is 853 (same as DoT).
			if _, _, err := net.SplitHostPort(addr); err != nil {
				addr += ":853"
			}
			doqAddrs = append(doqAddrs, addr)
		default:
			plainHosts = append(plainHosts, t)
		}
	}
	return
}

func initClients(f *Fanout, hosts []string) {
	transports := make([]string, len(hosts))
	for i, host := range hosts {
		trans, h := parse.Transport(host)
		f.addClient(NewClient(h, f.net))
		transports[i] = trans
	}

	f.tlsConfig.ServerName = f.tlsServerName
	for i := range f.clients {
		if transports[i] == transport.TLS {
			f.clients[i].SetTLSConfig(f.tlsConfig)
		}
	}
}

// initDoHClients creates DNS-over-HTTPS clients from the provided URLs and appends them
// to the fanout's client list. Each URL must be a full HTTPS endpoint (e.g. "https://dns.google/dns-query").
func initDoHClients(f *Fanout, urls []string) {
	for _, u := range urls {
		c := newDoHClientFull(u, nil, f.bootstrap)
		if f.tlsConfig != nil && f.tlsConfig.ServerName != "" {
			c.SetTLSConfig(f.tlsConfig)
		}
		f.addClient(c)
	}
}

// initDoH3Clients creates DNS-over-HTTPS/3 (HTTP/3 over QUIC) clients from the provided
// URLs and appends them to the fanout's client list.
func initDoH3Clients(f *Fanout, urls []string) {
	for _, u := range urls {
		c := newDoH3ClientFull(u, nil, f.bootstrap)
		if f.tlsConfig != nil && f.tlsConfig.ServerName != "" {
			c.SetTLSConfig(f.tlsConfig)
		}
		f.addClient(c)
	}
}

// initDoQClients creates DNS-over-QUIC (RFC 9250) clients from the provided addresses
// and appends them to the fanout's client list.
func initDoQClients(f *Fanout, addrs []string) {
	for _, a := range addrs {
		c := newDoQClientFull(a, nil, f.bootstrap)
		if f.tlsConfig != nil && f.tlsConfig.ServerName != "" {
			c.SetTLSConfig(f.tlsConfig)
		}
		f.addClient(c)
	}
}

func initServerSelectionPolicy(f *Fanout) error {
	if f.serverCount > len(f.clients) || f.serverCount == 0 {
		f.serverCount = len(f.clients)
	}

	loadFactor := f.loadFactor
	if len(loadFactor) == 0 {
		for i := 0; i < len(f.clients); i++ {
			loadFactor = append(loadFactor, maxLoadFactor)
		}
	}
	if len(loadFactor) != len(f.clients) {
		return errors.New("load-factor params count must be the same as the number of hosts")
	}

	f.ServerSelectionPolicy = &SequentialPolicy{}
	if f.policyType == policyWeightedRandom {
		f.ServerSelectionPolicy = &WeightedPolicy{
			loadFactor: loadFactor,
		}
	}

	return nil
}

// parseRegistry maps Corefile directive names to their parse functions.
var parseRegistry = map[string]func(*Fanout, *caddyfile.Dispenser) error{
	"tls":                             parseTLS,
	"network":                         parseProtocol,
	"tls-server":                      parseTLSServer,
	"tls_servername":                  parseTLSServer,
	"worker-count":                    parseWorkerCount,
	"policy":                          parsePolicy,
	"weighted-random-server-count":    parseWeightedRandomServerCount,
	"weighted-random-load-factor":     parseLoadFactor,
	"timeout":                         parseTimeout,
	"debug":                           parseDebug,
	"race":                            parseRace,
	"race-continue-on-error":          parseRaceContinueOnError,
	"race-continue-on-error-response": parseRaceContinueOnError,
	"bootstrap":                       parseBootstrap,
	"ecs":                             parseECS,
	"except":                          parseIgnored,
	"except-file":                     parseIgnoredFromFile,
	"attempt-count":                   parseAttemptCount,
}

func parseValue(v string, f *Fanout, c *caddyfile.Dispenser) error {
	handler, ok := parseRegistry[v]
	if !ok {
		return errors.Errorf("unknown property %v", v)
	}
	return handler(f, c)
}

func parseWeightedRandomServerCount(f *Fanout, c *caddyfile.Dispenser) error {
	serverCount, err := parsePositiveInt(c)
	f.serverCount = serverCount
	return err
}

func parseAttemptCount(f *Fanout, c *caddyfile.Dispenser) error {
	num, err := parsePositiveInt(c)
	f.Attempts = num
	return err
}

func parseDebug(f *Fanout, c *caddyfile.Dispenser) error {
	if c.NextArg() {
		return c.ArgErr()
	}
	f.Debug = true
	return nil
}

func parsePolicy(f *Fanout, c *caddyfile.Dispenser) error {
	if !c.NextArg() {
		return c.ArgErr()
	}

	policyType := strings.ToLower(c.Val())
	if policyType != policyWeightedRandom && policyType != policySequential {
		return errors.Errorf("unknown policy %q", c.Val())
	}
	f.policyType = policyType

	return nil
}

func parseTimeout(f *Fanout, c *caddyfile.Dispenser) error {
	if !c.NextArg() {
		return c.ArgErr()
	}
	var err error
	val := c.Val()
	f.Timeout, err = time.ParseDuration(val)
	if err != nil {
		return err
	}
	if f.Timeout < minTimeout {
		return errors.Errorf("timeout %s is too small, minimum is %s", val, minTimeout)
	}
	if f.Timeout > maxTimeout {
		return errors.Errorf("timeout %s is too large, maximum is %s", val, maxTimeout)
	}
	return nil
}

func parseRace(f *Fanout, c *caddyfile.Dispenser) error {
	if c.NextArg() {
		return c.ArgErr()
	}
	f.Race = true
	return nil
}

func parseRaceContinueOnError(f *Fanout, c *caddyfile.Dispenser) error {
	if c.NextArg() {
		return c.ArgErr()
	}
	f.RaceContinueOnErrorResponse = true
	return nil
}

func parseBootstrap(f *Fanout, c *caddyfile.Dispenser) error {
	args := c.RemainingArgs()
	if len(args) == 0 {
		return c.ArgErr()
	}
	addrs := make([]string, 0, len(args))
	for _, a := range args {
		if _, _, err := net.SplitHostPort(a); err != nil {
			a = net.JoinHostPort(a, "53")
		}
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			return c.Errf("invalid bootstrap address %q: %v", a, err)
		}
		if net.ParseIP(host) == nil {
			return c.Errf("bootstrap address must be an IP literal: %q", host)
		}
		addrs = append(addrs, a)
	}
	f.bootstrap = newBootstrapConfig(addrs)
	return nil
}

func parseECS(f *Fanout, c *caddyfile.Dispenser) error {
	if f.bootstrap == nil {
		return c.Errf("ecs requires a prior bootstrap directive")
	}
	args := c.RemainingArgs()
	switch len(args) {
	case 0:
		// Auto-detect from outgoing IP toward the first reachable bootstrap server.
		subnet, err := detectLocalSubnetFromAny(f.bootstrap.addrs)
		if err != nil {
			return c.Errf("ecs auto-detection failed: %v", err)
		}
		f.bootstrap.setECS(subnet)
	case 1:
		_, subnet, err := net.ParseCIDR(args[0])
		if err != nil {
			return c.Errf("invalid CIDR for ecs: %v", err)
		}
		f.bootstrap.setECS(subnet)
	default:
		return c.Errf("ecs takes zero or one argument: ecs [CIDR]")
	}
	return nil
}

func parseIgnoredFromFile(f *Fanout, c *caddyfile.Dispenser) error {
	args := c.RemainingArgs()
	if len(args) != 1 {
		return c.ArgErr()
	}
	cleanPath := filepath.Clean(args[0])
	if !filepath.IsAbs(cleanPath) && !filepath.IsLocal(cleanPath) {
		return errors.Errorf("path must be local: %q", args[0])
	}
	readPath := cleanPath
	if !filepath.IsAbs(cleanPath) {
		workDir, err := os.Getwd()
		if err != nil {
			return err
		}
		absPath := filepath.Join(workDir, cleanPath)
		relPath, err := filepath.Rel(workDir, absPath)
		if err != nil {
			return err
		}
		if relPath == ".." || strings.HasPrefix(relPath, ".."+string(os.PathSeparator)) {
			return errors.Errorf("path escapes working directory: %q", args[0])
		}
		readPath = absPath
	}
	b, err := os.ReadFile(readPath)
	if err != nil {
		return err
	}
	names := strings.Split(string(b), "\n")
	for i := 0; i < len(names); i++ {
		normalized := plugin.Host(names[i]).NormalizeExact()
		if len(normalized) == 0 {
			return errors.Errorf("unable to normalize '%s'", names[i])
		}
		f.ExcludeDomains.AddString(normalized[0])
	}
	return nil
}

func parseIgnored(f *Fanout, c *caddyfile.Dispenser) error {
	ignore := c.RemainingArgs()
	if len(ignore) == 0 {
		return c.ArgErr()
	}
	for i := 0; i < len(ignore); i++ {
		normalized := plugin.Host(ignore[i]).NormalizeExact()
		if len(normalized) == 0 {
			return errors.Errorf("unable to normalize '%s'", ignore[i])
		}
		f.ExcludeDomains.AddString(normalized[0])
	}
	return nil
}

func parseWorkerCount(f *Fanout, c *caddyfile.Dispenser) error {
	var err error
	f.WorkerCount, err = parsePositiveInt(c)
	if err == nil {
		if f.WorkerCount < minWorkerCount {
			return errors.New("worker count should be more or equal 2. Consider to use Forward plugin")
		}
		if f.WorkerCount > maxWorkerCount {
			return errors.Errorf("worker count more then max value: %v", maxWorkerCount)
		}
	}
	return err
}

func parseLoadFactor(f *Fanout, c *caddyfile.Dispenser) error {
	args := c.RemainingArgs()
	if len(args) == 0 {
		return c.ArgErr()
	}

	for _, arg := range args {
		loadFactor, err := strconv.Atoi(arg)
		if err != nil {
			return c.ArgErr()
		}

		if loadFactor < minLoadFactor {
			return errors.New("load-factor should be more or equal 1")
		}
		if loadFactor > maxLoadFactor {
			return errors.Errorf("load-factor %d should be less than %d", loadFactor, maxLoadFactor)
		}

		f.loadFactor = append(f.loadFactor, loadFactor)
	}

	return nil
}

func parsePositiveInt(c *caddyfile.Dispenser) (int, error) {
	if !c.NextArg() {
		return -1, c.ArgErr()
	}
	v := c.Val()
	num, err := strconv.Atoi(v)
	if err != nil {
		return -1, c.ArgErr()
	}
	if num < 0 {
		return -1, c.ArgErr()
	}
	return num, nil
}

func parseTLSServer(f *Fanout, c *caddyfile.Dispenser) error {
	if !c.NextArg() {
		return c.ArgErr()
	}
	f.tlsServerName = c.Val()
	return nil
}

func parseProtocol(f *Fanout, c *caddyfile.Dispenser) error {
	if !c.NextArg() {
		return c.ArgErr()
	}
	protocol := strings.ToLower(c.Val())
	if protocol != TCP && protocol != UDP && protocol != TCPTLS && protocol != DOH && protocol != DOH3 && protocol != DOQ {
		return errors.New("unknown network protocol")
	}
	f.net = protocol
	return nil
}

func parseTLS(f *Fanout, c *caddyfile.Dispenser) error {
	args := c.RemainingArgs()
	if len(args) > 3 {
		return c.ArgErr()
	}

	tlsConfig, err := tls.NewTLSConfigFromArgs(args...)
	if err != nil {
		return err
	}
	f.tlsConfig = tlsConfig
	return nil
}
