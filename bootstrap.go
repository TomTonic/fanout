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
	"math/rand/v2"
	"net"

	"github.com/pkg/errors"
)

// newBootstrapResolver creates a net.Resolver that sends DNS queries to the
// given server addresses (ip:port) over plain UDP instead of using the system
// default resolver. This breaks the circular dependency that occurs when
// DoH/DoH3/DoQ upstream hostnames must be resolved through the very DNS
// service being configured.
func newBootstrapResolver(addrs []string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: dialTimeout}
			addr := addrs[rand.IntN(len(addrs))]
			return d.DialContext(ctx, "udp", addr)
		},
	}
}

// bootstrapResolveHost resolves the hostname portion of a host:port string
// using the given resolver. If the host is already an IP address the input is
// returned unchanged. On success the first resolved IP is returned joined with
// the original port, and the bare hostname is returned separately so the caller
// can set the TLS ServerName.
func bootstrapResolveHost(ctx context.Context, resolver *net.Resolver, hostport string) (resolved, hostname string, err error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport, "", nil
	}
	if net.ParseIP(host) != nil {
		return hostport, "", nil
	}
	ips, err := resolver.LookupHost(ctx, host)
	if err != nil {
		return "", host, errors.Wrapf(err, "bootstrap resolution of %s failed", host)
	}
	if len(ips) == 0 {
		return "", host, errors.Errorf("bootstrap resolution of %s returned no addresses", host)
	}
	return net.JoinHostPort(ips[0], port), host, nil
}
