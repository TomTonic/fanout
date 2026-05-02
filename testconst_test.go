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

// Test-only constants shared across test files in the fanout package.
const (
	// DNS endpoint strings.
	localDNS53      = "127.0.0.1:53"
	localDNS853     = "127.0.0.1:853"
	exampleDoTAddr  = "dns.example.com:853"
	exampleDoTHost  = "dns.example.com"
	ipv6Bracket443  = "[2001:db8::1]:443"
	dnsGoogleHost   = "dns.google"
	dnsGoogleDoHURL = "https://dns.google/dns-query"
	googleDoH8888   = "https://8.8.8.8/dns-query"

	// TLS / PEM block type literals.
	localhostName = "localhost"
	pemTypeCert   = "CERTIFICATE"
	pemTypeECKey  = "EC PRIVATE KEY"

	// DNS record content.
	spfRecord = "v=spf1 include:example.com ~all"

	// Corefile snippet strings used as test inputs.
	corefileUDPLocal   = "fanout . 127.0.0.1"
	corefileTCPLocal   = "fanout . 127.0.0.1 {\nnetwork tcp\n}"
	corefileDoHGoogle  = "fanout . https://dns.google/dns-query"
	corefileDoH3Google = "fanout . h3://dns.google/dns-query"
	corefileAllDoH     = "fanout . 127.0.0.1 https://dns.google/dns-query h3://cloudflare-dns.com/dns-query"
	corefileAllDoHDoQ  = "fanout . 127.0.0.1 https://dns.google/dns-query h3://cloudflare-dns.com/dns-query quic://dns.example.com:853"

	// Domain names used in test assertions.
	exampleOrgFQDN   = "example.org."
	exampleOrgNoDot  = "example.org"
	orgDot           = "org."
	wrongExampleFQDN = "wrong.example."

	// net.Addr type name strings used in tracing tests.
	addrTypeUDP = "*net.UDPAddr"
	addrTypeTCP = "*net.TCPAddr"

	// HTTP header names.
	httpHeaderContentType = "Content-Type"

	// Error message substrings.
	errMsgWrongArgCount      = "Wrong argument count"
	errMsgTooSmall           = "too small"
	errMsgWrongArgOrEnd      = "Wrong argument count or unexpected line ending"
	errMsgLoadFactorMismatch = "load-factor params count must be the same as the number of hosts"

	// Test case name strings that appear in multiple test files.
	testCaseLowercase = "lowercase"
	testCaseUppercase = "uppercase"
	testCaseMixedcase = "mixedcase"
	testCaseDohOnly   = "doh-only"
	testCaseDoH3Only  = "doh3-only"
	testCaseUDP       = "UDP"
	testCaseTCP       = "TCP"
	testCaseDoT       = "DoT"
	testCaseDoQ       = "DoQ"
)
