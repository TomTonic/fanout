// Copyright (c) 2020 Doc.ai and/or its affiliates.
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

// Package fanout - parallel proxying DNS messages to upstream resolvers.
//
// Supported transport protocols:
//   - DNS/UDP (plain, default)
//   - DNS/TCP (plain)
//   - DoT  - DNS-over-TLS   (RFC 7858)  — tls:// prefix or "tls" directive
//   - DoH  - DNS-over-HTTPS (RFC 8484)  — https:// prefix (HTTP/2 transport)
//   - DoH3 - DNS-over-HTTPS (RFC 8484)  — h3:// prefix   (HTTP/3 / QUIC transport, RFC 9114)
//   - DoQ  - DNS-over-QUIC  (RFC 9250)  — quic:// prefix
package fanout
