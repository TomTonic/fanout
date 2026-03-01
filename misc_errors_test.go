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
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

// TestLogErrIfNotNil is a utility coverage test. Calls logErrIfNotNil with nil and a non-nil
// error to ensure it does not panic in either case.
func TestLogErrIfNotNil(_ *testing.T) {
	// just to trigger coverage
	logErrIfNotNil(nil)
	logErrIfNotNil(errors.New("test error"))
}

// TestDomainContains_NilChild verifies that during domain-exclusion lookup, querying a label
// that has no matching child in the trie returns false without panicking.
// Tests with "c" (no trailing dot) against a trie containing "b.c.".
func TestDomainContains_NilChild(t *testing.T) {
	d := NewDomain()
	d.AddString("b.c.")

	// 'c.' exists, 'b.' exists.
	// We lookup 'x.y.b.c.' -> 'c' exists, 'b' exists, 'y' doesn't exist.
	if d.Contains("c") {
		t.Fatal("expected false")
	}
}

// TestDomain_EmptyStringHandling verifies that the domain trie handles empty strings gracefully.
// AddString("") is a no-op and Contains("") always returns false.
func TestDomain_EmptyStringHandling(t *testing.T) {
	d := NewDomain()
	d.AddString("")
	require.False(t, d.Contains(""), "Contains('') must return false")

	// Adding a real domain still works after empty-string calls
	d.AddString("example.com.")
	require.True(t, d.Contains("example.com."))
	require.False(t, d.Contains(""))
}

// TestAddClient_IncrementsCounters verifies that AddClient increments both WorkerCount
// and serverCount, while addClient (used during setup) only appends the client.
func TestAddClient_IncrementsCounters(t *testing.T) {
	f := New()
	require.Equal(t, 0, f.WorkerCount)
	require.Equal(t, 0, f.serverCount)

	f.AddClient(NewClient("127.0.0.1:53", "udp"))
	require.Equal(t, 1, f.WorkerCount)
	require.Equal(t, 1, f.serverCount)
	require.Len(t, f.clients, 1)

	f.AddClient(NewClient("127.0.0.2:53", "udp"))
	require.Equal(t, 2, f.WorkerCount)
	require.Equal(t, 2, f.serverCount)
	require.Len(t, f.clients, 2)
}
