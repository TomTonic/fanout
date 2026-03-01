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

package fanout

import (
	"crypto/rand"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestDomainBasic verifies basic parent/child containment in the Domain trie used by the except /
// except-file directives. The trie is checked on every incoming query to decide whether to skip fanout.
// Ensures "." matches everything, "org." matches "example.org.", but "example.org." does not match "org.".
func TestDomainBasic(t *testing.T) {
	samples := []struct {
		child    string
		parent   string
		expected bool
	}{
		{".", ".", true},
		{"example.org.", ".", true},
		{"example.org.", "example.org.", true},
		{"example.org", "example.org", true},
		{"example.org.", "org.", true},
		{"org.", "example.org.", false},
	}

	for i, s := range samples {
		l := NewDomain()
		l.AddString(s.parent)
		require.Equal(t, s.expected, l.Contains(s.child), i)
	}
}

// TestDomainGet verifies the internal structure of the Domain trie used for domain exclusion.
// After adding "google.com." and "example.com.", navigating . → com → google must reach a final node.
// Ensures the tree is built in reverse-label order as expected.
func TestDomainGet(t *testing.T) {
	d := NewDomain()
	d.AddString("google.com.")
	d.AddString("example.com.")
	require.True(t, d.Get(".").Get("com").Get("google").IsFinal())
}

// TestDomain_ContainsShouldWorkFast is a performance guard for the domain-exclusion lookup that
// runs on every DNS query. Inserts 10 000 random domain names into the trie, then asserts that
// 10 000 Contains() calls complete in under 250 ms.
func TestDomain_ContainsShouldWorkFast(t *testing.T) {
	var samples []string
	d := NewDomain()
	for i := 0; i < 100; i++ {
		for j := 0; j < 100; j++ {
			samples = append(samples, genSample(i+1))
			d.AddString(samples[len(samples)-1])
		}
	}
	start := time.Now()
	for i := 0; i < 10000; i++ {
		require.True(t, d.Contains(samples[i]))
	}
	require.True(t, time.Since(start) < time.Second/4)
}

// TestDomainFewEntries verifies that two sibling domains (google.com., example.com.) are stored
// independently in the Domain trie and that their common parent "com." alone does not match.
func TestDomainFewEntries(t *testing.T) {
	d := NewDomain()
	d.AddString("google.com.")
	d.AddString("example.com.")
	require.True(t, d.Contains("google.com."))
	require.True(t, d.Contains("example.com."))
	require.False(t, d.Contains("com."))
}

// TestDomain_DoNotStoreExtraEntries verifies that when a broader domain (example.com.) is already
// in the trie, adding a more specific subdomain (advanced.example.com.) is a no-op.
// The trie stays minimal because the broader rule already covers all subdomains.
func TestDomain_DoNotStoreExtraEntries(t *testing.T) {
	d := NewDomain()
	d.AddString("example.com.")
	d.AddString("advanced.example.com.")
	require.Nil(t, d.Get(".").Get("com").Get("example").Get("advanced"))
}

func BenchmarkDomain_ContainsMatch(b *testing.B) {
	d := NewDomain()
	var samples []string
	for i := 0; i < 100; i++ {
		for j := 0; j < 100; j++ {
			samples = append(samples, genSample(i+1))
			d.AddString(samples[len(samples)-1])
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < 10000; j++ {
			d.Contains(samples[j])
		}
	}
}

func BenchmarkDomain_AddString(b *testing.B) {
	d := NewDomain()
	var samples []string
	for i := 0; i < 100; i++ {
		for j := 0; j < 100; j++ {
			samples = append(samples, genSample(i+1))
		}
	}
	for i := 0; i < b.N; i++ {
		for j := 0; j < len(samples); j++ {
			d.AddString(samples[j])
		}
	}
}

func BenchmarkDomain_ContainsAny(b *testing.B) {
	d := NewDomain()
	var samples []string
	for i := 0; i < 100; i++ {
		for j := 0; j < 100; j++ {
			d.AddString(genSample(i + 1))
			samples = append(samples, genSample(i+1))
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < len(samples); j++ {
			d.Contains(samples[j])
		}
	}
}

func genSample(n int) string {
	randInt := func() int {
		r, err := rand.Int(rand.Reader, big.NewInt(100))
		if err != nil {
			panic(err.Error())
		}
		return int(r.Int64())
	}

	var sb strings.Builder
	for segment := 0; segment < n; segment++ {
		l := randInt()%9 + 1
		for i := 0; i < l; i++ {
			v := (randInt() % 26) + 97
			_, _ = sb.WriteRune(rune(v))
		}
		_, _ = sb.WriteRune('.')
	}
	return sb.String()
}
