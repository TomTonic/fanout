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
)

// FuzzDomainAddAndContains fuzzes the Domain trie that backs the except / except-file
// directives. It feeds arbitrary strings into AddString and Contains to find panics,
// index-out-of-range errors, or infinite loops in the trie traversal logic.
func FuzzDomainAddAndContains(f *testing.F) {
	// Seed corpus with representative inputs
	f.Add("example.com.")
	f.Add(".")
	f.Add("a.b.c.d.e.f.")
	f.Add("")
	f.Add("a")
	f.Add("..")
	f.Add("com.")
	f.Add("very.deep.sub.domain.example.org.")

	f.Fuzz(func(_ *testing.T, input string) {
		d := NewDomain()
		d.AddString(input)  // must not panic
		d.Contains(input)   // must not panic
		d.Contains("other") // must not panic even with arbitrary trie state
	})
}
