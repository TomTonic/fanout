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
	"strings"
)

// Domain stores excluded DNS names in a suffix trie for fast lookup.
// Fanout builds this structure from except and except-file directives and
// checks it for each incoming query before contacting upstream resolvers.
type Domain interface {
	// Get returns the child node for one label, or nil if absent.
	Get(string) Domain
	// AddString inserts a fully-qualified domain name into the trie.
	AddString(string)
	// Add attaches a child node for one label.
	Add(string, Domain)
	// Contains reports whether the trie contains the given fully-qualified name.
	Contains(string) bool
	// IsFinal reports whether this node marks the end of an excluded name.
	IsFinal() bool
	// Finish marks the current node as the end of an excluded name.
	Finish()
}

type domain struct {
	children map[string]Domain
	end      bool
}

// Finish marks current domain as last in the chain
func (l *domain) Finish() {
	l.end = true
}

// Add adds domain by name
func (l *domain) Add(n string, d Domain) {
	l.children[n] = d
}

// IsFinal returns true if this domain is last in the chain
func (l *domain) IsFinal() bool {
	return l.end
}

// Contains parses string and check is domains contains
func (l *domain) Contains(s string) bool {
	if s == "" {
		return false
	}
	end := len(s)
	var curr Domain = l
	for start := strings.LastIndex(s, "."); start != -1; start = strings.LastIndex(s[:start], ".") {
		var k string
		if start == end-1 {
			k = "."
		} else {
			k = s[start+1 : end]
		}
		end = start
		curr = curr.Get(k)
		if curr == nil {
			return false
		}
		if curr.IsFinal() {
			return true
		}
	}
	curr = curr.Get(s[:end])
	if curr == nil {
		return false
	}
	return curr.IsFinal()
}

// AddString parses string and adds child domains.
// Empty strings are ignored.
func (l *domain) AddString(s string) {
	if s == "" {
		return
	}
	end := len(s)
	var curr = Domain(l)
	for start := strings.LastIndex(s, "."); start != -1; start = strings.LastIndex(s[:start], ".") {
		var k string
		if start == end-1 {
			k = "."
		} else {
			k = s[start+1 : end]
		}
		end = start
		if v := curr.Get(k); v != nil {
			if v.IsFinal() {
				return
			}
			curr = v
		} else {
			next := &domain{children: map[string]Domain{}}
			curr.Add(k, next)
			curr = next
		}
	}
	if s != "." {
		next := &domain{children: map[string]Domain{}, end: true}
		curr.Add(s[:end], next)
	} else {
		curr.Finish()
	}
}

// Get returns child domain by name
func (l *domain) Get(s string) Domain {
	return l.children[s]
}

// NewDomain creates an empty exclusion trie.
// Callers typically use it during Fanout initialization and then populate it
// through AddString while parsing Corefile directives.
func NewDomain() Domain {
	return &domain{children: map[string]Domain{}}
}
