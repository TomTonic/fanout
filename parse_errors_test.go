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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coredns/caddy"
)

// TestParseErrors verifies argument validation during Corefile parsing for all configuration directives.
// Table-driven test covering invalid Corefile snippets: missing arguments for network, policy,
// timeout, tls-server, worker-count, except, race; too many TLS args; no upstream hosts; path escape
// in except-file; unparseable timeout; timeout out of range; invalid worker-count; and bad load-factor format.
// Each case asserts that parseFanout returns an error containing the expected substring.
func TestParseErrors(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectedErr string
	}{
		{name: "err-missing-network", input: "fanout . 127.0.0.1 {\nnetwork\n}", expectedErr: "Wrong argument count"},
		{name: "err-missing-policy", input: "fanout . 127.0.0.1 {\npolicy\n}", expectedErr: "Wrong argument count"},
		{name: "err-missing-timeout", input: "fanout . 127.0.0.1 {\ntimeout\n}", expectedErr: "Wrong argument count"},
		{name: "err-missing-tls-servername", input: "fanout . 127.0.0.1 {\ntls-server\n}", expectedErr: "Wrong argument count"},
		{name: "err-missing-worker-count", input: "fanout . 127.0.0.1 {\nworker-count\n}", expectedErr: "Wrong argument count"},
		{name: "err-missing-except", input: "fanout . 127.0.0.1 {\nexcept\n}", expectedErr: "Wrong argument count"},
		{name: "err-too-many-tls-args", input: "fanout . 127.0.0.1 {\ntls 1 2 3 4\n}", expectedErr: "Wrong argument count"},
		{name: "err-too-many-race-args", input: "fanout . 127.0.0.1 {\nrace 1\n}", expectedErr: "Wrong argument count"},
		{name: "err-no-to-hosts", input: "fanout .", expectedErr: "Wrong argument count"},
		{name: "err-except-file-escape", input: "fanout . 127.0.0.1 {\nexcept-file ../file.txt\n}", expectedErr: "path must be local"},
		{name: "err-timeout-parse", input: "fanout . 127.0.0.1 {\ntimeout asd\n}", expectedErr: "invalid duration"},
		{name: "err-timeout-too-small", input: "fanout . 127.0.0.1 {\ntimeout 10ms\n}", expectedErr: "too small"},
		{name: "err-timeout-negative", input: "fanout . 127.0.0.1 {\ntimeout -1s\n}", expectedErr: "too small"},
		{name: "err-timeout-too-large", input: "fanout . 127.0.0.1 {\ntimeout 10m\n}", expectedErr: "too large"},
		{name: "err-worker-count-parse", input: "fanout . 127.0.0.1 {\nworker-count \n}", expectedErr: "Wrong argument count"},
		{name: "err-load-factor-parse", input: "fanout . 127.0.0.1 {\npolicy weighted-random \nweighted-random-load-factor asd\n}", expectedErr: "Wrong argument count"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := caddy.NewTestController("dns", tc.input)
			_, err := parseFanout(c)
			if err == nil {
				t.Fatalf("expected error containing %q but got none", tc.expectedErr)
			}
			if !strings.Contains(err.Error(), tc.expectedErr) {
				t.Fatalf("expected error to contain: %v, found error: %v", tc.expectedErr, err)
			}
		})
	}
}

// TestParseExceptFileRelativeOK verifies that during Corefile parsing, a relative except-file path
// (within the working directory) is accepted and its contents loaded into ExcludeDomains.
// Creates a temp file in the CWD, parses a Corefile referencing it by relative path,
// and verifies the domain is present in the exclusion list.
func TestParseExceptFileRelativeOK(t *testing.T) {
	// Create a temporary file in the *current working directory* to allow relative path testing
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.CreateTemp(cwd, "except*.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString("example.org.")
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // test-controlled temp file path created in this function
	defer func() { _ = os.Remove(f.Name()) }()

	relPath, _ := filepath.Rel(cwd, f.Name())

	input := "fanout . 127.0.0.1 {\nexcept-file " + relPath + "\n}"
	c := caddy.NewTestController("dns", input)
	fan, err := parseFanout(c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !fan.ExcludeDomains.Contains("example.org.") {
		t.Fatal("expected domain not loaded")
	}
}
