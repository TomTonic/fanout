package fanout

import (
	"errors"
	"testing"
)

// TestLogErrIfNotNil is a utility coverage test. Calls logErrIfNotNil with nil and a non-nil
// error to ensure it does not panic in either case.
func TestLogErrIfNotNil(t *testing.T) {
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
