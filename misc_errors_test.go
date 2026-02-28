package fanout

import (
	"errors"
	"testing"
)

func TestLogErrIfNotNil(t *testing.T) {
	// just to trigger coverage
	logErrIfNotNil(nil)
	logErrIfNotNil(errors.New("test error"))
}

func TestDomainContains_NilChild(t *testing.T) {
	d := NewDomain()
	d.AddString("b.c.")

	// 'c.' exists, 'b.' exists.
	// We lookup 'x.y.b.c.' -> 'c' exists, 'b' exists, 'y' doesn't exist.
	if d.Contains("c") {
		t.Fatal("expected false")
	}
}
