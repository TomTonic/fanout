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
