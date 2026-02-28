package fanout

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coredns/caddy"
)

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
	f.WriteString("example.org.")
	f.Close()
	defer os.Remove(f.Name())

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
