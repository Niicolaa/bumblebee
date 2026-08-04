package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The compiled-in fallback version and the VERSION file are two separate
// places recording the same fact, and nothing but this test links them.
// A release that bumps one and forgets the other ships binaries whose
// scanner_version does not match the tag they were cut from.
func TestFileDefaultMatchesVERSION(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimSpace(string(data))
	if fileDefault != want {
		t.Errorf("fileDefault = %q but VERSION file says %q; bump both", fileDefault, want)
	}
}
