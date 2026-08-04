package hex

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func TestScanMixLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mix.lock")
	if err := os.WriteFile(path, []byte(`%{
  "castore": {:hex, :castore, "1.0.5", "9eeebb394cc9a0f3ae56b813459f990abb0a3dedee1be6b27fdb1d1a3fd9d049", [:mix], [], "hexpm", "8d7c597c3e4a64c395980882d4bca3cebb8d74197c590bc272087bd7c8e5e4d4"},
  "jason": {:hex, :jason, "1.4.1", "af1504e35f629ddcdd576b25d24f6dc6dd7e4d4c7d0f2fd66a09e13d5a3cf3d5", [:mix], [], "hexpm", "fbb01ecdfd565b56261302f7e1fcc27c4fb8f32d56eab74db621fc154604a7b3"},
  "my_fork": {:git, "https://github.com/me/fork.git", "abcdef1234567890", []},
}
`), 0o644); err != nil {
		t.Fatal(err)
	}

	var got []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { got = append(got, r) }}
	if err := s.ScanMixLock(path, model.Record{}); err != nil {
		t.Fatal(err)
	}

	// Only :hex entries name a registry release; the :git entry's third
	// field is a revision, not a version.
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2: %+v", len(got), got)
	}
	byName := map[string]model.Record{}
	for _, r := range got {
		byName[r.PackageName] = r
	}
	if r := byName["castore"]; r.Version != "1.0.5" {
		t.Errorf("castore version = %q", r.Version)
	}
	if r := byName["jason"]; r.Version != "1.4.1" {
		t.Errorf("jason version = %q", r.Version)
	}
	if _, ok := byName["my_fork"]; ok {
		t.Error("git-sourced entry must not be emitted")
	}
	if byName["castore"].Ecosystem != model.EcosystemHex {
		t.Errorf("ecosystem = %q", byName["castore"].Ecosystem)
	}
}

func TestQuotedFields(t *testing.T) {
	got := quotedFields(`"a": {:hex, :a, "1.0.0", "hash"},`)
	want := []string{"a", "1.0.0", "hash"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("field %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestQuotedFieldsHandlesEscapes(t *testing.T) {
	// A stray escape must not desynchronise the remaining fields.
	got := quotedFields(`"a\"b", "second"`)
	if len(got) != 2 || got[0] != `a"b` || got[1] != "second" {
		t.Errorf("got %#v", got)
	}
}
