package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

// The real shape that failed in production: a commented .vscode/mcp.json.
// Before JSONC handling this returned "invalid character '/' looking for
// beginning of object key string" and the machine reported no MCP
// servers at all.
func TestScanConfigAcceptsJSONC(t *testing.T) {
	body := `{
  // Managed by the platform team - do not edit by hand.
  "servers": {
    /* internal tooling */
    "odp": {
      "command": "uvx",
      "args": ["mcp-server-odp", "--url", "https://example.com//api"],
      "type": "stdio"
    },
    "other": {
      "command": "npx",
      "args": ["-y", "some-server"], // trailing comment
    },
  }
}`
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.json")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	var diags []string
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) { out = append(out, r) },
		Diag:        func(level, p, msg string) { diags = append(diags, level+": "+msg) },
	}
	if err := s.ScanConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 servers, got %d (diags: %v)", len(out), diags)
	}
	names := map[string]bool{}
	for _, r := range out {
		names[r.ServerName] = true
	}
	if !names["odp"] || !names["other"] {
		t.Errorf("missing servers: %+v", names)
	}
}

// A "//" inside a string is not a comment. MCP configs are full of URLs,
// so getting this wrong would corrupt the very fields we emit.
func TestStripJSONCPreservesStrings(t *testing.T) {
	cases := map[string]string{
		`{"u":"https://example.com//x"}`:         "https://example.com//x",
		`{"u":"a /* not a comment */ b"}`:        "a /* not a comment */ b",
		`{"u":"quote \" then // not a comment"}`: `quote " then // not a comment`,
	}
	for in, want := range cases {
		var got struct {
			U string `json:"u"`
		}
		if err := json.Unmarshal(stripJSONC([]byte(in)), &got); err != nil {
			t.Errorf("%s: %v", in, err)
			continue
		}
		if got.U != want {
			t.Errorf("%s -> %q, want %q", in, got.U, want)
		}
	}
}

// Offsets and line numbers must survive so parse errors still point at
// the right place in the original file.
func TestStripJSONCPreservesLayout(t *testing.T) {
	in := []byte("{\n// c\n/* a\nb */\n\"k\": 1\n}")
	out := stripJSONC(in)
	if len(out) != len(in) {
		t.Errorf("length changed: %d -> %d", len(in), len(out))
	}
	if countNewlines(out) != countNewlines(in) {
		t.Errorf("newline count changed")
	}
	var doc map[string]int
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("result is not valid JSON: %v (%q)", err, out)
	}
	if doc["k"] != 1 {
		t.Errorf("got %+v", doc)
	}
}

func countNewlines(b []byte) int {
	n := 0
	for _, c := range b {
		if c == '\n' {
			n++
		}
	}
	return n
}
