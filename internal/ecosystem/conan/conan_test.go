package conan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func scan(t *testing.T, content string) []model.Record {
	t.Helper()
	path := filepath.Join(t.TempDir(), "conan.lock")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	var got []model.Record
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) { got = append(got, r) },
		Diag:        func(level, path, msg string) {},
	}
	if err := s.ScanConanLock(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestScanConanLockV2(t *testing.T) {
	got := scan(t, `{
  "version": "0.5",
  "requires": [
    "zlib/1.2.13#revision%1699999999.0",
    "fmt/10.1.1"
  ],
  "build_requires": ["cmake/3.27.7"],
  "python_requires": []
}`)
	byName := map[string]model.Record{}
	for _, r := range got {
		byName[r.PackageName] = r
	}
	if len(byName) != 3 {
		t.Fatalf("got %d records, want 3: %+v", len(byName), got)
	}
	// Revision and timestamp metadata must be stripped from the version.
	if v := byName["zlib"].Version; v != "1.2.13" {
		t.Errorf("zlib version = %q, want 1.2.13", v)
	}
	if byName["cmake"].InstallScope != "build" {
		t.Errorf("build require scope = %q", byName["cmake"].InstallScope)
	}
	if byName["fmt"].Ecosystem != model.EcosystemConan {
		t.Errorf("ecosystem = %q", byName["fmt"].Ecosystem)
	}
}

func TestScanConanLockV1Graph(t *testing.T) {
	got := scan(t, `{
  "graph_lock": {
    "nodes": {
      "0": { "ref": "app/1.0" },
      "1": { "ref": "boost/1.83.0@user/channel#rev" }
    }
  },
  "version": "0.4"
}`)
	byName := map[string]model.Record{}
	for _, r := range got {
		byName[r.PackageName] = r
	}
	if len(byName) != 2 {
		t.Fatalf("got %d records, want 2: %+v", len(byName), got)
	}
	if v := byName["boost"].Version; v != "1.83.0" {
		t.Errorf("boost version = %q, want user/channel and revision stripped", v)
	}
}

func TestSplitReference(t *testing.T) {
	cases := map[string][2]string{
		"zlib/1.2.13":                    {"zlib", "1.2.13"},
		"zlib/1.2.13@user/chan":          {"zlib", "1.2.13"},
		"zlib/1.2.13#rev":                {"zlib", "1.2.13"},
		"zlib/1.2.13#rev%1699999999.123": {"zlib", "1.2.13"},
	}
	for ref, want := range cases {
		name, version, ok := splitReference(ref)
		if !ok || name != want[0] || version != want[1] {
			t.Errorf("splitReference(%q) = %q %q %v", ref, name, version, ok)
		}
	}
	for _, bad := range []string{"", "noslash", "/1.0", "name/"} {
		if _, _, ok := splitReference(bad); ok {
			t.Errorf("splitReference(%q) should fail", bad)
		}
	}
}
