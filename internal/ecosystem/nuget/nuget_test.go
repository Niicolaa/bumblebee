package nuget

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func TestIsCacheNuspec(t *testing.T) {
	cases := []struct {
		in      string
		ok      bool
		id      string
		version string
	}{
		{filepath.Join("home", ".nuget", "packages", "newtonsoft.json", "13.0.3", "newtonsoft.json.nuspec"), true, "newtonsoft.json", "13.0.3"},
		{filepath.Join("c", "packages", "serilog", "4.0.0-dev-02226", "serilog.nuspec"), true, "serilog", "4.0.0-dev-02226"},
		// A nuspec inside package content, not at the version root.
		{filepath.Join("packages", "foo", "1.0.0", "lib", "net8.0", "foo.nuspec"), false, "", ""},
		// Name mismatch with the id directory.
		{filepath.Join("packages", "foo", "1.0.0", "bar.nuspec"), false, "", ""},
		{filepath.Join("packages", "foo", "notaversion", "foo.nuspec"), false, "", ""},
		{filepath.Join("packages", "foo", "1.0.0", "foo.txt"), false, "", ""},
	}
	for _, c := range cases {
		ok, id, version, _ := IsCacheNuspec(c.in)
		if ok != c.ok || id != c.id || version != c.version {
			t.Errorf("IsCacheNuspec(%q) = (%v, %q, %q), want (%v, %q, %q)",
				c.in, ok, id, version, c.ok, c.id, c.version)
		}
	}
}

func TestScanPackagesLockJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "packages.lock.json")
	// The same package under two target frameworks must dedupe to one record.
	body := `{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"},
      "Serilog": {"type": "Transitive", "resolved": "4.0.0"},
      "MyProject.Core": {"type": "Project"}
    },
    "net6.0": {
      "Newtonsoft.Json": {"type": "Direct", "resolved": "13.0.3"}
    }
  }
}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanPackagesLockJSON(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PackageName < out[j].PackageName })
	if len(out) != 3 {
		t.Fatalf("want 3 deduped records, got %d: %+v", len(out), out)
	}
	if out[0].PackageName != "MyProject.Core" || out[0].Version != "" || out[0].Confidence != "low" {
		t.Errorf("project reference: %+v", out[0])
	}
	if out[1].PackageName != "Newtonsoft.Json" || out[1].Version != "13.0.3" {
		t.Errorf("newtonsoft: %+v", out[1])
	}
	if out[1].NormalizedName != "newtonsoft.json" {
		t.Errorf("normalized=%q, NuGet ids are case-insensitive", out[1].NormalizedName)
	}
}

func TestScanPackagesConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "packages.config")
	body := `<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="12.0.3" targetFramework="net472" />
  <package id="EntityFramework" version="6.4.4" targetFramework="net472" />
</packages>`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanPackagesConfig(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 records, got %d", len(out))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PackageName < out[j].PackageName })
	if out[0].PackageName != "EntityFramework" || out[0].Version != "6.4.4" {
		t.Errorf("ef: %+v", out[0])
	}
	if out[0].SourceType != "nuget-packages-config" {
		t.Errorf("source_type=%q", out[0].SourceType)
	}
}
