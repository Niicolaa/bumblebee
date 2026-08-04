package gomod

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func TestScanGoSum(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.sum")
	body := `github.com/example/foo v1.2.3 h1:abc=
github.com/example/foo v1.2.3/go.mod h1:def=
github.com/example/bar v0.0.0-20240101000000-abcdef h1:bar=
github.com/example/bar v0.0.0-20240101000000-abcdef/go.mod h1:bar2=
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanGoSum(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 records, got %d: %+v", len(out), out)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PackageName < out[j].PackageName })
	if out[0].PackageName != "github.com/example/bar" || out[0].Version != "v0.0.0-20240101000000-abcdef" {
		t.Errorf("bar: %+v", out[0])
	}
	if out[1].PackageName != "github.com/example/foo" || out[1].Version != "v1.2.3" {
		t.Errorf("foo: %+v", out[1])
	}
	for _, r := range out {
		if r.SourceType != "go-sum" {
			t.Errorf("source_type=%q", r.SourceType)
		}
		if r.Ecosystem != "go" {
			t.Errorf("ecosystem=%q", r.Ecosystem)
		}
	}
}

func TestScanGoMod(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.mod")
	body := `module example.com/x

go 1.22

require github.com/example/single v1.0.0

require (
	github.com/example/foo v1.2.3
	github.com/example/bar v0.0.0-20240101000000-abcdef // indirect
)
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanGoMod(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 {
		t.Fatalf("want 3 records, got %d", len(out))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PackageName < out[j].PackageName })
	if out[0].PackageName != "github.com/example/bar" || out[0].InstallScope != "indirect" {
		t.Errorf("bar: %+v", out[0])
	}
	if out[0].DirectDependency == nil || *out[0].DirectDependency {
		t.Errorf("bar should be indirect")
	}
	if out[1].PackageName != "github.com/example/foo" || out[1].InstallScope == "indirect" {
		t.Errorf("foo: %+v", out[1])
	}
	if out[2].PackageName != "github.com/example/single" {
		t.Errorf("single: %+v", out[2])
	}
}

// go.work.sum shares go.sum's line format, but a workspace sum covers the
// union of every member module's graph, so it is emitted at medium
// confidence under its own source_type.
func TestScanGoWorkSum(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.work.sum")
	body := `github.com/example/foo v1.2.3 h1:abc=
github.com/example/foo v1.2.3/go.mod h1:def=
github.com/example/bar v0.4.0 h1:bar=
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanGoWorkSum(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 records, got %d: %+v", len(out), out)
	}
	for _, r := range out {
		if r.SourceType != "go-work-sum" {
			t.Errorf("source_type=%q", r.SourceType)
		}
		if r.Confidence != "medium" {
			t.Errorf("confidence=%q, want medium", r.Confidence)
		}
	}
}

func TestIsVendorModulesTxt(t *testing.T) {
	cases := []struct {
		in string
		ok bool
	}{
		{filepath.Join("proj", "vendor", "modules.txt"), true},
		{filepath.Join("proj", "modules.txt"), false},
		{filepath.Join("proj", "vendor", "sub", "modules.txt"), false},
		{filepath.Join("proj", "vendor", "other.txt"), false},
	}
	for _, c := range cases {
		if got := IsVendorModulesTxt(c.in); got != c.ok {
			t.Errorf("IsVendorModulesTxt(%q) = %v, want %v", c.in, got, c.ok)
		}
	}
}

// A vendored tree carries no go.sum, so modules.txt is its only
// inventory. Replace directives and package lines must not become
// records.
func TestScanVendorModulesTxt(t *testing.T) {
	dir := t.TempDir()
	vendorDir := filepath.Join(dir, "vendor")
	if err := os.MkdirAll(vendorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(vendorDir, "modules.txt")
	body := `# github.com/example/foo v1.2.3
## explicit; go 1.21
github.com/example/foo
github.com/example/foo/internal/x
# github.com/example/bar v0.4.0 => ../local/bar
## explicit
# github.com/example/baz v2.0.0+incompatible
## explicit
github.com/example/baz
`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { out = append(out, r) }}
	if err := s.ScanVendorModulesTxt(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 records (replace directive skipped), got %d: %+v", len(out), out)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PackageName < out[j].PackageName })
	if out[0].PackageName != "github.com/example/baz" || out[0].Version != "v2.0.0+incompatible" {
		t.Errorf("baz: %+v", out[0])
	}
	if out[1].PackageName != "github.com/example/foo" || out[1].Version != "v1.2.3" {
		t.Errorf("foo: %+v", out[1])
	}
	for _, r := range out {
		if r.SourceType != "go-vendor-modules-txt" {
			t.Errorf("source_type=%q", r.SourceType)
		}
		if r.Confidence != "high" {
			t.Errorf("confidence=%q", r.Confidence)
		}
		// project_path is the module root, not the vendor dir.
		if r.ProjectPath != dir {
			t.Errorf("project_path=%q, want %q", r.ProjectPath, dir)
		}
	}
}
