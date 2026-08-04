package gomod

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func TestIsVendorModulesTxt(t *testing.T) {
	if !IsVendorModulesTxt(filepath.Join("proj", "vendor", "modules.txt")) {
		t.Error("vendor/modules.txt should match")
	}
	// The basename alone is far too generic.
	if IsVendorModulesTxt(filepath.Join("docs", "modules.txt")) {
		t.Error("modules.txt outside vendor/ must not match")
	}
	if IsVendorModulesTxt(filepath.Join("vendor", "other.txt")) {
		t.Error("non-modules.txt must not match")
	}
}

func TestScanVendorModulesTxt(t *testing.T) {
	proj := t.TempDir()
	vendorDir := filepath.Join(proj, "vendor")
	if err := os.MkdirAll(vendorDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(vendorDir, "modules.txt")
	if err := os.WriteFile(path, []byte(`# github.com/google/uuid v1.5.0
## explicit; go 1.19
github.com/google/uuid
# golang.org/x/sys v0.15.0 => golang.org/x/sys v0.14.0
## explicit; go 1.18
golang.org/x/sys/unix
`), 0o644); err != nil {
		t.Fatal(err)
	}

	var got []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { got = append(got, r) }}
	if err := s.ScanVendorModulesTxt(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2 (package lines are not modules): %+v", len(got), got)
	}

	byName := map[string]model.Record{}
	for _, r := range got {
		byName[r.PackageName] = r
	}
	uuid, ok := byName["github.com/google/uuid"]
	if !ok {
		t.Fatal("uuid module missing")
	}
	if uuid.Version != "v1.5.0" {
		t.Errorf("version = %q", uuid.Version)
	}
	if uuid.SourceType != "go-vendor-modules" {
		t.Errorf("source type = %q", uuid.SourceType)
	}
	// modules.txt lives in <project>/vendor/, so the project is its
	// grandparent, not its parent.
	if uuid.ProjectPath != proj {
		t.Errorf("project path = %q, want %q", uuid.ProjectPath, proj)
	}
	// A replace directive records the original module coordinates, which
	// is the identity an advisory would name.
	if _, ok := byName["golang.org/x/sys"]; !ok {
		t.Errorf("replaced module should record its original coordinates: %+v", got)
	}
}

func TestScanGoWorkSum(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "go.work.sum")
	if err := os.WriteFile(path, []byte(`github.com/google/uuid v1.5.0 h1:abc=
github.com/google/uuid v1.5.0/go.mod h1:def=
`), 0o644); err != nil {
		t.Fatal(err)
	}
	var got []model.Record
	s := &Scanner{MaxFileSize: 1 << 20, Emit: func(r model.Record) { got = append(got, r) }}
	if err := s.ScanGoWorkSum(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1 (the /go.mod pseudo-entry is skipped): %+v", len(got), got)
	}
	if got[0].SourceType != "go-work-sum" {
		t.Errorf("source type = %q", got[0].SourceType)
	}
	if got[0].Version != "v1.5.0" {
		t.Errorf("version = %q", got[0].Version)
	}
}
