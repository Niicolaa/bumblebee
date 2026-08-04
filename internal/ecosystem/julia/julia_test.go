package julia

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func scan(t *testing.T, content string) []model.Record {
	t.Helper()
	path := filepath.Join(t.TempDir(), "Manifest.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	var got []model.Record
	s := &Scanner{
		MaxFileSize: 1 << 20,
		Emit:        func(r model.Record) { got = append(got, r) },
		Diag:        func(level, path, msg string) {},
	}
	if err := s.ScanManifestTOML(path, model.Record{}); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestScanManifestFormat2(t *testing.T) {
	got := scan(t, `julia_version = "1.10.0"
manifest_format = "2.0"

[[deps.JSON]]
deps = ["Dates", "Mmap"]
uuid = "682c06a0-de6a-54ab-a142-c8b1cf79cde6"
version = "0.21.4"

[[deps.Dates]]
uuid = "ade2ca70-3891-5945-98fb-dc099432e06a"
`)
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1 (stdlib entry without a version is skipped): %+v", len(got), got)
	}
	r := got[0]
	if r.PackageName != "JSON" || r.Version != "0.21.4" {
		t.Errorf("record = %q@%q", r.PackageName, r.Version)
	}
	if r.Ecosystem != model.EcosystemJulia || r.Confidence != "high" {
		t.Errorf("ecosystem/confidence = %q/%q", r.Ecosystem, r.Confidence)
	}
	if r.NormalizedName != "json" {
		t.Errorf("normalized = %q", r.NormalizedName)
	}
}

func TestScanManifestFormat1(t *testing.T) {
	got := scan(t, `[[Colors]]
deps = ["FixedPointNumbers"]
uuid = "5ae59095-9a9b-59fe-a467-6f913c188581"
version = "0.12.10"
`)
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1: %+v", len(got), got)
	}
	if got[0].PackageName != "Colors" || got[0].Version != "0.12.10" {
		t.Errorf("record = %q@%q", got[0].PackageName, got[0].Version)
	}
}

// The scalar metadata keys at the top of a v1 manifest must not be
// mistaken for package entries.
func TestScanManifestIgnoresScalarMetadata(t *testing.T) {
	got := scan(t, `julia_version = "1.10.0"
manifest_format = "2.0"
project_hash = "abc123"
`)
	if len(got) != 0 {
		t.Errorf("got %d records from metadata-only manifest: %+v", len(got), got)
	}
}
