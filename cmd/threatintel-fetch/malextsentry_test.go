package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/perplexityai/bumblebee/internal/exposure"
	"github.com/perplexityai/bumblebee/internal/model"
)

func TestFetchMalExtSentry_LocalCSV(t *testing.T) {
	fixture := `extension_id,name,reason,source,insert_date_fmt,blocklist
lbgfcdjklmgkaogjkkbkleeepndmbnja,Glanceai,Malware,Store Monitoring,2026-05-28,
onmpecpdikhopjbmjajcjcnfdjdmbbfd,Tiktok Unban Ban Pass,Policy Violation,Store Monitoring,2026-05-28,
beelllgidjaklbnacknjkghfibfpjhac,Clipkeeper Download Gamec,Bundling Unwanted Software,Store Monitoring,2026-05-28,
NOT_A_VALID_ID,Bad Row,Malware,Store Monitoring,2026-05-28,
lbgfcdjklmgkaogjkkbkleeepndmbnja,Glanceai duplicate,Malware,Store Monitoring,2026-05-28,
`
	dir := t.TempDir()
	src := filepath.Join(dir, "in.csv")
	if err := os.WriteFile(src, []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := fetchMalExtSentry(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(c.Entries), 3; got != want {
		t.Fatalf("entry count: got=%d want=%d (dedup + invalid-ID filter)", got, want)
	}

	// Validate severity mapping.
	bySev := map[string]string{}
	for _, e := range c.Entries {
		bySev[e.Package] = e.Severity
	}
	if bySev["lbgfcdjklmgkaogjkkbkleeepndmbnja"] != "critical" {
		t.Errorf("malware → critical, got %q", bySev["lbgfcdjklmgkaogjkkbkleeepndmbnja"])
	}
	if bySev["onmpecpdikhopjbmjajcjcnfdjdmbbfd"] != "medium" {
		t.Errorf("policy violation → medium, got %q", bySev["onmpecpdikhopjbmjajcjcnfdjdmbbfd"])
	}
	if bySev["beelllgidjaklbnacknjkghfibfpjhac"] != "high" {
		t.Errorf("bundling → high, got %q", bySev["beelllgidjaklbnacknjkghfibfpjhac"])
	}

	for _, e := range c.Entries {
		if e.Ecosystem != model.EcosystemBrowserExtension {
			t.Errorf("ecosystem mismatch: %q", e.Ecosystem)
		}
		if len(e.Versions) != 1 || e.Versions[0] != "*" {
			t.Errorf("expected versions=[\"*\"], got %v", e.Versions)
		}
	}
}

func TestWriteCatalog_AtomicAndValidated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	c := &catalog{
		SchemaVersion: model.SchemaVersion,
		Entries: []*entry{
			{ID: "z", Ecosystem: "npm", Package: "z", Versions: []string{"1.0.0"}},
			{ID: "a", Ecosystem: "npm", Package: "a", Versions: []string{"*"}},
		},
	}
	changed, err := writeCatalog(path, c)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("expected changed=true on first write")
	}
	// Re-run with same content → no change.
	c2 := &catalog{
		SchemaVersion: model.SchemaVersion,
		Entries: []*entry{
			{ID: "a", Ecosystem: "npm", Package: "a", Versions: []string{"*"}},
			{ID: "z", Ecosystem: "npm", Package: "z", Versions: []string{"1.0.0"}},
		},
	}
	changed, err = writeCatalog(path, c2)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("expected changed=false when content is identical")
	}

	// The on-disk file must parse via the exposure loader, including
	// the wildcard entry.
	parsed, err := exposure.LoadFile(path, 0)
	if err != nil {
		t.Fatalf("loader rejected our output: %v", err)
	}
	if parsed.Len() != 2 {
		t.Fatalf("loader saw %d entries", parsed.Len())
	}
}

func TestWriteShardedCatalog_DistributesAndRoundTrips(t *testing.T) {
	c := &catalog{
		SchemaVersion: model.SchemaVersion,
		Comment:       "test",
		Source:        "https://example.com",
	}
	const n = 4
	for i := 0; i < 1000; i++ {
		pkg := "pkg-" + string(rune('a'+(i%26))) + "-" + string(rune('a'+((i/26)%26))) + "-" + string(rune('0'+(i%10)))
		c.Entries = append(c.Entries, &entry{
			ID:        "x-" + pkg,
			Ecosystem: "npm",
			Package:   pkg,
			Versions:  []string{"1.0.0"},
		})
	}
	dir := t.TempDir()
	paths := shardPaths(dir, "test", n)
	changed, total, err := writeShardedCatalog(paths, c)
	if err != nil {
		t.Fatal(err)
	}
	if total != len(c.Entries) {
		t.Errorf("entry total: shards reported %d, catalog has %d", total, len(c.Entries))
	}
	if changed == 0 {
		t.Error("expected at least one shard changed on first write")
	}

	// Each shard should parse via the loader, and the union of shards
	// should equal the input set.
	union := map[string]bool{}
	for _, p := range paths {
		parsed, err := exposure.LoadFile(p, 0)
		if err != nil {
			t.Fatalf("loader rejected shard %s: %v", p, err)
		}
		if parsed.Len() == 0 {
			t.Errorf("shard %s is empty — uneven distribution suggests broken hash", p)
		}
		// Re-read raw to assert the file looks sharded (has shard label).
		raw, _ := os.ReadFile(p)
		if !contains(string(raw), "shard ") {
			t.Errorf("shard %s missing shard label in comment", p)
		}
		for _, e := range parsed.Entries {
			if union[e.Package] {
				t.Errorf("package %s appeared in multiple shards", e.Package)
			}
			union[e.Package] = true
		}
	}
	if len(union) != 1000 {
		t.Errorf("union size: got %d want 1000 (shards lost or duplicated entries)", len(union))
	}

	// Re-running with same input should report zero changed shards.
	changed, _, err = writeShardedCatalog(paths, c)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 0 {
		t.Errorf("expected 0 changed shards on identical re-write, got %d", changed)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestWriteCatalog_RejectsInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "out.json")
	// Missing ecosystem → loader rejects → writeCatalog must surface
	// the error and NOT touch the destination file.
	c := &catalog{
		SchemaVersion: model.SchemaVersion,
		Entries:       []*entry{{ID: "x", Package: "y", Versions: []string{"1"}}},
	}
	if _, err := writeCatalog(path, c); err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected destination file absent after failed write, stat=%v", err)
	}
}
