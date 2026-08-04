package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func TestFetchVSXSentry_LocalCSV(t *testing.T) {
	fixture := `extension_id,publisher_id,extension_name,metadata_comment,metadata_severity,metadata_category,metadata_source,metadata_reference,metadata_status,removal_date,source_reason,last_updated_utc,merged_sources
0xS1rx58D3V.ChatGPT-B0T,0xS1rx58D3V,ChatGPT-B0T,Removed from VS Marketplace: Malware.,critical,malware,microsoft_removed_packages,https://example.com/a,removed_marketplace,2025-03-18,Malware,2026-05-28T07:41:40+00:00,microsoft_removed_packages
ahban.shiba,ahban,shiba,Removed from VS Marketplace: Malware.,critical,malware,microsoft_removed_packages,https://example.com/b,removed_marketplace,2025-03-13,Malware,2026-05-28T07:41:40+00:00,microsoft_removed_packages
NotADottedID,publisher,name,bad,critical,malware,src,ref,status,,reason,utc,merged
ahban.shiba,ahban,shiba,duplicate row,critical,malware,microsoft_removed_packages,https://example.com/dup,removed_marketplace,2025-03-13,Malware,2026-05-28T07:41:40+00:00,microsoft_removed_packages
`
	dir := t.TempDir()
	src := filepath.Join(dir, "in.csv")
	if err := os.WriteFile(src, []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := fetchVSXSentry(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(c.Entries), 2; got != want {
		t.Fatalf("entry count: got=%d want=%d (dedup + non-dotted-ID filter)", got, want)
	}
	for _, e := range c.Entries {
		if e.Ecosystem != model.EcosystemEditorExtension {
			t.Errorf("ecosystem mismatch: %q", e.Ecosystem)
		}
		if e.Versions[0] != "*" {
			t.Errorf("expected wildcard versions, got %v", e.Versions)
		}
		if e.Package == "" {
			t.Errorf("empty package")
		}
	}
}
