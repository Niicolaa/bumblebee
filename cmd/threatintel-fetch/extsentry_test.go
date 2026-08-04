package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func TestFetchExtSentry_LocalCSV(t *testing.T) {
	fixture := `extension_id,extension_name,wildcard_pattern,category,threat_type,reference_url,description,chrome_webstore_url,severity,crx_sha256,first_seen,feed_source
eebihieclccoidddmjcencomodomdoei,Supersonic AI,*eebihieclccoidddmjcencomodomdoei*,malware,malicious,https://example.com/a,,https://chromewebstore.google.com/detail/eebihieclccoidddmjcencomodomdoei,critical,,2026-05-28,ExtSentry
dcjfbgppfdokmjgajnnkgdmkdeiloigh,Picsart,*dcjfbgppfdokmjgajnnkgdmkdeiloigh*,malware,malicious,https://example.com/b,,https://chromewebstore.google.com/detail/dcjfbgppfdokmjgajnnkgdmkdeiloigh,,,2026-05-28,ExtSentry
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,Suspicious,,cryptocurrency,suspicious,https://example.com/c,,,medium,,2026-05-28,ExtSentry
NOT_A_VALID_ID,Bad Row,,malware,malicious,,,,critical,,2026-05-28,ExtSentry
eebihieclccoidddmjcencomodomdoei,Supersonic AI dup,,malware,malicious,,,,critical,,2026-05-28,ExtSentry
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb,Empty Sev,,malware,malicious,,,,,,2026-05-28,ExtSentry
ccccccccccccccccccccccccccccccccccccccccccc,Wrong Length,,malware,malicious,,,,critical,,2026-05-28,ExtSentry
`
	dir := t.TempDir()
	src := filepath.Join(dir, "in.csv")
	if err := os.WriteFile(src, []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := fetchExtSentry(context.Background(), src)
	if err != nil {
		t.Fatal(err)
	}
	// Expect 4: two unique malicious + one suspicious + one with empty-sev
	// fallback. The dup, invalid-format, and wrong-length rows are dropped.
	if got, want := len(c.Entries), 4; got != want {
		t.Fatalf("entry count: got=%d want=%d", got, want)
	}

	bySev := map[string]string{}
	byName := map[string]string{}
	indByPkg := map[string]map[string]any{}
	for _, e := range c.Entries {
		bySev[e.Package] = e.Severity
		byName[e.Package] = e.Name
		indByPkg[e.Package] = e.Indicators
		if e.Ecosystem != model.EcosystemBrowserExtension {
			t.Errorf("ecosystem mismatch for %s: %q", e.Package, e.Ecosystem)
		}
		if len(e.Versions) != 1 || e.Versions[0] != "*" {
			t.Errorf("versions for %s: %v", e.Package, e.Versions)
		}
	}

	// Severity comes from the CSV when present.
	if bySev["eebihieclccoidddmjcencomodomdoei"] != "critical" {
		t.Errorf("explicit critical severity not preserved: %q", bySev["eebihieclccoidddmjcencomodomdoei"])
	}
	// Suspicious tier should still be medium.
	if bySev["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] != "medium" {
		t.Errorf("suspicious severity: %q", bySev["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"])
	}
	// Empty severity column → fallback derives critical from category=malware.
	if bySev["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"] != "critical" {
		t.Errorf("empty-severity fallback for malware category should be critical, got %q", bySev["bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"])
	}
	// Severity from the CSV that's blank string for Picsart row → category=malware,
	// threat=malicious → fallback critical.
	if bySev["dcjfbgppfdokmjgajnnkgdmkdeiloigh"] != "critical" {
		t.Errorf("Picsart row severity (blank sev, malware category): %q", bySev["dcjfbgppfdokmjgajnnkgdmkdeiloigh"])
	}

	// Display name composes "<name> (<id>)".
	if byName["eebihieclccoidddmjcencomodomdoei"] != "Supersonic AI (eebihieclccoidddmjcencomodomdoei)" {
		t.Errorf("display name: %q", byName["eebihieclccoidddmjcencomodomdoei"])
	}

	// Indicators carry forward the upstream metadata.
	ind := indByPkg["eebihieclccoidddmjcencomodomdoei"]
	if ind["reference"] != "https://example.com/a" {
		t.Errorf("reference indicator: %v", ind["reference"])
	}
	if ind["category"] != "malware" {
		t.Errorf("category indicator: %v", ind["category"])
	}
	if ind["threat_type"] != "malicious" {
		t.Errorf("threat_type indicator: %v", ind["threat_type"])
	}
	// Upstream's first_seen is the feed rebuild date, not a real
	// first-observation date, so it must never be persisted — it would
	// churn every entry in the catalog daily for no analytic value.
	if _, present := ind["first_seen"]; present {
		t.Error("first_seen must not be copied into indicators (it is the feed rebuild date and causes daily churn)")
	}
}

func TestSeverityFromExtSentry_Fallback(t *testing.T) {
	cases := []struct {
		cat, threat, want string
	}{
		{"malware", "malicious", "critical"},
		{"stealer", "malicious", "critical"},
		{"cryptocurrency", "malicious", "high"},
		{"compromised", "malicious", "high"},
		{"PUP", "malicious", "medium"},
		{"unknown-category", "malicious", "high"},
		{"malware", "suspicious", "medium"},
	}
	for _, tc := range cases {
		got := severityFromExtSentry(tc.cat, tc.threat)
		if got != tc.want {
			t.Errorf("severityFromExtSentry(%q, %q) = %q; want %q", tc.cat, tc.threat, got, tc.want)
		}
	}
}
