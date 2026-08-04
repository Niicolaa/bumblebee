package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCat(t *testing.T, dir, name string, n int) {
	t.Helper()
	var sb strings.Builder
	sb.WriteString(`{"schema_version":"0.2.0","entries":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmtEntry(&sb, i)
	}
	sb.WriteString(`]}`)
	if err := os.WriteFile(filepath.Join(dir, name), []byte(sb.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fmtEntry(sb *strings.Builder, i int) {
	sb.WriteString(`{"id":"e`)
	sb.WriteString(itoa(i))
	sb.WriteString(`","ecosystem":"npm","package":"p`)
	sb.WriteString(itoa(i))
	sb.WriteString(`","versions":["1.0.0"]}`)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestCheckShrink_FlagsCollapse(t *testing.T) {
	dir := t.TempDir()
	writeCat(t, dir, "a.json", 100)
	before := snapshotCounts(dir)
	if before["a.json"] != 100 {
		t.Fatalf("snapshot: got %d want 100", before["a.json"])
	}

	// Simulate an upstream shape change that empties the catalog.
	writeCat(t, dir, "a.json", 3)
	v := checkShrink(dir, before, 0.5)
	if len(v) != 1 {
		t.Fatalf("expected 1 violation, got %d: %v", len(v), v)
	}
	if !strings.Contains(v[0], "shrank from 100 to 3") {
		t.Errorf("unexpected message: %q", v[0])
	}
}

func TestCheckShrink_AllowsNormalGrowthAndMildShrink(t *testing.T) {
	dir := t.TempDir()
	writeCat(t, dir, "a.json", 100)
	before := snapshotCounts(dir)

	// Growth is always fine.
	writeCat(t, dir, "a.json", 250)
	if v := checkShrink(dir, before, 0.5); len(v) != 0 {
		t.Errorf("growth should not trip the guard: %v", v)
	}

	// A 20% drop is plausible upstream curation, not a parse failure.
	writeCat(t, dir, "a.json", 80)
	if v := checkShrink(dir, before, 0.5); len(v) != 0 {
		t.Errorf("mild shrink should not trip the guard: %v", v)
	}

	// Exactly at the floor is allowed; just under is not.
	writeCat(t, dir, "a.json", 50)
	if v := checkShrink(dir, before, 0.5); len(v) != 0 {
		t.Errorf("exactly-at-floor should pass: %v", v)
	}
	writeCat(t, dir, "a.json", 49)
	if v := checkShrink(dir, before, 0.5); len(v) != 1 {
		t.Errorf("just-under-floor should fail, got %v", v)
	}
}

func TestCheckShrink_DisabledAndNewFiles(t *testing.T) {
	dir := t.TempDir()
	writeCat(t, dir, "a.json", 100)
	before := snapshotCounts(dir)
	writeCat(t, dir, "a.json", 1)

	if v := checkShrink(dir, before, 0); len(v) != 0 {
		t.Errorf("minRatio=0 should disable the guard, got %v", v)
	}

	// A file that appears only after the fetch has no baseline and must
	// not be flagged.
	writeCat(t, dir, "brand-new.json", 1)
	v := checkShrink(dir, before, 0.5)
	for _, msg := range v {
		if strings.Contains(msg, "brand-new.json") {
			t.Errorf("new file should not be flagged: %q", msg)
		}
	}
}

func TestCheckShrink_FlagsDisappearance(t *testing.T) {
	dir := t.TempDir()
	writeCat(t, dir, "a.json", 100)
	before := snapshotCounts(dir)
	if err := os.Remove(filepath.Join(dir, "a.json")); err != nil {
		t.Fatal(err)
	}
	v := checkShrink(dir, before, 0.5)
	if len(v) != 1 || !strings.Contains(v[0], "disappeared") {
		t.Fatalf("expected disappearance violation, got %v", v)
	}
}

func TestWriteCatalog_TimestampOnlyChangeIsNoop(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "c.json")

	mk := func(stamp string, n int) *catalog {
		c := &catalog{
			SchemaVersion: "0.2.0",
			Comment:       "test",
			GeneratedUTC:  stamp,
			Source:        "https://example.com",
		}
		for i := 0; i < n; i++ {
			c.Entries = append(c.Entries, &entry{
				ID: "e" + itoa(i), Ecosystem: "npm",
				Package: "p" + itoa(i), Versions: []string{"1.0.0"},
			})
		}
		return c
	}

	changed, err := writeCatalog(path, mk("2026-08-03T00:00:00Z", 3))
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("first write should report changed")
	}

	// Same entries, later timestamp: must be a no-op so the daily sync
	// job doesn't commit and cut a release when no feed actually moved.
	changed, err = writeCatalog(path, mk("2026-08-04T09:11:23Z", 3))
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("timestamp-only difference must not count as a change")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "2026-08-03T00:00:00Z") {
		t.Error("original timestamp should be preserved when content is unchanged")
	}

	// A real content change must still be written, and must refresh the
	// stamp so it reads as "when this data last changed".
	changed, err = writeCatalog(path, mk("2026-08-04T09:11:23Z", 4))
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("content change must be written")
	}
	body, _ = os.ReadFile(path)
	if !strings.Contains(string(body), "2026-08-04T09:11:23Z") {
		t.Error("timestamp should advance when content actually changed")
	}
}
