package exposure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The catalogs in threat_intel/ are shipped in every release tarball and
// are what a fleet actually matches against. Nothing was checking that
// they load: the sync workflows ran `go test -run TestLoad`, which only
// exercises temp fixtures, so a catalog committed with a bad
// schema_version or malformed JSON would have shipped and every scan
// using it would have failed at the point of use, on the endpoint.
func TestShippedCatalogsLoad(t *testing.T) {
	dir := filepath.Join("..", "..", "threat_intel")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("no threat_intel directory: %v", err)
	}

	cat, err := Load(dir, 256*1024*1024)
	if err != nil {
		t.Fatalf("loading shipped catalogs: %v", err)
	}
	if cat.Len() == 0 {
		t.Fatal("shipped catalogs loaded but contain zero entries")
	}
	t.Logf("shipped catalogs: %d entries", cat.Len())

	// Every catalog file must also load on its own. Load() merges a
	// directory, so a single unreadable file could otherwise be masked
	// by the others.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		files++
		p := filepath.Join(dir, e.Name())
		c, err := LoadFile(p, 256*1024*1024)
		if err != nil {
			t.Errorf("%s: %v", e.Name(), err)
			continue
		}
		if c.Len() == 0 {
			t.Errorf("%s: parsed but has zero entries", e.Name())
		}
	}
	if files == 0 {
		t.Error("no *.json catalogs found in threat_intel/")
	}
}
