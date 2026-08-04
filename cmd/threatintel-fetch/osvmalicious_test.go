package main

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

// buildOSVZip creates a fixture OSV all.zip containing the provided
// JSON records, mirroring the layout the OSV bucket exposes.
func buildOSVZip(t *testing.T, dir, eco string, files map[string]string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(dir, eco), 0o755); err != nil {
		t.Fatal(err)
	}
	buf := &bytes.Buffer{}
	zw := zip.NewWriter(buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, eco, "all.zip"), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestFetchOSVMalicious_Npm covers the fetcher's zip → catalog pipeline
// end-to-end via internal/osv. The record→entry semantics are owned by
// internal/osv (with its own unit tests upstream); this test just
// verifies our fetcher wires the two halves together correctly.
func TestFetchOSVMalicious_Npm(t *testing.T) {
	dir := t.TempDir()
	buildOSVZip(t, dir, "npm", map[string]string{
		"MAL-2024-100.json": `{
			"id": "MAL-2024-100",
			"summary": "Malicious npm package foo",
			"affected": [{
				"package": {"ecosystem": "npm", "name": "foo"},
				"versions": ["1.0.0", "1.0.1"]
			}]
		}`,
		"MAL-2024-101.json": `{
			"id": "MAL-2024-101",
			"summary": "All-versions malicious npm package bar",
			"affected": [{
				"package": {"ecosystem": "npm", "name": "bar"},
				"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]
			}]
		}`,
		// CVE entry — must be ignored (only MAL-* records are emitted).
		"CVE-2024-9999.json": `{
			"id": "CVE-2024-9999",
			"affected": [{"package": {"ecosystem": "npm", "name": "ignored"}, "versions": ["1.0.0"]}]
		}`,
		// Wrong ecosystem — must be skipped (Options.Ecosystems filter).
		"MAL-2024-200.json": `{
			"id": "MAL-2024-200",
			"affected": [{"package": {"ecosystem": "PyPI", "name": "skipped"}, "versions": ["1.0.0"]}]
		}`,
	})

	c, err := fetchOSVMalicious(context.Background(), osvEcosystem{bumblebee: model.EcosystemNPM, osv: "npm"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(c.Entries), 2; got != want {
		t.Fatalf("entry count: got=%d want=%d", got, want)
	}

	byID := map[string]*entry{}
	for _, e := range c.Entries {
		byID[e.ID] = e
	}
	if e := byID["MAL-2024-100"]; e == nil {
		t.Fatal("missing MAL-2024-100")
	} else {
		if len(e.Versions) != 2 || e.Versions[0] != "1.0.0" || e.Versions[1] != "1.0.1" {
			t.Errorf("versions = %v", e.Versions)
		}
		if e.Source != "https://osv.dev/vulnerability/MAL-2024-100" {
			t.Errorf("source = %q", e.Source)
		}
		if e.Severity != "critical" {
			t.Errorf("severity = %q", e.Severity)
		}
	}
	if e := byID["MAL-2024-101"]; e == nil {
		t.Fatal("missing MAL-2024-101")
	} else {
		if len(e.Versions) != 1 || e.Versions[0] != "*" {
			t.Errorf("all-versions range should map to [*], got %v", e.Versions)
		}
	}
}
