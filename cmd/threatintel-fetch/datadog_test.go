package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/perplexityai/bumblebee/internal/model"
)

func TestFetchDataDog_LocalManifest(t *testing.T) {
	// Fixture mirrors the real DataDog manifest shape: object of
	// package -> null | [version,...]. Layout the test expects:
	// dir/npm/manifest.json so the fetcher's local-source path
	// resolves the same way it does for URLs.
	manifest := `{
        "02-echo": ["0.0.7"],
        "@antv/a8": ["0.1.1", "0.2.1"],
        "000webhost-admin": null,
        "duped-versions": ["1.0.0", "1.0.0", "  ", ""],
        "": ["1.0.0"]
    }`
	dir := t.TempDir()
	ecoDir := filepath.Join(dir, "npm")
	if err := os.MkdirAll(ecoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ecoDir, "manifest.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}

	c, err := fetchDataDog(context.Background(), dataDogEcosystem{bumblebee: model.EcosystemNPM, datadog: "npm"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	// 4 valid entries: 02-echo, @antv/a8, 000webhost-admin, duped-versions.
	// Empty-key row is dropped.
	if got, want := len(c.Entries), 4; got != want {
		t.Fatalf("entry count: got=%d want=%d", got, want)
	}

	byPkg := map[string]*entry{}
	for _, e := range c.Entries {
		byPkg[e.Package] = e
		if e.Ecosystem != model.EcosystemNPM {
			t.Errorf("ecosystem mismatch: %q", e.Ecosystem)
		}
		if e.Severity != "critical" {
			t.Errorf("expected critical severity for %s, got %q", e.Package, e.Severity)
		}
	}

	// null → wildcard
	if v := byPkg["000webhost-admin"].Versions; len(v) != 1 || v[0] != "*" {
		t.Errorf("null manifest entry should wildcard, got %v", v)
	}
	// explicit single version preserved
	if v := byPkg["02-echo"].Versions; len(v) != 1 || v[0] != "0.0.7" {
		t.Errorf("explicit version not preserved: %v", v)
	}
	// scoped package + multi-version
	if v := byPkg["@antv/a8"].Versions; len(v) != 2 {
		t.Errorf("scoped multi-version: %v", v)
	}
	// dedup + drop empties
	if v := byPkg["duped-versions"].Versions; len(v) != 1 || v[0] != "1.0.0" {
		t.Errorf("dedup/empty-strip failed: %v", v)
	}
}

func TestCleanVersionList(t *testing.T) {
	cases := []struct {
		in   []string
		want []string
	}{
		{nil, nil},
		{[]string{}, nil},
		{[]string{"1.0", "1.0", "2.0"}, []string{"1.0", "2.0"}},
		{[]string{"", "  ", "1.0"}, []string{"1.0"}},
		{[]string{" 1.0 "}, []string{"1.0"}},
	}
	for i, tc := range cases {
		got := cleanVersionList(tc.in)
		if len(got) != len(tc.want) {
			t.Errorf("case %d: len got=%d want=%d (in=%v out=%v)", i, len(got), len(tc.want), tc.in, got)
			continue
		}
		for j := range got {
			if got[j] != tc.want[j] {
				t.Errorf("case %d: idx %d got=%q want=%q", i, j, got[j], tc.want[j])
			}
		}
	}
}
