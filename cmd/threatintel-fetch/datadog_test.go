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

// writeDataDogManifest lays out dir/<segment>/manifest.json so the
// fetcher's local-source path resolves the same way it does for URLs.
func writeDataDogManifest(t *testing.T, dir, segment, manifest string) {
	t.Helper()
	ecoDir := filepath.Join(dir, segment)
	if err := os.MkdirAll(ecoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ecoDir, "manifest.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestFetchDataDog_IDEExtensions covers the ide_extensions dataset,
// whose keys are marketplace `Publisher.Name` ids in upstream casing.
// The package name is emitted verbatim (exposure matching lowercases
// both sides for editor-extension), while the entry ID is normalized.
func TestFetchDataDog_IDEExtensions(t *testing.T) {
	dir := t.TempDir()
	writeDataDogManifest(t, dir, "ide_extensions", `{
        "0xS1rx58D3V.ChatGPT-B0T": null,
        "nrwl.angular-console": ["18.95.0"]
    }`)

	c, err := fetchDataDog(context.Background(),
		dataDogEcosystem{bumblebee: model.EcosystemEditorExtension, datadog: "ide_extensions"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(c.Entries), 2; got != want {
		t.Fatalf("entry count: got=%d want=%d", got, want)
	}
	byPkg := map[string]*entry{}
	for _, e := range c.Entries {
		byPkg[e.Package] = e
		if e.Ecosystem != model.EcosystemEditorExtension {
			t.Errorf("ecosystem mismatch: %q", e.Ecosystem)
		}
	}
	e := byPkg["0xS1rx58D3V.ChatGPT-B0T"]
	if e == nil {
		t.Fatal("upstream casing not preserved on package name")
	}
	if want := "datadog-ide_extensions--0xs1rx58d3v.chatgpt-b0t"; e.ID != want {
		t.Errorf("entry ID not normalized: got=%q want=%q", e.ID, want)
	}
	if v := e.Versions; len(v) != 1 || v[0] != "*" {
		t.Errorf("null manifest entry should wildcard, got %v", v)
	}
	if v := byPkg["nrwl.angular-console"].Versions; len(v) != 1 || v[0] != "18.95.0" {
		t.Errorf("explicit version not preserved: %v", v)
	}
}

// TestFetchDataDog_AISkills covers the ai-skills dataset, whose flattened
// slugs are expanded into candidate `owner/repo` names so they can match
// what internal/ecosystem/skills emits.
func TestFetchDataDog_AISkills(t *testing.T) {
	dir := t.TempDir()
	writeDataDogManifest(t, dir, "ai-skills", `{
        "acme-evil-skill": null,
        "already/slashed": null
    }`)

	c, err := fetchDataDog(context.Background(),
		dataDogEcosystem{bumblebee: model.EcosystemAgentSkill, datadog: "ai-skills"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	byPkg := map[string]*entry{}
	for _, e := range c.Entries {
		if _, dup := byPkg[e.Package]; dup {
			t.Errorf("duplicate package entry %q", e.Package)
		}
		byPkg[e.Package] = e
		if e.Ecosystem != model.EcosystemAgentSkill {
			t.Errorf("ecosystem mismatch: %q", e.Ecosystem)
		}
	}
	// raw key + one candidate per interior hyphen, plus the pre-slashed key.
	for _, want := range []string{
		"acme-evil-skill", "acme/evil-skill", "acme-evil/skill", "already/slashed",
	} {
		if byPkg[want] == nil {
			t.Errorf("missing candidate %q", want)
		}
	}
	if got, want := len(c.Entries), 4; got != want {
		t.Fatalf("entry count: got=%d want=%d", got, want)
	}
	if e := byPkg["acme/evil-skill"]; e != nil {
		if e.Indicators["name_reconstructed"] != true {
			t.Errorf("candidate entry not flagged: %v", e.Indicators)
		}
		if e.Indicators["upstream_package"] != "acme-evil-skill" {
			t.Errorf("candidate missing upstream package: %v", e.Indicators)
		}
	}
	if e := byPkg["acme-evil-skill"]; e != nil {
		if _, flagged := e.Indicators["name_reconstructed"]; flagged {
			t.Errorf("verbatim entry should not be flagged: %v", e.Indicators)
		}
	}
}

func TestPackageCandidates(t *testing.T) {
	npm := dataDogEcosystem{bumblebee: model.EcosystemNPM, datadog: "npm"}
	if got := packageCandidates(npm, "a-b-c"); len(got) != 1 || got[0] != "a-b-c" {
		t.Errorf("non-ai-skills datasets must pass names through: %v", got)
	}
	skills := dataDogEcosystem{bumblebee: model.EcosystemAgentSkill, datadog: "ai-skills"}
	// Leading and trailing hyphens produce no candidate split.
	if got := packageCandidates(skills, "-x-"); len(got) != 1 || got[0] != "-x-" {
		t.Errorf("edge hyphens should not split: %v", got)
	}
	if got := packageCandidates(skills, "nohyphens"); len(got) != 1 {
		t.Errorf("hyphen-free key should yield itself only: %v", got)
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
